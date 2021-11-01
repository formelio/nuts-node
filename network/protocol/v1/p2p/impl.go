/*
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package p2p

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/transport"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	errors2 "github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
)

type dialer func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error)

const connectingQueueChannelSize = 100
const eventChannelSize = 100
const messageBacklogChannelSize = 1000 // TODO: Does this number make sense? Should also be configurable?
const defaultMaxMessageSizeInBytes = 1024 * 512

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

type adapter struct {
	config AdapterConfig

	grpcServer  *grpc.Server
	serverMutex *sync.Mutex
	listener    net.Listener

	// connectors contains the list of peers we're currently trying to connect to.
	connectors map[string]*connector
	// connectorAddChannel is used to communicate addresses of remote peers to connect to.
	connectorAddChannel chan string
	// Event channels which are listened to by, peers connects/disconnects
	peerConnectedChannel    chan types.Peer
	peerDisconnectedChannel chan types.Peer

	conns *connectionManager

	receivedMessages messageQueue
	grpcDialer       dialer
}

func (n adapter) EventChannels() (peerConnected chan types.Peer, peerDisconnected chan types.Peer) {
	return n.peerConnectedChannel, n.peerDisconnectedChannel
}

func (n adapter) Diagnostics() []core.DiagnosticResult {
	peers := n.Peers()
	return []core.DiagnosticResult{
		numberOfPeersStatistic{numberOfPeers: len(peers)},
		peersStatistic{peers: peers},
		ownPeerIDStatistic{peerID: n.config.PeerID},
	}
}

func (n *adapter) Peers() []types.Peer {
	var result []types.Peer
	n.conns.forEach(func(conn connection) {
		result = append(result, conn.peer())
	})
	return result
}

func (n *adapter) Broadcast(message *transport.NetworkMessage) {
	n.conns.forEach(func(conn connection) {
		if err := conn.send(message); err != nil {
			log.Logger().Warnf("Unable to broadcast to %s: %v", conn.peer().ID, err)
		}
	})
}

func (n adapter) ReceivedMessages() MessageQueue {
	return n.receivedMessages
}

func (n adapter) Send(peerID types.PeerID, message *transport.NetworkMessage) error {
	conn := n.conns.get(peerID)
	if conn == nil {
		return fmt.Errorf("unknown peer: %s", peerID)
	}
	return conn.send(message)
}

type connector struct {
	address string
	backoff Backoff
	dialer
}

func (c *connector) doConnect(ownID types.PeerID, tlsConfig *tls.Config) (*types.Peer, transport.Network_ConnectClient, error) {
	log.Logger().Debugf("Connecting to peer: %v", c.address)

	ctx := metadata.NewOutgoingContext(context.Background(), constructMetadata(ownID))

	dialContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),                 // Dial should block until connection succeeded (or time-out expired)
		grpc.WithReturnConnectionError(), // This option causes underlying errors to be returned when connections fail, rather than just "context deadline exceeded"
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxMessageSizeInBytes),
			grpc.MaxCallSendMsgSize(MaxMessageSizeInBytes),
		),
	}
	if tlsConfig != nil {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))) // TLS authentication
	} else {
		dialOptions = append(dialOptions, grpc.WithInsecure()) // No TLS, requires 'insecure' flag
	}
	grpcConn, err := c.dialer(dialContext, c.address, dialOptions...)
	if err != nil {
		return nil, nil, errors2.Wrap(err, "unable to connect")
	}
	client := transport.NewNetworkClient(grpcConn)
	messenger, err := client.Connect(ctx)
	if err != nil {
		log.Logger().Warnf("Failed to set up stream (addr=%s): %v", c.address, err)
		_ = grpcConn.Close()
		return nil, nil, err
	}

	serverPeerID, err := readClientHeaders(messenger)
	if err != nil {
		log.Logger().Warnf("Error reading headers from server, closing connection (addr=%s): %v", c.address, err)
		_ = grpcConn.Close()
		return nil, nil, err
	}
	return &types.Peer{
		ID:      serverPeerID,
		Address: c.address,
	}, messenger, nil
}

func readClientHeaders(gate transport.Network_ConnectClient) (types.PeerID, error) {
	serverHeader, err := gate.Header()
	if err != nil {
		return "", err
	}

	return readHeaders(serverHeader)
}

func readHeaders(metadata metadata.MD) (types.PeerID, error) {
	serverPeerID, err := peerIDFromMetadata(metadata)
	if err != nil {
		return "", fmt.Errorf("unable to parse PeerID: %w", err)
	}
	if serverPeerID == "" {
		return "", errors.New("peer didn't sent a PeerID")
	}

	peerVersion, err := protocolVersionFromMetadata(metadata)
	if err != nil {
		return "", err
	}
	if peerVersion != protocolVersionV1 {
		return "", fmt.Errorf("peer uses incorrect protocol version: %s", peerVersion)
	}
	return serverPeerID, nil
}

// NewAdapter creates an interface to be used connect to peers in the network and exchange messages.
func NewAdapter() Adapter {
	return &adapter{
		conns:                   newConnectionManager(),
		connectors:              make(map[string]*connector, 0),
		connectorAddChannel:     make(chan string, connectingQueueChannelSize),
		peerConnectedChannel:    make(chan types.Peer, eventChannelSize),
		peerDisconnectedChannel: make(chan types.Peer, eventChannelSize),
		serverMutex:             &sync.Mutex{},
		receivedMessages:        messageQueue{c: make(chan PeerMessage, messageBacklogChannelSize)},
		grpcDialer:              grpc.DialContext,
	}
}

type messageQueue struct {
	c chan PeerMessage
}

func (m messageQueue) Get() PeerMessage {
	return <-m.c
}

func (n *adapter) Configure(config AdapterConfig) error {
	if config.PeerID == "" {
		return errors.New("PeerID is empty")
	}
	n.config = config
	return nil
}

func (n *adapter) Start() error {
	n.serverMutex.Lock()
	defer n.serverMutex.Unlock()

	log.Logger().Debugf("Starting gRPC P2P node (ID: %s)", n.config.PeerID)

	if n.config.ListenAddress != "" {
		log.Logger().Debugf("Starting gRPC server on %s", n.config.ListenAddress)
		serverOpts := []grpc.ServerOption{
			grpc.MaxRecvMsgSize(MaxMessageSizeInBytes),
			grpc.MaxSendMsgSize(MaxMessageSizeInBytes),
		}
		var err error
		n.listener, err = net.Listen("tcp", n.config.ListenAddress)
		if err != nil {
			return err
		}
		// Set ListenAddress to actual interface address resolved by `Listen()`
		n.config.ListenAddress = n.listener.Addr().String()
		// Configure TLS if enabled
		if n.config.tlsEnabled() {
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{n.config.ServerCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    n.config.TrustStore,
			})))
		}

		if n.config.CRLValidator != nil {
			n.config.CRLValidator.SyncLoop(context.TODO())
		}

		n.startServing(serverOpts)
	}

	// Start client
	go n.connectToNewPeers()

	return nil
}

func (n *adapter) startServing(serverOpts []grpc.ServerOption) {
	server := grpc.NewServer(serverOpts...)
	n.grpcServer = server
	transport.RegisterNetworkServer(server, n)
	go func() {
		err := server.Serve(n.listener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Logger().Errorf("gRPC server errored: %v", err)
			_ = n.Stop()
		}
	}()
}

func (n *adapter) Stop() error {
	n.serverMutex.Lock()
	defer n.serverMutex.Unlock()
	// Stop client
	close(n.connectorAddChannel)
	n.conns.stop()
	// Stop gRPC server
	if n.grpcServer != nil {
		n.grpcServer.Stop()
		n.grpcServer = nil
	}
	// Stop TCP listener
	if n.listener != nil {
		if err := n.listener.Close(); err != nil {
			log.Logger().Warn("Error while closing server listener: ", err)
		}
		n.listener = nil
	}
	return nil
}

func (n adapter) ConnectToPeer(address string) bool {
	if n.shouldConnectTo(address, "") && len(n.connectorAddChannel) < connectingQueueChannelSize {
		n.connectorAddChannel <- address
		return true
	}
	return false
}

// connectToNewPeers reads from connectorAddChannel to start connecting to new peers
func (n *adapter) connectToNewPeers() {
	for address := range n.connectorAddChannel {
		if n.conns.isConnected(address) {
			log.Logger().Debugf("Not connecting to peer, already connected (address=%s)", address)
		} else if n.connectors[address] != nil {
			log.Logger().Debugf("Not connecting to peer, already trying to connect (address=%s)", address)
		} else {
			newConnector := &connector{
				address: address,
				backoff: defaultBackoff(),
				dialer:  n.grpcDialer,
			}

			n.connectors[address] = newConnector
			log.Logger().Debugf("Added remote peer (address=%s)", address)

			go n.startConnecting(newConnector)
		}
	}
}

func (n *adapter) startConnecting(newConnector *connector) {
	var resolvedPeerID types.PeerID
	for {
		if n.shouldConnectTo(newConnector.address, resolvedPeerID) {
			var tlsConfig *tls.Config

			if n.config.tlsEnabled() {
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{
						n.config.ClientCert,
					},
					RootCAs: n.config.TrustStore,
				}

				// Configure support for checking revoked certificates
				n.config.CRLValidator.Configure(tlsConfig, n.config.MaxCRLValidityDays)
			}
			if peer, stream, err := newConnector.doConnect(n.config.PeerID, tlsConfig); err != nil {
				waitPeriod := newConnector.backoff.Backoff()
				log.Logger().Infof("Couldn't connect to peer, reconnecting in %d seconds (peer=%s,err=%v)", int(waitPeriod.Seconds()), newConnector.address, err)
				time.Sleep(waitPeriod)
			} else {
				newConnector.backoff.Reset()
				// Since outgoing connections only get the peer's address as input, it doesn't know the peer's ID when initially connecting.
				// We might already have a connection to this peer, in case it connected to the local node first.
				// That's why we store the peer's ID, so we can check whether we're already connected to the peer next time before reconnecting.
				resolvedPeerID = peer.ID
				n.acceptPeer(*peer, stream)
				// When the peer's reconnection timing is very close to the local node's (because they're running the same software),
				// they might reconnect to each other at the same time after a disconnect.
				// So we add a bit of randomness before reconnecting, making the chance they reconnect at the same time a lot smaller.
				time.Sleep(RandomBackoff(time.Second, 5*time.Second))
			}
		}

		// We check whether we should (re)connect to the registered peers every second. Should be OK since it's a cheap check.
		time.Sleep(time.Second)
	}
}

// shouldConnectTo checks whether we should connect to the given node.
func (n *adapter) shouldConnectTo(address string, peerID types.PeerID) bool {
	normalizedAddress := normalizeAddress(address)
	if normalizedAddress == normalizeAddress(n.getLocalAddress()) {
		// We're not going to connect to our own node
		log.Logger().Tracef("Not connecting since it's localhost (address=%s)", address)
		return false
	}

	alreadyConnected := n.conns.isConnected(normalizedAddress)
	if alreadyConnected {
		log.Logger().Tracef("Not connected since we're already connected to a peer on that address (address=%s)", address)
	} else if peerID != "" && n.conns.get(peerID) != nil {
		log.Logger().Tracef("Not connecting since we're already connected to a peer with that ID (peer=%s)", peerID)
		alreadyConnected = true
	}

	return !alreadyConnected
}

func (n *adapter) getLocalAddress() string {
	if strings.HasPrefix(n.config.ListenAddress, ":") {
		// Interface's address not included in listening address (e.g. :5555), so prepend with localhost
		return "localhost" + n.config.ListenAddress
	}
	// Interface's address included in listening address (e.g. localhost:5555), so return as-is.
	return n.config.ListenAddress
}

// Connect is the callback that is called from the GRPC layer when a new client connects
func (n adapter) Connect(stream transport.Network_ConnectServer) error {
	peerCtx, _ := grpcPeer.FromContext(stream.Context())
	log.Logger().Tracef("New peer connected from %s", peerCtx.Addr)
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return errors.New("unable to get metadata")
	}

	peerID, err := readHeaders(md)
	if err != nil {
		return fmt.Errorf("client connection (peer=%s) rejected: %w", peerCtx.Addr, err)
	}

	peer := types.Peer{
		ID:      peerID,
		Address: peerCtx.Addr.String(),
	}
	log.Logger().Infof("New peer connected (peer=%s)", peer)
	// We received our peer's PeerID, now send our own.
	if err := stream.SendHeader(constructMetadata(n.config.PeerID)); err != nil {
		return fmt.Errorf("unable to send headers: %w", err)
	}
	n.acceptPeer(peer, stream)
	return nil
}

// acceptPeer registers a connection, associating the gRPC stream with the given peer. It starts the goroutines required
// for receiving and sending messages from/to the peer. It should be called from the gRPC service handler,
// so when this function exits (and the service handler as well), goroutines spawned for calling Recv() will exit.
func (n *adapter) acceptPeer(peer types.Peer, stream grpcMessenger) {
	conn := n.conns.register(peer, stream)
	n.peerConnectedChannel <- conn.peer()
	conn.exchange(n.receivedMessages)
	// Previous call was blocking, if we reach this the connection has either errored out, been disconnected
	// by the local node or by the peer. We still need to explicitly close it to clean up the connection
	// (in case it's closed due to a network error or by the peer).
	n.conns.close(peer.ID)
	n.peerDisconnectedChannel <- peer
}