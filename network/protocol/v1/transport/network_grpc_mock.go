// Code generated by MockGen. DO NOT EDIT.
// Source: network/protocol/v1/transport/network_grpc.pb.go

// Package transport is a generated GoMock package.
package transport

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	grpc "google.golang.org/grpc"
	metadata "google.golang.org/grpc/metadata"
)

// MockNetworkClient is a mock of NetworkClient interface.
type MockNetworkClient struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkClientMockRecorder
}

// MockNetworkClientMockRecorder is the mock recorder for MockNetworkClient.
type MockNetworkClientMockRecorder struct {
	mock *MockNetworkClient
}

// NewMockNetworkClient creates a new mock instance.
func NewMockNetworkClient(ctrl *gomock.Controller) *MockNetworkClient {
	mock := &MockNetworkClient{ctrl: ctrl}
	mock.recorder = &MockNetworkClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetworkClient) EXPECT() *MockNetworkClientMockRecorder {
	return m.recorder
}

// Connect mocks base method.
func (m *MockNetworkClient) Connect(ctx context.Context, opts ...grpc.CallOption) (Network_ConnectClient, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Connect", varargs...)
	ret0, _ := ret[0].(Network_ConnectClient)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Connect indicates an expected call of Connect.
func (mr *MockNetworkClientMockRecorder) Connect(ctx interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Connect", reflect.TypeOf((*MockNetworkClient)(nil).Connect), varargs...)
}

// MockNetwork_ConnectClient is a mock of Network_ConnectClient interface.
type MockNetwork_ConnectClient struct {
	ctrl     *gomock.Controller
	recorder *MockNetwork_ConnectClientMockRecorder
}

// MockNetwork_ConnectClientMockRecorder is the mock recorder for MockNetwork_ConnectClient.
type MockNetwork_ConnectClientMockRecorder struct {
	mock *MockNetwork_ConnectClient
}

// NewMockNetwork_ConnectClient creates a new mock instance.
func NewMockNetwork_ConnectClient(ctrl *gomock.Controller) *MockNetwork_ConnectClient {
	mock := &MockNetwork_ConnectClient{ctrl: ctrl}
	mock.recorder = &MockNetwork_ConnectClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetwork_ConnectClient) EXPECT() *MockNetwork_ConnectClientMockRecorder {
	return m.recorder
}

// CloseSend mocks base method.
func (m *MockNetwork_ConnectClient) CloseSend() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseSend")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseSend indicates an expected call of CloseSend.
func (mr *MockNetwork_ConnectClientMockRecorder) CloseSend() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseSend", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).CloseSend))
}

// Context mocks base method.
func (m *MockNetwork_ConnectClient) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockNetwork_ConnectClientMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).Context))
}

// Header mocks base method.
func (m *MockNetwork_ConnectClient) Header() (metadata.MD, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Header")
	ret0, _ := ret[0].(metadata.MD)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Header indicates an expected call of Header.
func (mr *MockNetwork_ConnectClientMockRecorder) Header() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Header", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).Header))
}

// Recv mocks base method.
func (m *MockNetwork_ConnectClient) Recv() (*NetworkMessage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*NetworkMessage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv.
func (mr *MockNetwork_ConnectClientMockRecorder) Recv() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).Recv))
}

// RecvMsg mocks base method.
func (m_2 *MockNetwork_ConnectClient) RecvMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "RecvMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockNetwork_ConnectClientMockRecorder) RecvMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).RecvMsg), m)
}

// Send mocks base method.
func (m *MockNetwork_ConnectClient) Send(arg0 *NetworkMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send.
func (mr *MockNetwork_ConnectClientMockRecorder) Send(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).Send), arg0)
}

// SendMsg mocks base method.
func (m_2 *MockNetwork_ConnectClient) SendMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "SendMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockNetwork_ConnectClientMockRecorder) SendMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).SendMsg), m)
}

// Trailer mocks base method.
func (m *MockNetwork_ConnectClient) Trailer() metadata.MD {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trailer")
	ret0, _ := ret[0].(metadata.MD)
	return ret0
}

// Trailer indicates an expected call of Trailer.
func (mr *MockNetwork_ConnectClientMockRecorder) Trailer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trailer", reflect.TypeOf((*MockNetwork_ConnectClient)(nil).Trailer))
}

// MockNetworkServer is a mock of NetworkServer interface.
type MockNetworkServer struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkServerMockRecorder
}

// MockNetworkServerMockRecorder is the mock recorder for MockNetworkServer.
type MockNetworkServerMockRecorder struct {
	mock *MockNetworkServer
}

// NewMockNetworkServer creates a new mock instance.
func NewMockNetworkServer(ctrl *gomock.Controller) *MockNetworkServer {
	mock := &MockNetworkServer{ctrl: ctrl}
	mock.recorder = &MockNetworkServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetworkServer) EXPECT() *MockNetworkServerMockRecorder {
	return m.recorder
}

// Connect mocks base method.
func (m *MockNetworkServer) Connect(arg0 Network_ConnectServer) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Connect", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Connect indicates an expected call of Connect.
func (mr *MockNetworkServerMockRecorder) Connect(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Connect", reflect.TypeOf((*MockNetworkServer)(nil).Connect), arg0)
}

// MockUnsafeNetworkServer is a mock of UnsafeNetworkServer interface.
type MockUnsafeNetworkServer struct {
	ctrl     *gomock.Controller
	recorder *MockUnsafeNetworkServerMockRecorder
}

// MockUnsafeNetworkServerMockRecorder is the mock recorder for MockUnsafeNetworkServer.
type MockUnsafeNetworkServerMockRecorder struct {
	mock *MockUnsafeNetworkServer
}

// NewMockUnsafeNetworkServer creates a new mock instance.
func NewMockUnsafeNetworkServer(ctrl *gomock.Controller) *MockUnsafeNetworkServer {
	mock := &MockUnsafeNetworkServer{ctrl: ctrl}
	mock.recorder = &MockUnsafeNetworkServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUnsafeNetworkServer) EXPECT() *MockUnsafeNetworkServerMockRecorder {
	return m.recorder
}

// mustEmbedUnimplementedNetworkServer mocks base method.
func (m *MockUnsafeNetworkServer) mustEmbedUnimplementedNetworkServer() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "mustEmbedUnimplementedNetworkServer")
}

// mustEmbedUnimplementedNetworkServer indicates an expected call of mustEmbedUnimplementedNetworkServer.
func (mr *MockUnsafeNetworkServerMockRecorder) mustEmbedUnimplementedNetworkServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "mustEmbedUnimplementedNetworkServer", reflect.TypeOf((*MockUnsafeNetworkServer)(nil).mustEmbedUnimplementedNetworkServer))
}

// MockNetwork_ConnectServer is a mock of Network_ConnectServer interface.
type MockNetwork_ConnectServer struct {
	ctrl     *gomock.Controller
	recorder *MockNetwork_ConnectServerMockRecorder
}

// MockNetwork_ConnectServerMockRecorder is the mock recorder for MockNetwork_ConnectServer.
type MockNetwork_ConnectServerMockRecorder struct {
	mock *MockNetwork_ConnectServer
}

// NewMockNetwork_ConnectServer creates a new mock instance.
func NewMockNetwork_ConnectServer(ctrl *gomock.Controller) *MockNetwork_ConnectServer {
	mock := &MockNetwork_ConnectServer{ctrl: ctrl}
	mock.recorder = &MockNetwork_ConnectServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetwork_ConnectServer) EXPECT() *MockNetwork_ConnectServerMockRecorder {
	return m.recorder
}

// Context mocks base method.
func (m *MockNetwork_ConnectServer) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockNetwork_ConnectServerMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).Context))
}

// Recv mocks base method.
func (m *MockNetwork_ConnectServer) Recv() (*NetworkMessage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*NetworkMessage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv.
func (mr *MockNetwork_ConnectServerMockRecorder) Recv() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).Recv))
}

// RecvMsg mocks base method.
func (m_2 *MockNetwork_ConnectServer) RecvMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "RecvMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockNetwork_ConnectServerMockRecorder) RecvMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).RecvMsg), m)
}

// Send mocks base method.
func (m *MockNetwork_ConnectServer) Send(arg0 *NetworkMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send.
func (mr *MockNetwork_ConnectServerMockRecorder) Send(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).Send), arg0)
}

// SendHeader mocks base method.
func (m *MockNetwork_ConnectServer) SendHeader(arg0 metadata.MD) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHeader", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHeader indicates an expected call of SendHeader.
func (mr *MockNetwork_ConnectServerMockRecorder) SendHeader(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHeader", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).SendHeader), arg0)
}

// SendMsg mocks base method.
func (m_2 *MockNetwork_ConnectServer) SendMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "SendMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockNetwork_ConnectServerMockRecorder) SendMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).SendMsg), m)
}

// SetHeader mocks base method.
func (m *MockNetwork_ConnectServer) SetHeader(arg0 metadata.MD) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetHeader", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetHeader indicates an expected call of SetHeader.
func (mr *MockNetwork_ConnectServerMockRecorder) SetHeader(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetHeader", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).SetHeader), arg0)
}

// SetTrailer mocks base method.
func (m *MockNetwork_ConnectServer) SetTrailer(arg0 metadata.MD) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetTrailer", arg0)
}

// SetTrailer indicates an expected call of SetTrailer.
func (mr *MockNetwork_ConnectServerMockRecorder) SetTrailer(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTrailer", reflect.TypeOf((*MockNetwork_ConnectServer)(nil).SetTrailer), arg0)
}