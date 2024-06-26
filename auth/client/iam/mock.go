// Code generated by MockGen. DO NOT EDIT.
// Source: auth/client/iam/interface.go
//
// Generated by this command:
//
//	mockgen -destination=auth/client/iam/mock.go -package=iam -source=auth/client/iam/interface.go
//

// Package iam is a generated GoMock package.
package iam

import (
	context "context"
	url "net/url"
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	vc "github.com/nuts-foundation/go-did/vc"
	oauth "github.com/nuts-foundation/nuts-node/auth/oauth"
	pe "github.com/nuts-foundation/nuts-node/vcr/pe"
	gomock "go.uber.org/mock/gomock"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AccessToken mocks base method.
func (m *MockClient) AccessToken(ctx context.Context, code string, verifier did.DID, callbackURI string, clientID did.DID, codeVerifier string) (*oauth.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessToken", ctx, code, verifier, callbackURI, clientID, codeVerifier)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AccessToken indicates an expected call of AccessToken.
func (mr *MockClientMockRecorder) AccessToken(ctx, code, verifier, callbackURI, clientID, codeVerifier any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessToken", reflect.TypeOf((*MockClient)(nil).AccessToken), ctx, code, verifier, callbackURI, clientID, codeVerifier)
}

// AccessTokenOid4vci mocks base method.
func (m *MockClient) AccessTokenOid4vci(ctx context.Context, clientId, tokenEndpoint, redirectUri, code string, pkceCodeVerifier *string) (*oauth.Oid4vciTokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessTokenOid4vci", ctx, clientId, tokenEndpoint, redirectUri, code, pkceCodeVerifier)
	ret0, _ := ret[0].(*oauth.Oid4vciTokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AccessTokenOid4vci indicates an expected call of AccessTokenOid4vci.
func (mr *MockClientMockRecorder) AccessTokenOid4vci(ctx, clientId, tokenEndpoint, redirectUri, code, pkceCodeVerifier any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessTokenOid4vci", reflect.TypeOf((*MockClient)(nil).AccessTokenOid4vci), ctx, clientId, tokenEndpoint, redirectUri, code, pkceCodeVerifier)
}

// AuthorizationServerMetadata mocks base method.
func (m *MockClient) AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizationServerMetadata", ctx, webdid)
	ret0, _ := ret[0].(*oauth.AuthorizationServerMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthorizationServerMetadata indicates an expected call of AuthorizationServerMetadata.
func (mr *MockClientMockRecorder) AuthorizationServerMetadata(ctx, webdid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizationServerMetadata", reflect.TypeOf((*MockClient)(nil).AuthorizationServerMetadata), ctx, webdid)
}

// ClientMetadata mocks base method.
func (m *MockClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientMetadata", ctx, endpoint)
	ret0, _ := ret[0].(*oauth.OAuthClientMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ClientMetadata indicates an expected call of ClientMetadata.
func (mr *MockClientMockRecorder) ClientMetadata(ctx, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientMetadata", reflect.TypeOf((*MockClient)(nil).ClientMetadata), ctx, endpoint)
}

// CreateAuthorizationRequest mocks base method.
func (m *MockClient) CreateAuthorizationRequest(ctx context.Context, client, server did.DID, modifier RequestModifier) (*url.URL, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAuthorizationRequest", ctx, client, server, modifier)
	ret0, _ := ret[0].(*url.URL)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAuthorizationRequest indicates an expected call of CreateAuthorizationRequest.
func (mr *MockClientMockRecorder) CreateAuthorizationRequest(ctx, client, server, modifier any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthorizationRequest", reflect.TypeOf((*MockClient)(nil).CreateAuthorizationRequest), ctx, client, server, modifier)
}

// OpenIdConfiguration mocks base method.
func (m *MockClient) OpenIdConfiguration(ctx context.Context, serverURL string) (*oauth.OpenIDConfigurationMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenIdConfiguration", ctx, serverURL)
	ret0, _ := ret[0].(*oauth.OpenIDConfigurationMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenIdConfiguration indicates an expected call of OpenIdConfiguration.
func (mr *MockClientMockRecorder) OpenIdConfiguration(ctx, serverURL any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenIdConfiguration", reflect.TypeOf((*MockClient)(nil).OpenIdConfiguration), ctx, serverURL)
}

// OpenIdCredentialIssuerMetadata mocks base method.
func (m *MockClient) OpenIdCredentialIssuerMetadata(ctx context.Context, webDID did.DID) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenIdCredentialIssuerMetadata", ctx, webDID)
	ret0, _ := ret[0].(*oauth.OpenIDCredentialIssuerMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenIdCredentialIssuerMetadata indicates an expected call of OpenIdCredentialIssuerMetadata.
func (mr *MockClientMockRecorder) OpenIdCredentialIssuerMetadata(ctx, webDID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenIdCredentialIssuerMetadata", reflect.TypeOf((*MockClient)(nil).OpenIdCredentialIssuerMetadata), ctx, webDID)
}

// PostAuthorizationResponse mocks base method.
func (m *MockClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI, state string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostAuthorizationResponse", ctx, vp, presentationSubmission, verifierResponseURI, state)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostAuthorizationResponse indicates an expected call of PostAuthorizationResponse.
func (mr *MockClientMockRecorder) PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI, state any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostAuthorizationResponse", reflect.TypeOf((*MockClient)(nil).PostAuthorizationResponse), ctx, vp, presentationSubmission, verifierResponseURI, state)
}

// PostError mocks base method.
func (m *MockClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI, verifierClientState string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostError", ctx, auth2Error, verifierResponseURI, verifierClientState)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostError indicates an expected call of PostError.
func (mr *MockClientMockRecorder) PostError(ctx, auth2Error, verifierResponseURI, verifierClientState any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostError", reflect.TypeOf((*MockClient)(nil).PostError), ctx, auth2Error, verifierResponseURI, verifierClientState)
}

// PresentationDefinition mocks base method.
func (m *MockClient) PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PresentationDefinition", ctx, endpoint)
	ret0, _ := ret[0].(*pe.PresentationDefinition)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PresentationDefinition indicates an expected call of PresentationDefinition.
func (mr *MockClientMockRecorder) PresentationDefinition(ctx, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PresentationDefinition", reflect.TypeOf((*MockClient)(nil).PresentationDefinition), ctx, endpoint)
}

// RequestRFC021AccessToken mocks base method.
func (m *MockClient) RequestRFC021AccessToken(ctx context.Context, requestHolder, verifier did.DID, scopes string) (*oauth.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestRFC021AccessToken", ctx, requestHolder, verifier, scopes)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestRFC021AccessToken indicates an expected call of RequestRFC021AccessToken.
func (mr *MockClientMockRecorder) RequestRFC021AccessToken(ctx, requestHolder, verifier, scopes any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestRFC021AccessToken", reflect.TypeOf((*MockClient)(nil).RequestRFC021AccessToken), ctx, requestHolder, verifier, scopes)
}

// VerifiableCredentials mocks base method.
func (m *MockClient) VerifiableCredentials(ctx context.Context, credentialEndpoint, accessToken string, cNonce *string, holderDid, audienceDid did.DID) (*CredentialResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifiableCredentials", ctx, credentialEndpoint, accessToken, cNonce, holderDid, audienceDid)
	ret0, _ := ret[0].(*CredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifiableCredentials indicates an expected call of VerifiableCredentials.
func (mr *MockClientMockRecorder) VerifiableCredentials(ctx, credentialEndpoint, accessToken, cNonce, holderDid, audienceDid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifiableCredentials", reflect.TypeOf((*MockClient)(nil).VerifiableCredentials), ctx, credentialEndpoint, accessToken, cNonce, holderDid, audienceDid)
}
