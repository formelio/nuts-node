// Code generated by MockGen. DO NOT EDIT.
// Source: crypto/interface.go

// Package crypto is a generated GoMock package.
package crypto

import (
	context "context"
	crypto "crypto"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockKeyCreator is a mock of KeyCreator interface.
type MockKeyCreator struct {
	ctrl     *gomock.Controller
	recorder *MockKeyCreatorMockRecorder
}

// MockKeyCreatorMockRecorder is the mock recorder for MockKeyCreator.
type MockKeyCreatorMockRecorder struct {
	mock *MockKeyCreator
}

// NewMockKeyCreator creates a new mock instance.
func NewMockKeyCreator(ctrl *gomock.Controller) *MockKeyCreator {
	mock := &MockKeyCreator{ctrl: ctrl}
	mock.recorder = &MockKeyCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyCreator) EXPECT() *MockKeyCreatorMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockKeyCreator) New(ctx context.Context, namingFunc KIDNamingFunc) (Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", ctx, namingFunc)
	ret0, _ := ret[0].(Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New.
func (mr *MockKeyCreatorMockRecorder) New(ctx, namingFunc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockKeyCreator)(nil).New), ctx, namingFunc)
}

// MockKeyResolver is a mock of KeyResolver interface.
type MockKeyResolver struct {
	ctrl     *gomock.Controller
	recorder *MockKeyResolverMockRecorder
}

// MockKeyResolverMockRecorder is the mock recorder for MockKeyResolver.
type MockKeyResolverMockRecorder struct {
	mock *MockKeyResolver
}

// NewMockKeyResolver creates a new mock instance.
func NewMockKeyResolver(ctrl *gomock.Controller) *MockKeyResolver {
	mock := &MockKeyResolver{ctrl: ctrl}
	mock.recorder = &MockKeyResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyResolver) EXPECT() *MockKeyResolverMockRecorder {
	return m.recorder
}

// Exists mocks base method.
func (m *MockKeyResolver) Exists(ctx context.Context, kid string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", ctx, kid)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Exists indicates an expected call of Exists.
func (mr *MockKeyResolverMockRecorder) Exists(ctx, kid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockKeyResolver)(nil).Exists), ctx, kid)
}

// List mocks base method.
func (m *MockKeyResolver) List(ctx context.Context) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx)
	ret0, _ := ret[0].([]string)
	return ret0
}

// List indicates an expected call of List.
func (mr *MockKeyResolverMockRecorder) List(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockKeyResolver)(nil).List), ctx)
}

// Resolve mocks base method.
func (m *MockKeyResolver) Resolve(ctx context.Context, kid string) (Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ctx, kid)
	ret0, _ := ret[0].(Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockKeyResolverMockRecorder) Resolve(ctx, kid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockKeyResolver)(nil).Resolve), ctx, kid)
}

// MockKeyStore is a mock of KeyStore interface.
type MockKeyStore struct {
	ctrl     *gomock.Controller
	recorder *MockKeyStoreMockRecorder
}

// MockKeyStoreMockRecorder is the mock recorder for MockKeyStore.
type MockKeyStoreMockRecorder struct {
	mock *MockKeyStore
}

// NewMockKeyStore creates a new mock instance.
func NewMockKeyStore(ctrl *gomock.Controller) *MockKeyStore {
	mock := &MockKeyStore{ctrl: ctrl}
	mock.recorder = &MockKeyStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyStore) EXPECT() *MockKeyStoreMockRecorder {
	return m.recorder
}

// Decrypt mocks base method.
func (m *MockKeyStore) Decrypt(ctx context.Context, kid string, ciphertext []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decrypt", ctx, kid, ciphertext)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Decrypt indicates an expected call of Decrypt.
func (mr *MockKeyStoreMockRecorder) Decrypt(ctx, kid, ciphertext interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decrypt", reflect.TypeOf((*MockKeyStore)(nil).Decrypt), ctx, kid, ciphertext)
}

// DecryptJWE mocks base method.
func (m *MockKeyStore) DecryptJWE(ctx context.Context, message string) ([]byte, map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecryptJWE", ctx, message)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(map[string]interface{})
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DecryptJWE indicates an expected call of DecryptJWE.
func (mr *MockKeyStoreMockRecorder) DecryptJWE(ctx, message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptJWE", reflect.TypeOf((*MockKeyStore)(nil).DecryptJWE), ctx, message)
}

// EncryptJWE mocks base method.
func (m *MockKeyStore) EncryptJWE(ctx context.Context, payload []byte, headers map[string]interface{}, publicKey interface{}) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EncryptJWE", ctx, payload, headers, publicKey)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptJWE indicates an expected call of EncryptJWE.
func (mr *MockKeyStoreMockRecorder) EncryptJWE(ctx, payload, headers, publicKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptJWE", reflect.TypeOf((*MockKeyStore)(nil).EncryptJWE), ctx, payload, headers, publicKey)
}

// Exists mocks base method.
func (m *MockKeyStore) Exists(ctx context.Context, kid string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", ctx, kid)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Exists indicates an expected call of Exists.
func (mr *MockKeyStoreMockRecorder) Exists(ctx, kid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockKeyStore)(nil).Exists), ctx, kid)
}

// List mocks base method.
func (m *MockKeyStore) List(ctx context.Context) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx)
	ret0, _ := ret[0].([]string)
	return ret0
}

// List indicates an expected call of List.
func (mr *MockKeyStoreMockRecorder) List(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockKeyStore)(nil).List), ctx)
}

// New mocks base method.
func (m *MockKeyStore) New(ctx context.Context, namingFunc KIDNamingFunc) (Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", ctx, namingFunc)
	ret0, _ := ret[0].(Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New.
func (mr *MockKeyStoreMockRecorder) New(ctx, namingFunc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockKeyStore)(nil).New), ctx, namingFunc)
}

// Resolve mocks base method.
func (m *MockKeyStore) Resolve(ctx context.Context, kid string) (Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ctx, kid)
	ret0, _ := ret[0].(Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockKeyStoreMockRecorder) Resolve(ctx, kid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockKeyStore)(nil).Resolve), ctx, kid)
}

// SignJWS mocks base method.
func (m *MockKeyStore) SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, key interface{}, detached bool) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJWS", ctx, payload, headers, key, detached)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJWS indicates an expected call of SignJWS.
func (mr *MockKeyStoreMockRecorder) SignJWS(ctx, payload, headers, key, detached interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJWS", reflect.TypeOf((*MockKeyStore)(nil).SignJWS), ctx, payload, headers, key, detached)
}

// SignJWT mocks base method.
func (m *MockKeyStore) SignJWT(ctx context.Context, claims map[string]interface{}, key interface{}) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJWT", ctx, claims, key)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJWT indicates an expected call of SignJWT.
func (mr *MockKeyStoreMockRecorder) SignJWT(ctx, claims, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJWT", reflect.TypeOf((*MockKeyStore)(nil).SignJWT), ctx, claims, key)
}

// MockDecrypter is a mock of Decrypter interface.
type MockDecrypter struct {
	ctrl     *gomock.Controller
	recorder *MockDecrypterMockRecorder
}

// MockDecrypterMockRecorder is the mock recorder for MockDecrypter.
type MockDecrypterMockRecorder struct {
	mock *MockDecrypter
}

// NewMockDecrypter creates a new mock instance.
func NewMockDecrypter(ctrl *gomock.Controller) *MockDecrypter {
	mock := &MockDecrypter{ctrl: ctrl}
	mock.recorder = &MockDecrypterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDecrypter) EXPECT() *MockDecrypterMockRecorder {
	return m.recorder
}

// Decrypt mocks base method.
func (m *MockDecrypter) Decrypt(ctx context.Context, kid string, ciphertext []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decrypt", ctx, kid, ciphertext)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Decrypt indicates an expected call of Decrypt.
func (mr *MockDecrypterMockRecorder) Decrypt(ctx, kid, ciphertext interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decrypt", reflect.TypeOf((*MockDecrypter)(nil).Decrypt), ctx, kid, ciphertext)
}

// MockJWTSigner is a mock of JWTSigner interface.
type MockJWTSigner struct {
	ctrl     *gomock.Controller
	recorder *MockJWTSignerMockRecorder
}

// MockJWTSignerMockRecorder is the mock recorder for MockJWTSigner.
type MockJWTSignerMockRecorder struct {
	mock *MockJWTSigner
}

// NewMockJWTSigner creates a new mock instance.
func NewMockJWTSigner(ctrl *gomock.Controller) *MockJWTSigner {
	mock := &MockJWTSigner{ctrl: ctrl}
	mock.recorder = &MockJWTSignerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockJWTSigner) EXPECT() *MockJWTSignerMockRecorder {
	return m.recorder
}

// DecryptJWE mocks base method.
func (m *MockJWTSigner) DecryptJWE(ctx context.Context, message string) ([]byte, map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecryptJWE", ctx, message)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(map[string]interface{})
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DecryptJWE indicates an expected call of DecryptJWE.
func (mr *MockJWTSignerMockRecorder) DecryptJWE(ctx, message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptJWE", reflect.TypeOf((*MockJWTSigner)(nil).DecryptJWE), ctx, message)
}

// EncryptJWE mocks base method.
func (m *MockJWTSigner) EncryptJWE(ctx context.Context, payload []byte, headers map[string]interface{}, publicKey interface{}) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EncryptJWE", ctx, payload, headers, publicKey)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptJWE indicates an expected call of EncryptJWE.
func (mr *MockJWTSignerMockRecorder) EncryptJWE(ctx, payload, headers, publicKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptJWE", reflect.TypeOf((*MockJWTSigner)(nil).EncryptJWE), ctx, payload, headers, publicKey)
}

// SignJWS mocks base method.
func (m *MockJWTSigner) SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, key interface{}, detached bool) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJWS", ctx, payload, headers, key, detached)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJWS indicates an expected call of SignJWS.
func (mr *MockJWTSignerMockRecorder) SignJWS(ctx, payload, headers, key, detached interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJWS", reflect.TypeOf((*MockJWTSigner)(nil).SignJWS), ctx, payload, headers, key, detached)
}

// SignJWT mocks base method.
func (m *MockJWTSigner) SignJWT(ctx context.Context, claims map[string]interface{}, key interface{}) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJWT", ctx, claims, key)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJWT indicates an expected call of SignJWT.
func (mr *MockJWTSignerMockRecorder) SignJWT(ctx, claims, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJWT", reflect.TypeOf((*MockJWTSigner)(nil).SignJWT), ctx, claims, key)
}

// MockKey is a mock of Key interface.
type MockKey struct {
	ctrl     *gomock.Controller
	recorder *MockKeyMockRecorder
}

// MockKeyMockRecorder is the mock recorder for MockKey.
type MockKeyMockRecorder struct {
	mock *MockKey
}

// NewMockKey creates a new mock instance.
func NewMockKey(ctrl *gomock.Controller) *MockKey {
	mock := &MockKey{ctrl: ctrl}
	mock.recorder = &MockKeyMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKey) EXPECT() *MockKeyMockRecorder {
	return m.recorder
}

// KID mocks base method.
func (m *MockKey) KID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KID")
	ret0, _ := ret[0].(string)
	return ret0
}

// KID indicates an expected call of KID.
func (mr *MockKeyMockRecorder) KID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KID", reflect.TypeOf((*MockKey)(nil).KID))
}

// Public mocks base method.
func (m *MockKey) Public() crypto.PublicKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Public")
	ret0, _ := ret[0].(crypto.PublicKey)
	return ret0
}

// Public indicates an expected call of Public.
func (mr *MockKeyMockRecorder) Public() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Public", reflect.TypeOf((*MockKey)(nil).Public))
}

// MockexportableKey is a mock of exportableKey interface.
type MockexportableKey struct {
	ctrl     *gomock.Controller
	recorder *MockexportableKeyMockRecorder
}

// MockexportableKeyMockRecorder is the mock recorder for MockexportableKey.
type MockexportableKeyMockRecorder struct {
	mock *MockexportableKey
}

// NewMockexportableKey creates a new mock instance.
func NewMockexportableKey(ctrl *gomock.Controller) *MockexportableKey {
	mock := &MockexportableKey{ctrl: ctrl}
	mock.recorder = &MockexportableKeyMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockexportableKey) EXPECT() *MockexportableKeyMockRecorder {
	return m.recorder
}

// KID mocks base method.
func (m *MockexportableKey) KID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KID")
	ret0, _ := ret[0].(string)
	return ret0
}

// KID indicates an expected call of KID.
func (mr *MockexportableKeyMockRecorder) KID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KID", reflect.TypeOf((*MockexportableKey)(nil).KID))
}

// Public mocks base method.
func (m *MockexportableKey) Public() crypto.PublicKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Public")
	ret0, _ := ret[0].(crypto.PublicKey)
	return ret0
}

// Public indicates an expected call of Public.
func (mr *MockexportableKeyMockRecorder) Public() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Public", reflect.TypeOf((*MockexportableKey)(nil).Public))
}

// Signer mocks base method.
func (m *MockexportableKey) Signer() crypto.Signer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Signer")
	ret0, _ := ret[0].(crypto.Signer)
	return ret0
}

// Signer indicates an expected call of Signer.
func (mr *MockexportableKeyMockRecorder) Signer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Signer", reflect.TypeOf((*MockexportableKey)(nil).Signer))
}
