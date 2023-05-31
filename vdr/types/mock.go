// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/types/interface.go

// Package types is a generated GoMock package.
package types

import (
	context "context"
	crypto "crypto"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	go_did "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	crypto0 "github.com/nuts-foundation/nuts-node/crypto"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
)

// MockDocResolver is a mock of DocResolver interface.
type MockDocResolver struct {
	ctrl     *gomock.Controller
	recorder *MockDocResolverMockRecorder
}

// MockDocResolverMockRecorder is the mock recorder for MockDocResolver.
type MockDocResolverMockRecorder struct {
	mock *MockDocResolver
}

// NewMockDocResolver creates a new mock instance.
func NewMockDocResolver(ctrl *gomock.Controller) *MockDocResolver {
	mock := &MockDocResolver{ctrl: ctrl}
	mock.recorder = &MockDocResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocResolver) EXPECT() *MockDocResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockDocResolver) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockDocResolverMockRecorder) Resolve(id, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockDocResolver)(nil).Resolve), id, metadata)
}

// ResolveControllers mocks base method.
func (m *MockDocResolver) ResolveControllers(input did.Document, metadata *ResolveMetadata) ([]did.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveControllers", input, metadata)
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveControllers indicates an expected call of ResolveControllers.
func (mr *MockDocResolverMockRecorder) ResolveControllers(input, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveControllers", reflect.TypeOf((*MockDocResolver)(nil).ResolveControllers), input, metadata)
}

// MockPredicate is a mock of Predicate interface.
type MockPredicate struct {
	ctrl     *gomock.Controller
	recorder *MockPredicateMockRecorder
}

// MockPredicateMockRecorder is the mock recorder for MockPredicate.
type MockPredicateMockRecorder struct {
	mock *MockPredicate
}

// NewMockPredicate creates a new mock instance.
func NewMockPredicate(ctrl *gomock.Controller) *MockPredicate {
	mock := &MockPredicate{ctrl: ctrl}
	mock.recorder = &MockPredicateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPredicate) EXPECT() *MockPredicateMockRecorder {
	return m.recorder
}

// Match mocks base method.
func (m *MockPredicate) Match(arg0 did.Document, arg1 DocumentMetadata) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Match", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Match indicates an expected call of Match.
func (mr *MockPredicateMockRecorder) Match(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Match", reflect.TypeOf((*MockPredicate)(nil).Match), arg0, arg1)
}

// MockDocFinder is a mock of DocFinder interface.
type MockDocFinder struct {
	ctrl     *gomock.Controller
	recorder *MockDocFinderMockRecorder
}

// MockDocFinderMockRecorder is the mock recorder for MockDocFinder.
type MockDocFinderMockRecorder struct {
	mock *MockDocFinder
}

// NewMockDocFinder creates a new mock instance.
func NewMockDocFinder(ctrl *gomock.Controller) *MockDocFinder {
	mock := &MockDocFinder{ctrl: ctrl}
	mock.recorder = &MockDocFinderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocFinder) EXPECT() *MockDocFinderMockRecorder {
	return m.recorder
}

// Find mocks base method.
func (m *MockDocFinder) Find(arg0 ...Predicate) ([]did.Document, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Find", varargs...)
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Find indicates an expected call of Find.
func (mr *MockDocFinderMockRecorder) Find(arg0 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Find", reflect.TypeOf((*MockDocFinder)(nil).Find), arg0...)
}

// MockDocCreator is a mock of DocCreator interface.
type MockDocCreator struct {
	ctrl     *gomock.Controller
	recorder *MockDocCreatorMockRecorder
}

// MockDocCreatorMockRecorder is the mock recorder for MockDocCreator.
type MockDocCreatorMockRecorder struct {
	mock *MockDocCreator
}

// NewMockDocCreator creates a new mock instance.
func NewMockDocCreator(ctrl *gomock.Controller) *MockDocCreator {
	mock := &MockDocCreator{ctrl: ctrl}
	mock.recorder = &MockDocCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocCreator) EXPECT() *MockDocCreatorMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockDocCreator) Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto0.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto0.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockDocCreatorMockRecorder) Create(ctx, options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockDocCreator)(nil).Create), ctx, options)
}

// MockDocWriter is a mock of DocWriter interface.
type MockDocWriter struct {
	ctrl     *gomock.Controller
	recorder *MockDocWriterMockRecorder
}

// MockDocWriterMockRecorder is the mock recorder for MockDocWriter.
type MockDocWriterMockRecorder struct {
	mock *MockDocWriter
}

// NewMockDocWriter creates a new mock instance.
func NewMockDocWriter(ctrl *gomock.Controller) *MockDocWriter {
	mock := &MockDocWriter{ctrl: ctrl}
	mock.recorder = &MockDocWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocWriter) EXPECT() *MockDocWriterMockRecorder {
	return m.recorder
}

// Write mocks base method.
func (m *MockDocWriter) Write(document did.Document, metadata DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", document, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockDocWriterMockRecorder) Write(document, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockDocWriter)(nil).Write), document, metadata)
}

// MockDocUpdater is a mock of DocUpdater interface.
type MockDocUpdater struct {
	ctrl     *gomock.Controller
	recorder *MockDocUpdaterMockRecorder
}

// MockDocUpdaterMockRecorder is the mock recorder for MockDocUpdater.
type MockDocUpdaterMockRecorder struct {
	mock *MockDocUpdater
}

// NewMockDocUpdater creates a new mock instance.
func NewMockDocUpdater(ctrl *gomock.Controller) *MockDocUpdater {
	mock := &MockDocUpdater{ctrl: ctrl}
	mock.recorder = &MockDocUpdaterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocUpdater) EXPECT() *MockDocUpdaterMockRecorder {
	return m.recorder
}

// Update mocks base method.
func (m *MockDocUpdater) Update(ctx context.Context, id did.DID, next did.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDocUpdaterMockRecorder) Update(ctx, id, next interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDocUpdater)(nil).Update), ctx, id, next)
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

// ResolveAssertionKeyID mocks base method.
func (m *MockKeyResolver) ResolveAssertionKeyID(id did.DID) (go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAssertionKeyID", id)
	ret0, _ := ret[0].(go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveAssertionKeyID indicates an expected call of ResolveAssertionKeyID.
func (mr *MockKeyResolverMockRecorder) ResolveAssertionKeyID(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAssertionKeyID", reflect.TypeOf((*MockKeyResolver)(nil).ResolveAssertionKeyID), id)
}

// ResolveKeyAgreementKey mocks base method.
func (m *MockKeyResolver) ResolveKeyAgreementKey(id did.DID) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveKeyAgreementKey", id)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveKeyAgreementKey indicates an expected call of ResolveKeyAgreementKey.
func (mr *MockKeyResolverMockRecorder) ResolveKeyAgreementKey(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveKeyAgreementKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolveKeyAgreementKey), id)
}

// ResolvePublicKey mocks base method.
func (m *MockKeyResolver) ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolvePublicKey", kid, sourceTransactionsRefs)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolvePublicKey indicates an expected call of ResolvePublicKey.
func (mr *MockKeyResolverMockRecorder) ResolvePublicKey(kid, sourceTransactionsRefs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolvePublicKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolvePublicKey), kid, sourceTransactionsRefs)
}

// ResolveRelationKey mocks base method.
func (m *MockKeyResolver) ResolveRelationKey(keyID string, validAt *time.Time, relationType RelationType) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveRelationKey", keyID, validAt, relationType)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveRelationKey indicates an expected call of ResolveRelationKey.
func (mr *MockKeyResolverMockRecorder) ResolveRelationKey(keyID, validAt, relationType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveRelationKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolveRelationKey), keyID, validAt, relationType)
}

// ResolveRelationKeyID mocks base method.
func (m *MockKeyResolver) ResolveRelationKeyID(id did.DID, relationType RelationType) (go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveRelationKeyID", id, relationType)
	ret0, _ := ret[0].(go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveRelationKeyID indicates an expected call of ResolveRelationKeyID.
func (mr *MockKeyResolverMockRecorder) ResolveRelationKeyID(id, relationType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveRelationKeyID", reflect.TypeOf((*MockKeyResolver)(nil).ResolveRelationKeyID), id, relationType)
}

// ResolveSigningKey mocks base method.
func (m *MockKeyResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKey", keyID, validAt)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKey indicates an expected call of ResolveSigningKey.
func (mr *MockKeyResolverMockRecorder) ResolveSigningKey(keyID, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolveSigningKey), keyID, validAt)
}

// ResolveSigningKeyID mocks base method.
func (m *MockKeyResolver) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKeyID", holder, validAt)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKeyID indicates an expected call of ResolveSigningKeyID.
func (mr *MockKeyResolverMockRecorder) ResolveSigningKeyID(holder, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKeyID", reflect.TypeOf((*MockKeyResolver)(nil).ResolveSigningKeyID), holder, validAt)
}

// MockVDR is a mock of VDR interface.
type MockVDR struct {
	ctrl     *gomock.Controller
	recorder *MockVDRMockRecorder
}

// MockVDRMockRecorder is the mock recorder for MockVDR.
type MockVDRMockRecorder struct {
	mock *MockVDR
}

// NewMockVDR creates a new mock instance.
func NewMockVDR(ctrl *gomock.Controller) *MockVDR {
	mock := &MockVDR{ctrl: ctrl}
	mock.recorder = &MockVDRMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVDR) EXPECT() *MockVDRMockRecorder {
	return m.recorder
}

// ConflictedDocuments mocks base method.
func (m *MockVDR) ConflictedDocuments() ([]did.Document, []DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConflictedDocuments")
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].([]DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ConflictedDocuments indicates an expected call of ConflictedDocuments.
func (mr *MockVDRMockRecorder) ConflictedDocuments() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConflictedDocuments", reflect.TypeOf((*MockVDR)(nil).ConflictedDocuments))
}

// Create mocks base method.
func (m *MockVDR) Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto0.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto0.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockVDRMockRecorder) Create(ctx, options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockVDR)(nil).Create), ctx, options)
}

// Update mocks base method.
func (m *MockVDR) Update(ctx context.Context, id did.DID, next did.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockVDRMockRecorder) Update(ctx, id, next interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockVDR)(nil).Update), ctx, id, next)
}

// MockDocManipulator is a mock of DocManipulator interface.
type MockDocManipulator struct {
	ctrl     *gomock.Controller
	recorder *MockDocManipulatorMockRecorder
}

// MockDocManipulatorMockRecorder is the mock recorder for MockDocManipulator.
type MockDocManipulatorMockRecorder struct {
	mock *MockDocManipulator
}

// NewMockDocManipulator creates a new mock instance.
func NewMockDocManipulator(ctrl *gomock.Controller) *MockDocManipulator {
	mock := &MockDocManipulator{ctrl: ctrl}
	mock.recorder = &MockDocManipulatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocManipulator) EXPECT() *MockDocManipulatorMockRecorder {
	return m.recorder
}

// AddVerificationMethod mocks base method.
func (m *MockDocManipulator) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage DIDKeyFlags) (*did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddVerificationMethod", ctx, id, keyUsage)
	ret0, _ := ret[0].(*did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddVerificationMethod indicates an expected call of AddVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) AddVerificationMethod(ctx, id, keyUsage interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).AddVerificationMethod), ctx, id, keyUsage)
}

// Deactivate mocks base method.
func (m *MockDocManipulator) Deactivate(ctx context.Context, id did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockDocManipulatorMockRecorder) Deactivate(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockDocManipulator)(nil).Deactivate), ctx, id)
}

// RemoveVerificationMethod mocks base method.
func (m *MockDocManipulator) RemoveVerificationMethod(ctx context.Context, id, keyID did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveVerificationMethod", ctx, id, keyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveVerificationMethod indicates an expected call of RemoveVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) RemoveVerificationMethod(ctx, id, keyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).RemoveVerificationMethod), ctx, id, keyID)
}
