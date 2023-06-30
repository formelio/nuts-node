// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/oidc4vci/identifiers.go

// Package oidc4vci is a generated GoMock package.
package oidc4vci

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	did "github.com/nuts-foundation/go-did/did"
)

// MockIdentifierResolver is a mock of IdentifierResolver interface.
type MockIdentifierResolver struct {
	ctrl     *gomock.Controller
	recorder *MockIdentifierResolverMockRecorder
}

// MockIdentifierResolverMockRecorder is the mock recorder for MockIdentifierResolver.
type MockIdentifierResolverMockRecorder struct {
	mock *MockIdentifierResolver
}

// NewMockIdentifierResolver creates a new mock instance.
func NewMockIdentifierResolver(ctrl *gomock.Controller) *MockIdentifierResolver {
	mock := &MockIdentifierResolver{ctrl: ctrl}
	mock.recorder = &MockIdentifierResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIdentifierResolver) EXPECT() *MockIdentifierResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockIdentifierResolver) Resolve(id did.DID) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockIdentifierResolverMockRecorder) Resolve(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockIdentifierResolver)(nil).Resolve), id)
}
