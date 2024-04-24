package patient

import (
	"context"
	"errors"
)

// VerifiablePresentationType is the patient verifiable presentation type
const VerifiablePresentationType = "NutsPatientPresentation"

// ContractFormat is the contract format type
const ContractFormat = "patientid"

type SessionStore interface {
	Start(ctx context.Context)
	Store(sessionID string, session Session)
	Load(sessionID string) (Session, bool)
	CheckAndSetStatus(sessionID string, expectedStatus, status string) bool
	Delete(sessionID string)
}

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionInProgress represents the session state after rendering the html
const SessionInProgress = "in-progress"

// SessionCompleted represents the session state after the user has accepted the contract
const SessionCompleted = "completed"

const SessionVPRequested = "vp-requested"

const SessionCancelled = "cancelled"

const SessionErrored = "errored"

const SessionExpired = "expired"

type verificationError struct {
	err error
}

func (v verificationError) Error() string {
	return v.err.Error()
}

func (v verificationError) Is(other error) bool {
	_, is := other.(verificationError)
	return is
}

func newVerificationError(error string) error {
	return verificationError{err: errors.New(error)}
}
