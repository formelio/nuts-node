/*
 * Nuts node
 * Copyright (C) 2023 Nuts community
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
 */

package patient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
)

const credentialType = "NutsPatientCredential"

// signer implements the contract.Signer interface
type signer struct {
	store     SessionStore
	vcr       vcr.VCR
	publicURL string
	// signingDuration is the time the user has to sign the contract
	signingDuration time.Duration
}

// NewSigner returns an initialized patient identity contract signer
func NewSigner(vcr vcr.VCR, publicURL string) contract.Signer {
	return &signer{
		// NewMemorySessionStore returns an initialized SessionStore
		store:           NewMemorySessionStore(),
		vcr:             vcr,
		publicURL:       publicURL,
		signingDuration: 10 * time.Minute,
	}
}

// SigningSessionStatus returns the status of a signing session
// If the session is completed, a VerifiablePresentation is created and added to the result
// The session is deleted after the VerifiablePresentation is created, so the completed result can only be retrieved once
func (v *signer) SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.store.Load(sessionID)
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	var (
		vp  *vc.VerifiablePresentation
		err error
	)
	if s.Status == SessionCompleted {
		// Make sure no other VP will be created for this session
		if !v.store.CheckAndSetStatus(sessionID, SessionCompleted, SessionVPRequested) {
			// Another VP is already being created for this session
			// Make sure the session is deleted
			v.store.Delete(sessionID)
			return nil, services.ErrSessionNotFound
		}

		// Create the VerifiablePresentation
		vp, err = v.createVP(ctx, s, time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to create VerifiablePresentation: %w", err)
		}
	}

	// cleanup all sessions in a final state
	switch s.Status {
	case SessionVPRequested:
		fallthrough
	case SessionExpired:
		fallthrough
	case SessionCancelled:
		fallthrough
	case SessionErrored:
		v.store.Delete(sessionID)
	}

	return signingSessionResult{
		id:                     sessionID,
		status:                 s.Status,
		request:                s.Contract,
		verifiablePresentation: vp,
	}, nil
}

// createVP creates a VerifiablePresentation for the given session
func (v *signer) createVP(ctx context.Context, s Session, issuanceDate time.Time) (*vc.VerifiablePresentation, error) {
	issuerID, err := did.ParseDID(s.ReferringOrganization)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer DID: %w", err)
	}

	// Todo: adjust expiration date?
	expirationData := issuanceDate.Add(24 * time.Hour)
	credentialOptions := vc.VerifiableCredential{
		Context:           []ssi.URI{credential.NutsV1ContextURI},
		Type:              []ssi.URI{ssi.MustParseURI(credentialType)},
		Issuer:            issuerID.URI(),
		IssuanceDate:      issuanceDate,
		ExpirationDate:    &expirationData,
		CredentialSubject: s.CredentialSubject(),
	}
	verifiableCredential, err := v.vcr.Issuer().Issue(ctx, credentialOptions, false, false)
	if err != nil {
		return nil, fmt.Errorf("issue VC failed: %w", err)
	}
	presentationOptions := holder.PresentationOptions{
		AdditionalContexts: []ssi.URI{credential.NutsV1ContextURI},
		AdditionalTypes:    []ssi.URI{ssi.MustParseURI(VerifiablePresentationType)},
		ProofOptions: proof.ProofOptions{
			Created:      issuanceDate,
			Challenge:    &s.Contract,
			ProofPurpose: proof.AuthenticationProofPurpose,
		},
	}
	return v.vcr.Holder().BuildVP(ctx, []vc.VerifiableCredential{*verifiableCredential}, presentationOptions, issuerID, true)
}

func (v *signer) Start(ctx context.Context) {
	v.store.Start(ctx)
}

func (v *signer) StartSigningSession(userContract contract.Contract, params map[string]interface{}) (contract.SessionPointer, error) {
	// check the session params first to provide the user with feedback if something is missing
	if err := checkSessionParams(params); err != nil {
		return nil, services.InvalidContractRequestError{Message: fmt.Errorf("invalid session params: %w", err)}
	}

	const randomByteCount = 16
	sessionBytes := make([]byte, randomByteCount)
	count, err := rand.Reader.Read(sessionBytes)
	if err != nil || count != randomByteCount {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	sessionID := hex.EncodeToString(sessionBytes)
	s := Session{
		Contract: userContract.RawContractText,
		/**
		* Set session to completed as the user has given permission in accordance to the contract before the session is started
		 */
		Status:    SessionCompleted,
		ExpiresAt: time.Now().Add(v.signingDuration),
	}

	// load params directly into session
	marshalled, err := json.Marshal(params)
	// only functions or other weird constructions can cause an error here. No need for custom error handling.
	if err != nil {
		return nil, err
	}
	// impossible to get an error here since both the pointer and the data is under our control.
	_ = json.Unmarshal(marshalled, &s)

	// Parse the DID here so we can return an error
	referringOrganizationDID, err := did.ParseDID(params["referringOrganization"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed to parse referringOrganization param as DID: %w", err)
	}
	s.ReferringOrganization = referringOrganizationDID.String()
	v.store.Store(sessionID, s)

	return sessionPointer{
		sessionID: sessionID,
	}, nil
}

// checkSessionParams checks for the following structure:
//
//	{
//	  "referringOrganization":"did:123",
//	  "patient": {
//	    "identifier": "481"
//	    "name": "A. Vilcinskas",
//	  }
//	}
func checkSessionParams(params map[string]interface{}) error {
	_, ok := params["referringOrganization"]
	if !ok {
		return fmt.Errorf("missing referring organization")
	}
	patient, ok := params["patient"]
	if !ok {
		return fmt.Errorf("missing patient")
	}
	patientMap, ok := patient.(map[string]interface{})
	if !ok {
		return fmt.Errorf("patient should be an object")
	}
	_, ok = patientMap["identifier"]
	if !ok {
		return fmt.Errorf("missing patient identifier")
	}
	_, ok = patientMap["initials"]
	if !ok {
		return fmt.Errorf("missing patient initials")
	}
	_, ok = patientMap["familyName"]
	if !ok {
		return fmt.Errorf("missing patient familyName")
	}
	return nil

}
