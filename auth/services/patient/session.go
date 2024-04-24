package patient

import (
	"encoding/json"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

type signingSessionResult struct {
	id                     string
	status                 string
	request                string
	verifiablePresentation *vc.VerifiablePresentation
}

func (s signingSessionResult) Status() string {
	return s.status
}

func (s signingSessionResult) VerifiablePresentation() (*vc.VerifiablePresentation, error) {
	return s.verifiablePresentation, nil
}

type sessionPointer struct {
	sessionID string
}

func (s sessionPointer) SessionID() string {
	return s.sessionID
}

func (s sessionPointer) Payload() []byte {
	return []byte{}
}

func (s sessionPointer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SessionID string `json:"sessionID"`
	}{SessionID: s.sessionID})
}

// Session contains the contract text and Session signing Status
type Session struct {
	ExpiresAt             time.Time
	Contract              string
	Status                string
	ReferringOrganization string
	Patient               Patient
}

func (s Session) CredentialSubject() []interface{} {
	subject := PatientIdentityCredentialSubject{
		BaseCredentialSubject: credential.BaseCredentialSubject{
			ID: s.ReferringOrganization,
		},
		Type: "Organization",
		Member: PatientIdentityCredentialMember{
			Identifier: s.Patient.Identifier,
			Member: PatientIdentityCredentialMemberMember{
				FamilyName: s.Patient.FamilyName,
				Initials:   s.Patient.Initials,
				Type:       "Patient",
			},
		},
	}
	data, _ := json.Marshal(subject)
	result := map[string]interface{}{}
	_ = json.Unmarshal(data, &result)
	return []interface{}{result}
}

type Patient struct {
	Identifier string
	Initials   string
	FamilyName string
}

type PatientIdentityCredentialSubject struct {
	credential.BaseCredentialSubject
	Type   string                          `json:"type"`
	Member PatientIdentityCredentialMember `json:"member"`
}

type PatientIdentityCredentialMember struct {
	Identifier string                                `json:"identifier"`
	Member     PatientIdentityCredentialMemberMember `json:"member"`
}

type PatientIdentityCredentialMemberMember struct {
	Initials   string `json:"initials"`
	FamilyName string `json:"familyName"`
	Type       string `json:"type"`
}
