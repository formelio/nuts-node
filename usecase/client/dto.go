package client

import "gorm.io/gorm/schema"

var _ schema.Tabler = (*list)(nil)

// list holds metadata for a use case list.
type list struct {
	// UsecaseID is the unique identifier list, corresponding with the use case UsecaseID
	UsecaseID string `gorm:"primaryKey"`
	// Timestamp is the last timestamp returned by the server when the list was fetched.
	Timestamp uint64
}

// TableName returns the table name for this DTO.
func (l list) TableName() string {
	return "usecase_client_list"
}

var _ schema.Tabler = (*entry)(nil)

// entry is a Verifiable Presentation on a use case list.
type entry struct {
	// ID is the unique identifier of the entry.
	ID string `gorm:"primaryKey"`
	// UsecaseID is the unique identifier of the use case.
	UsecaseID string
	// PresentationID is the unique identifier of the entry.
	PresentationID string
	// PresentationRaw is the entry in raw format (JWT).
	PresentationRaw string
	// PresentationExpiration is the expiration date of the entry.
	PresentationExpiration int64
	Credentials            []credential
}

// TableName returns the table name for this DTO.
func (p entry) TableName() string {
	return "usecase_client_entries"
}

var _ schema.Tabler = (*entry)(nil)

// credential is a Verifiable Credential, part of a presentation (entry) on a use case list.
type credential struct {
	// ID is the unique identifier of the entry.
	ID string `gorm:"primaryKey"`
	// EntryID corresponds to the list entry (VP) this credential belongs to.
	EntryID string
	// CredentialID contains the 'id' property of the Verifiable Credential.
	CredentialID string
	// CredentialIssuer contains the 'issuer' property of the Verifiable Credential.
	CredentialIssuer string
	// CredentialSubjectID contains the 'credentialSubject.id' property of the Verifiable Credential.
	CredentialSubjectID string
	// CredentialType contains the 'type' property of the Verifiable Credential (not being 'VerifiableCredential').
	CredentialType *string
	Properties     []property `gorm:"foreignKey:ID;references:ID"`
}

// TableName returns the table name for this DTO.
func (p credential) TableName() string {
	return "usecase_client_credential"
}

// property is a property of a Verifiable Presentation on a use case list.
type property struct {
	// ID refers to the entry record in usecase_list_client
	ID string `gorm:"primaryKey"`
	// Key is JSON path of the property.
	Key string `gorm:"primaryKey"`
	// Value is the value of the property.
	Value string
}

// TableName returns the table name for this DTO.
func (l property) TableName() string {
	return "usecase_client_presentation_props"
}
