package model

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// Definition holds the definition of a use case list.
type Definition struct {
	// ID is the unique identifier of the use case.
	ID string `json:"id"`
	// Endpoint is the endpoint where the use case list is served.
	Endpoint string `json:"endpoint"`
	// PresentationDefinition specifies the Presentation Definition submissions to the list must conform to,
	// according to the Presentation Exchange specification.
	PresentationDefinition pe.PresentationDefinition `json:"presentation_definition"`
	// PresentationMaxValidity specifies how long submitted presentations are allowed to be valid (in seconds).
	PresentationMaxValidity int `json:"presentation_max_validity"`
}

type ListResponse struct {
	Entries   []vc.VerifiablePresentation `json:"entries"`
	Timestamp uint64                      `json:"timestamp"`
	Tombstone []string                    `json:"tombstone"`
}
