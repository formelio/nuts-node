package model

import (
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"time"
)

var TestDefinition = Definition{
	ID:       "urn:nuts:example.com:usecase:test",
	Endpoint: "http://example.com/usecase",
	PresentationDefinition: pe.PresentationDefinition{
		InputDescriptors: []*pe.InputDescriptor{
			{
				Constraints: &pe.Constraints{
					Fields: []pe.Field{
						{
							Path: []string{"$.issuer"},
							Filter: &pe.Filter{
								Type: "string",
							},
						},
					},
				},
			},
		},
	},
	PresentationMaxValidity: int((24 * time.Hour).Seconds()),
}

var TestDefinitions = map[string]Definition{
	TestDefinition.ID: TestDefinition,
}
