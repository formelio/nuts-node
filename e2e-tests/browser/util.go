//go:build e2e_tests

package browser

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/e2e-tests/browser/rfc019_selfsigned/apps"
	vcrAPI "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
)

func IssueOrganizationCredential(organization *did.Document, name, city string) error {
	vcrClient := vcrAPI.HTTPClient{ClientConfig: apps.NodeClientConfig}
	request := vcrAPI.IssueVCRequest{
		Issuer: organization.ID.String(),
		CredentialSubject: map[string]interface{}{
			"id": organization.ID.String(),
			"organization": map[string]interface{}{
				"name": name,
				"city": city,
			},
		},
	}
	switch organization.ID.Method {
	case "web":
		withStatusList2021Revocation := false
		request.WithStatusList2021Revocation = &withStatusList2021Revocation
	case "nuts":
		visibility := vcrAPI.Public
		request.Visibility = &visibility
	}
	err := request.Type.FromIssueVCRequestType1(vcrAPI.IssueVCRequestType1{"VerifiableCredential", "NutsOrganizationCredential"})
	if err != nil {
		return err
	}
	issuedCredential, err := vcrClient.IssueVC(request)
	if err != nil {
		return err
	}
	if organization.ID.Method == "web" {
		// Need to load it into tbe wallet
		return vcrClient.LoadVC(organization.ID, *issuedCredential)
	}
	return nil
}
