package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/usecase/log"
	"github.com/nuts-foundation/nuts-node/usecase/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"io"
	"net/http"
	"net/url"
	"sync"
)

func newClient(db *gorm.DB, definitions map[string]model.Definition) *client {
	return &client{
		db:          db,
		definitions: definitions,
	}
}

type client struct {
	db          *gorm.DB
	definitions map[string]model.Definition
}

func (c *client) refreshAll() {
	wg := &sync.WaitGroup{}
	for _, definition := range c.definitions {
		wg.Add(1)
		go func(definition model.Definition) {
			c.refreshList(definition)
		}(definition)
	}
	wg.Done()
}

func (c *client) refreshList(definition model.Definition) error {
	var currentList list
	if err := c.db.Find(&currentList, "usecase_id = ?", definition.ID).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		// First refresh of the list
		if err := c.db.Create(&list{ID: definition.ID}).Error; err != nil {
			return err
		}
	} else if err != nil {
		// Other error
		return err
	}
	log.Logger().Debugf("Refreshing use case list %s", definition.ID)
	// replace with generated client later
	requestURL, _ := url.Parse(definition.Endpoint)
	requestURL.Query().Add("timestamp", fmt.Sprintf("%d", currentList.Timestamp))
	httpResponse, err := http.Get(definition.Endpoint)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}
	var response model.ListResponse
	if err = json.Unmarshal(data, &response); err != nil {
		return err
	}
	return c.applyDelta(currentList.ID, response.Entries, response.Tombstone, currentList.Timestamp, response.Timestamp)
}

func (c *client) search(usecaseID string, query map[string]string) ([]vc.VerifiablePresentation, error) {
	// these are properties that are present as columns
	var credentialWhereClauses []string
	var credentialWhereValues []string
	// these are dynamic credential subject properties
	var credentialSubjectWhereClauses []string
	var credentialSubjectWhereValues []string
	for jsonPath, value := range query {
		switch jsonPath {
		case "id":
			credentialWhereClauses = append(credentialWhereClauses, "credential.credential_id = ?")
			credentialWhereValues = append(credentialWhereValues, value)
		case "issuer":
			credentialWhereClauses = append(credentialWhereClauses, "credential.credential_issuer = ?")
			credentialWhereValues = append(credentialWhereValues, value)
		case "type":
			credentialWhereClauses = append(credentialWhereClauses, "credential.credential_type = ?")
			credentialWhereValues = append(credentialWhereValues, value)
		case "credentialSubject.id":
			credentialWhereClauses = append(credentialWhereClauses, "credential.credential_subject_id = ?")
			credentialWhereValues = append(credentialWhereValues, value)
		default:
			// this property is not present as column, but indexed as key-value property
			credentialSubjectWhereClauses = append(credentialSubjectWhereClauses, "property.key = ? AND property.value = ?")
			credentialSubjectWhereValues = append(credentialSubjectWhereValues, jsonPath, value)
		}
	}
	c.db.Model(&entry{}).
		Select("entry.presentation_raw").
		Joins("left inner join credential ON cred.entry_id = entry.id").

}

// applyDelta applies the update, retrieved from the use case list server, to the local index of the use case lists.
func (c *client) applyDelta(usecaseID string, presentations []vc.VerifiablePresentation, tombstoneSet []string, previousTimestamp uint64, timestamp uint64) error {
	// TODO: validate presentations
	if previousTimestamp == timestamp {
		// nothing to do
		return nil
	}
	// We use a transaction to make sure the complete update is applied, or nothing at all.
	// Use a lock on the list to make sure there are no concurrent updates being applied to the list,
	// which could lead to the client becoming out-of-sync with the server list.
	// This situation can only really occur in a distributed system (multiple nodes updating the same list at the same time, with a different timestamp),
	// or bug in the update scheduler.
	return c.db.Transaction(func(tx *gorm.DB) error {
		// Lock the list, check if we're applying the delta to the right starting point
		var currentList list
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("usecase_id = ?", usecaseID).
			Find(&currentList).
			Error; err != nil {
			return err
		}
		// Make sure we don't apply stale data
		if currentList.Timestamp != previousTimestamp {
			log.Logger().Infof("Not applying delta to use case list '%s': timestamp mismatch (expected %d but was %d). "+
				"Probably caused by multiple processes updating the list. This is not a problem/bug: stale data should be updated at next refresh.", usecaseID, previousTimestamp, currentList.Timestamp)
			return nil
		}
		// Now we can apply the delta:
		// - delete removed presentations
		// - add new presentations
		// - index the presentations' properties
		if len(tombstoneSet) > 0 {
			if err := tx.Delete(&entry{}, "usecase_id = ? AND presentation_id IN ?", usecaseID, tombstoneSet).Error; err != nil {
				return fmt.Errorf("failed to delete tombstone records: %w", err)
			}
		}
		for _, presentation := range presentations {
			entryID := uuid.NewString()
			// Store list entry / verifiable presentation
			if err := tx.Create(&entry{
				ID:                     entryID,
				UsecaseID:              usecaseID,
				PresentationID:         presentation.ID.String(),
				PresentationRaw:        presentation.Raw(),
				PresentationExpiration: presentation.JWT().Expiration().Unix(),
			}).Error; err != nil {
				return fmt.Errorf("failed to create entry: %w", err)
			}
			// Store the credentials of the presentation
			for _, curr := range presentation.VerifiableCredential {
				var credentialType *string
				for _, currType := range curr.Type {
					if currType.String() != "VerifiableCredential" {
						credentialType = new(string)
						*credentialType = currType.String()
						break
					}
				}
				subjectDID, err := curr.SubjectDID()
				if err != nil {
					return fmt.Errorf("invalid credential subject ID for VP '%s': %w", presentation.ID, err)
				}
				credentialRecordID := uuid.NewString()
				if err := tx.Create(&credential{
					ID:                  credentialRecordID,
					EntryID:             entryID,
					CredentialID:        curr.ID.String(),
					CredentialIssuer:    curr.Issuer.String(),
					CredentialSubjectID: subjectDID.String(),
					CredentialType:      credentialType,
				}).Error; err != nil {
					return fmt.Errorf("failed to create credential: %w", err)
				}
				if len(curr.CredentialSubject) != 1 {
					return errors.New("credential must contain exactly one subject")
				}
				// Store credential properties
				var keys []string
				var values []string
				indexJSONObject(curr.CredentialSubject[0].(map[string]interface{}), keys, values, "credentialSubject")
				for i, key := range keys {
					if err := tx.Create(&property{
						ID:    credentialRecordID,
						Key:   key,
						Value: values[i],
					}).Error; err != nil {
						return fmt.Errorf("failed to create property '%s' for credential '%s' in VP '%s': %w", key, curr.ID, presentation.ID, err)
					}
				}
			}
			// Finally, update the list timestamp
			if err := tx.Model(&list{}).Where("usecase_id = ?", usecaseID).Update("timestamp", timestamp).Error; err != nil {
				return fmt.Errorf("failed to update timestamp: %w", err)
			}
		}
		return nil
	})
}

// indexJSONObject indexes a JSON object, resulting in a slice of JSON paths and corresponding string values.
// It only traverses JSON objects and only adds string values to the result.
func indexJSONObject(target map[string]interface{}, jsonPaths []string, stringValues []string, currentPath string) {
	for key, value := range target {
		thisPath := currentPath
		if len(thisPath) > 0 {
			thisPath += "."
		}
		thisPath += key

		switch typedValue := value.(type) {
		case string:
			jsonPaths = append(jsonPaths, thisPath)
			stringValues = append(stringValues, typedValue)
		case map[string]interface{}:
			indexJSONObject(typedValue, jsonPaths, stringValues, thisPath)
		default:
			// other values (arrays, booleans, numbers, null) are not indexed
		}
	}
}
