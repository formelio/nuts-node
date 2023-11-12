package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/usecase/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_client_applyDelta(t *testing.T) {
	//storageEngine := storage.New()
	//storageEngine.(core.Injectable).Config().(*storage.Config).SQL = storage.SQLConfig{ConnectionString: "file:../../data/sqlite.db"}
	//require.NoError(t, storageEngine.Configure(core.TestServerConfig(core.ServerConfig{Datadir: "data"})))
	//require.NoError(t, storageEngine.Start())

	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	t.Run("fresh list, assert all persisted fields", func(t *testing.T) {
		c := setupClient(t, storageEngine)
		err := c.applyDelta(model.TestDefinition.ID, []vc.VerifiablePresentation{vpAlice, vpBob}, []string{"other", "and another"}, 0, 1000)
		require.NoError(t, err)

		var actualList list
		require.NoError(t, c.db.Find(&actualList, "usecase_id = ?", model.TestDefinition.ID).Error)
		require.Equal(t, model.TestDefinition.ID, actualList.UsecaseID)
		require.Equal(t, uint64(1000), actualList.Timestamp)

		var entries []entry
		require.NoError(t, c.db.Find(&entries, "usecase_id = ?", model.TestDefinition.ID).Error)
		require.Len(t, entries, 2)
		require.Equal(t, vpAlice.ID.String(), entries[0].PresentationID)
		require.Equal(t, vpBob.ID.String(), entries[1].PresentationID)
	})
}

func Test_client_writePresentation(t *testing.T) {
	type propertyTest struct {
		credentialID  string
		expectedKey   string
		expectedValue string
	}

	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	t.Run("1 credential", func(t *testing.T) {
		c := setupClient(t, storageEngine)
		err := c.writePresentation(c.db, model.TestDefinition.ID, vpAlice)
		require.NoError(t, err)

		var entries []entry
		require.NoError(t, c.db.Find(&entries, "usecase_id = ?", model.TestDefinition.ID).Error)
		require.Len(t, entries, 1)
		require.Equal(t, vpAlice.ID.String(), entries[0].PresentationID)
		require.Equal(t, vpAlice.Raw(), entries[0].PresentationRaw)
		require.Equal(t, vpAlice.JWT().Expiration().Unix(), entries[0].PresentationExpiration)

		var credentials []credential
		require.NoError(t, c.db.Find(&credentials, "entry_id = ?", entries[0].ID).Error)
		require.Len(t, credentials, 1)
		cred := credentials[0]
		require.Equal(t, vcAlice.ID.String(), cred.CredentialID)
		require.Equal(t, vcAlice.Issuer.String(), cred.CredentialIssuer)
		require.Equal(t, aliceDID.String(), cred.CredentialSubjectID)
		require.Equal(t, vcAlice.Type[1].String(), *cred.CredentialType)

		expectedProperties := []propertyTest{
			{
				credentialID:  cred.ID,
				expectedKey:   "person.givenName",
				expectedValue: "Alice",
			},
			{
				credentialID:  cred.ID,
				expectedKey:   "person.familyName",
				expectedValue: "Jones",
			},
			{
				credentialID:  cred.ID,
				expectedKey:   "person.city",
				expectedValue: "InfoSecLand",
			},
		}
		for _, expectedProperty := range expectedProperties {
			var properties []property
			require.NoError(t, c.db.Find(&properties, "id = ? AND key = ?", expectedProperty.credentialID, expectedProperty.expectedKey).Error)
			require.Len(t, properties, 1)
			require.Equal(t, expectedProperty.expectedValue, properties[0].Value)
		}

		var aliceProperties []property
		require.NoError(t, c.db.Find(&aliceProperties).Error)
		require.Len(t, credentials[0].Properties, 6)
		require.Equal(t, "person.givenName", credentials[0].Properties[0].Key)
		require.Equal(t, "person.givenName", credentials[0].Properties[1].Value)
		require.Equal(t, "person.familyName", credentials[0].Properties[0].Key)
		require.Equal(t, "person.familyName", credentials[0].Properties[1].Value)
		require.Equal(t, "person.city", credentials[0].Properties[0].Key)
		require.Equal(t, "person.city", credentials[0].Properties[1].Value)
	})
}

func setupClient(t *testing.T, storageEngine storage.Engine) *client {
	//t.Cleanup(func() {
	//	underlyingDB, err := storageEngine.GetSQLDatabase().DB()
	//	require.NoError(t, err)
	//	tables := []schema.Tabler{
	//		&entry{},
	//		&credential{},
	//		&list{},
	//	}
	//	for _, table := range tables {
	//		_, err = underlyingDB.Exec("DELETE FROM " + table.TableName())
	//		require.NoError(t, err)
	//	}
	//})
	testDefinitions := map[string]model.Definition{
		model.TestDefinition.ID: model.TestDefinition,
	}

	c, err := newClient(storageEngine.GetSQLDatabase(), testDefinitions)
	require.NoError(t, err)
	return c
}

var keyPairs map[string]*ecdsa.PrivateKey
var authorityDID did.DID
var aliceDID did.DID
var vcAlice vc.VerifiableCredential
var vpAlice vc.VerifiablePresentation
var bobDID did.DID
var vcBob vc.VerifiableCredential
var vpBob vc.VerifiablePresentation

func init() {
	keyPairs = make(map[string]*ecdsa.PrivateKey)
	authorityDID = did.MustParseDID("did:example:authority")
	keyPairs[authorityDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aliceDID = did.MustParseDID("did:example:alice")
	keyPairs[aliceDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobDID = did.MustParseDID("did:example:bob")
	keyPairs[bobDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	vcAlice = createCredentialWithClaims(authorityDID, aliceDID, func() []interface{} {
		return []interface{}{
			map[string]interface{}{
				"id": aliceDID.String(),
				"person": map[string]interface{}{
					"givenName":  "Alice",
					"familyName": "Jones",
					"city":       "InfoSecLand",
				},
			},
		}
	}, func(m map[string]interface{}) {
		// do nothing
	})
	vpAlice = createPresentation(aliceDID, vcAlice)
	vcBob = createCredentialWithClaims(authorityDID, bobDID, func() []interface{} {
		return []interface{}{
			map[string]interface{}{
				"id": aliceDID.String(),
				"person": map[string]interface{}{
					"givenName":  "Bob",
					"familyName": "Johansson",
					"city":       "InfoSecLand",
				},
			},
		}
	}, func(m map[string]interface{}) {
		// do nothing
	})
	vpBob = createPresentation(bobDID, vcBob)
}

func createCredential(issuerDID did.DID, subjectDID did.DID) vc.VerifiableCredential {
	return createCredentialWithClaims(issuerDID, subjectDID,
		func() []interface{} {
			return []interface{}{
				map[string]interface{}{
					"id": subjectDID.String(),
				},
			}
		},
		func(claims map[string]interface{}) {
			// do nothing
		})
}

func createCredentialWithClaims(issuerDID did.DID, subjectDID did.DID, credentialSubjectCreator func() []interface{}, claimVisitor func(map[string]interface{})) vc.VerifiableCredential {
	vcID := did.DIDURL{DID: issuerDID}
	vcID.Fragment = uuid.NewString()
	vcIDURI := vcID.URI()
	expirationDate := time.Now().Add(time.Hour * 24)

	result, err := vc.CreateJWTVerifiableCredential(context.Background(), vc.VerifiableCredential{
		ID:                &vcIDURI,
		Issuer:            issuerDID.URI(),
		Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("TestCredential")},
		IssuanceDate:      time.Now(),
		ExpirationDate:    &expirationDate,
		CredentialSubject: credentialSubjectCreator(),
	}, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		claimVisitor(claims)
		return signJWT(subjectDID, claims, headers)
	})
	if err != nil {
		panic(err)
	}
	return *result
}

func createPresentation(subjectDID did.DID, credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
	return createPresentationWithClaims(subjectDID, func(claims map[string]interface{}) {
		// do nothing
	}, credentials...)
}

func createPresentationWithClaims(subjectDID did.DID, claimVisitor func(map[string]interface{}), credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
	headers := map[string]interface{}{
		jws.TypeKey: "JWT",
	}
	claims := map[string]interface{}{
		jwt.IssuerKey:  subjectDID.String(),
		jwt.SubjectKey: subjectDID.String(),
		jwt.JwtIDKey:   subjectDID.String() + "#" + uuid.NewString(),
		"vp": vc.VerifiablePresentation{
			Type:                 append([]ssi.URI{ssi.MustParseURI("VerifiablePresentation")}),
			VerifiableCredential: credentials,
		},
		jwt.NotBeforeKey:  time.Now().Unix(),
		jwt.ExpirationKey: time.Now().Add(time.Hour * 8),
	}
	claimVisitor(claims)
	token, err := signJWT(subjectDID, claims, headers)
	if err != nil {
		panic(err)
	}
	presentation, err := vc.ParseVerifiablePresentation(token)
	if err != nil {
		panic(err)
	}
	return *presentation
}

func signJWT(subjectDID did.DID, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
	// Build JWK
	signingKey := keyPairs[subjectDID.String()]
	if signingKey == nil {
		return "", fmt.Errorf("key not found for DID: %s", subjectDID)
	}
	subjectKeyJWK, err := jwk.FromRaw(signingKey)
	if err != nil {
		return "", nil
	}
	keyID := did.DIDURL{DID: subjectDID}
	keyID.Fragment = "0"
	if err := subjectKeyJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return "", err
	}
	if err := subjectKeyJWK.Set(jwk.KeyIDKey, keyID.String()); err != nil {
		return "", err
	}

	// Build token
	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return "", err
		}
	}
	hdr := jws.NewHeaders()
	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			return "", err
		}
	}
	bytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, signingKey, jws.WithProtectedHeaders(hdr)))
	return string(bytes), err
}
