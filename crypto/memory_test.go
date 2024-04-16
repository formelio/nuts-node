package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMemoryKeyStore_Decrypt(t *testing.T) {
	_, err := MemoryKeyStore{}.Decrypt(context.Background(), "", nil)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_DecryptJWE(t *testing.T) {
	_, _, err := MemoryKeyStore{}.DecryptJWE(context.Background(), "")
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_Delete(t *testing.T) {
	err := MemoryKeyStore{}.Delete(context.Background(), "")
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_EncryptJWE(t *testing.T) {
	_, err := MemoryKeyStore{}.EncryptJWE(context.Background(), nil, nil, nil)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_New(t *testing.T) {
	_, err := MemoryKeyStore{}.New(context.Background(), nil)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_Exists(t *testing.T) {
	t.Run("does not exist", func(t *testing.T) {
		assert.False(t, MemoryKeyStore{}.Exists(context.Background(), ""))
	})
	t.Run("exists", func(t *testing.T) {
		pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, _ := jwk.FromRaw(pk)
		key.Set(jwk.KeyIDKey, "123")
		assert.True(t, MemoryKeyStore{
			Key: key,
		}.Exists(context.Background(), "123"))
	})
}

func TestMemoryKeyStore_List(t *testing.T) {
	assert.Equal(t, []string{}, MemoryKeyStore{}.List(context.Background()))
}

func TestMemoryKeyStore_Resolve(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		_, err := MemoryKeyStore{}.Resolve(context.Background(), "123")
		assert.ErrorIs(t, err, ErrPrivateKeyNotFound)
	})
	t.Run("found", func(t *testing.T) {
		pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, _ := jwk.FromRaw(pk)
		key.Set(jwk.KeyIDKey, "123")
		k, err := MemoryKeyStore{
			Key: key,
		}.Resolve(context.Background(), "123")
		assert.NoError(t, err)
		assert.Equal(t, "123", k.KID())
	})
}

func TestMemoryKeyStore_SignJWS(t *testing.T) {
	_, err := MemoryKeyStore{}.SignJWS(context.Background(), nil, nil, nil, false)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_SignJWT(t *testing.T) {

}