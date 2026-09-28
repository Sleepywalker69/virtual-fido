package identities

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/webauthn"

	"golang.org/x/crypto/scrypt"
)

type SavedCredentialSource struct {
	Type             string                                  `json:"type"`
	ID               []byte                                  `json:"id"`
	PrivateKey       []byte                                  `json:"private_key"`
	RelyingParty     webauthn.PublicKeyCredentialRPEntity    `json:"relying_party"`
	User             webauthn.PublicKeyCrendentialUserEntity `json:"user"`
	SignatureCounter int32                                   `json:"signature_counter"`
	CredRandom       []byte                                  `json:"cred_random,omitempty"`
	// NotDiscoverable is stored inverted so credentials saved before the flag
	// existed keep their old (discoverable) behaviour.
	NotDiscoverable bool `json:"not_discoverable,omitempty"`
}

type FIDODeviceConfig struct {
	EncryptionKey          []byte                  `json:"encryption_key"`
	AttestationCertificate []byte                  `json:"attestation_certificate"`
	AttestationPrivateKey  []byte                  `json:"attestation_private_key"`
	AuthenticationCounter  uint32                  `json:"authentication_counter"`
	PINEnabled             bool                    `json:"pin_enabled,omitempty"`
	PINHash                []byte                  `json:"pin_hash,omitempty"`
	PINRetries             *int32                  `json:"pin_retries,omitempty"`
	FingerprintEnabled     bool                    `json:"fingerprint_enabled,omitempty"`
	Sources                []SavedCredentialSource `json:"sources"`
}

type PassphraseEncryptedBlob struct {
	Salt          []byte `json:"salt"`
	EncryptionKey []byte `json:"encryption_key"`
	KeyNonce      []byte `json:"key_nonce"`
	EncryptedData []byte `json:"encrypted_data"`
	DataNonce     []byte `json:"data_nonce"`
}

const scryptN, scryptR, scryptP, scryptKeyLen = 32768, 8, 1, 32

// kekCache memoizes the scrypt-derived key-encryption-key for the active
// passphrase within this process. Repeated vault saves (e.g. a signature-counter
// bump on every assertion) would otherwise each re-run scrypt (~50-150ms); with
// the cache they reuse the same salt+KEK and only re-encrypt with a fresh random
// data key and nonces.
var kekCache struct {
	mu         sync.Mutex
	passphrase string
	salt       []byte
	kek        []byte
}

func cachedKEK(passphrase string) (kek, salt []byte, err error) {
	kekCache.mu.Lock()
	defer kekCache.mu.Unlock()
	if kekCache.kek != nil && kekCache.passphrase == passphrase {
		return kekCache.kek, kekCache.salt, nil
	}
	salt = crypto.RandomBytes(16)
	kek, err = scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, nil, err
	}
	kekCache.passphrase, kekCache.salt, kekCache.kek = passphrase, salt, kek
	return kek, salt, nil
}

func EncryptWithPassphrase(passphrase string, data []byte) ([]byte, error) {
	keyEncryptionKey, salt, err := cachedKEK(passphrase)
	if err != nil {
		return nil, fmt.Errorf("Could not create key encryption key: %w", err)
	}
	encryptionKey := crypto.GenerateSymmetricKey()
	encryptedKey, keyNonce, err := crypto.Encrypt(keyEncryptionKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt key: %w", err)
	}
	encryptedData, dataNonce, err := crypto.Encrypt(encryptionKey, data)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt data: %w", err)
	}
	blob := PassphraseEncryptedBlob{
		Salt:          salt,
		EncryptionKey: encryptedKey,
		KeyNonce:      keyNonce,
		EncryptedData: encryptedData,
		DataNonce:     dataNonce,
	}
	blobBytes, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal JSON: %w", err)
	}
	return blobBytes, nil
}

func DecryptWithPassphrase(passphrase string, data []byte) ([]byte, error) {
	blob := PassphraseEncryptedBlob{}
	err := json.Unmarshal(data, &blob)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal JSON into encrypted data: %w", err)
	}
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), blob.Salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("Could not create key encryption key: %w", err)
	}
	encryptionKey, err := crypto.Decrypt(keyEncryptionKey, blob.EncryptionKey, blob.KeyNonce)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt encryption key (wrong passphrase?): %w", err)
	}
	// Warm the cache so subsequent saves reuse this KEK/salt without re-deriving
	// (only once the passphrase is known to be right).
	kekCache.mu.Lock()
	kekCache.passphrase, kekCache.salt, kekCache.kek = passphrase, blob.Salt, keyEncryptionKey
	kekCache.mu.Unlock()
	decryptedData, err := crypto.Decrypt(encryptionKey, blob.EncryptedData, blob.DataNonce)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	return decryptedData, nil
}

func EncryptFIDOState(savedState FIDODeviceConfig, passphrase string) ([]byte, error) {
	stateBytes, err := json.Marshal(savedState)
	if err != nil {
		return nil, fmt.Errorf("Could not encode JSON: %w", err)
	}
	blob, err := EncryptWithPassphrase(passphrase, stateBytes)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt data: %w", err)
	}
	return blob, nil
}

func DecryptFIDOState(data []byte, passphrase string) (*FIDODeviceConfig, error) {
	stateBytes, err := DecryptWithPassphrase(passphrase, data)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	state := FIDODeviceConfig{}
	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		return nil, fmt.Errorf("Could not decode JSON: %w", err)
	}
	return &state, nil
}
