package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	util "github.com/bulwarkid/virtual-fido/util"
)

const RSA_NUMBER_OF_BITS = 4096

func GenerateSymmetricKey() []byte {
	return RandomBytes(32)
}

func GenerateECDSAKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	util.CheckErr(err, "Could not generate ecdsa private key")
	return key
}

func GenerateEd25519Key() *ed25519.PrivateKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	util.CheckErr(err, "Could not generate Ed25519 private key")
	return &privateKey
}

func GenerateRSAKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSA_NUMBER_OF_BITS)
	util.CheckErr(err, "Could not generate RSA private key")
	return privateKey
}

func EncodePublicKey(publicKey *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)
}

func DecodePublicKey(publicKeyBytes []byte) *ecdsa.PublicKey {
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return &key
}

func Encrypt(key []byte, data []byte) ([]byte, []byte, error) {
	// TODO: Handle errors more reliably than panicing
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create device cipher: %w", err)
	}
	nonce := RandomBytes(12)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create GCM mode: %w", err)
	}
	encryptedData := gcm.Seal(nil, nonce, data, nil)
	return encryptedData, nonce, nil
}

func Decrypt(key []byte, data []byte, nonce []byte) ([]byte, error) {
	// TODO: Handle errors more reliably than panicing
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Could not create device cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Could not create GCM mode: %w", err)
	}
	decryptedData, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	return decryptedData, nil
}

func SignECDSA(key *ecdsa.PrivateKey, data []byte) []byte {
	hash := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	util.CheckErr(err, "Could not sign data")
	return signature
}

func VerifyECDSA(key *ecdsa.PublicKey, data []byte, signature []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(key, hash[:], signature)
}

func SignEd25519(key *ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(*key, data)
}

func VerifyEd25519(publicKey *ed25519.PublicKey, data []byte, signature []byte) bool {
	return ed25519.Verify(*publicKey, data, signature)
}

func SignRSA(privateKey *rsa.PrivateKey, data []byte) []byte {
	digest := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], nil)
	util.CheckErr(err, "Could not sign data with RSA")
	return signature
}

func VerifyRSA(publicKey *rsa.PublicKey, data []byte, signature []byte) bool {
	digest := sha256.Sum256(data)
	err := rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], signature, nil)
	return err == nil
}

type EncryptedBox struct {
	Data []byte `cbor:"1,keyasint"`
	IV   []byte `cbor:"2,keyasint"`
}

func Seal(key []byte, data []byte) EncryptedBox {
	encryptedData, iv, err := Encrypt(key, data)
	util.CheckErr(err, "Could not seal data")
	return EncryptedBox{Data: encryptedData, IV: iv}
}

func Open(key []byte, box EncryptedBox) []byte {
	data, err := Decrypt(key, box.Data, box.IV)
	util.CheckErr(err, "Could not open data")
	return data
}

func HashSHA256(bytes []byte) []byte {
	hash := sha256.New()
	_, err := hash.Write(bytes)
	util.CheckErr(err, "Could not hash bytes")
	return hash.Sum(nil)
}

func EncryptAESCBC(key []byte, data []byte) []byte {
	aesCipher, err := aes.NewCipher(key)
	util.CheckErr(err, "Could not create AES cipher")
	iv := make([]byte, aesCipher.BlockSize())
	cbc := cipher.NewCBCEncrypter(aesCipher, iv)
	encryptedData := make([]byte, len(data))
	cbc.CryptBlocks(encryptedData, data)
	return encryptedData
}

func DecryptAESCBC(key []byte, data []byte) []byte {
	aesCipher, err := aes.NewCipher(key)
	util.CheckErr(err, "Could not create AES cipher")
	// CBC requires the input to be a non-zero multiple of the block size;
	// cipher.CryptBlocks panics otherwise. Callers may pass attacker-controlled
	// ciphertext (CTAP ClientPIN / hmac-secret), so reject bad lengths instead of
	// crashing the process — return nil and let the caller surface a CTAP error.
	if len(data) == 0 || len(data)%aesCipher.BlockSize() != 0 {
		return nil
	}
	iv := make([]byte, aesCipher.BlockSize())
	cbc := cipher.NewCBCDecrypter(aesCipher, iv)
	decryptedData := make([]byte, len(data))
	cbc.CryptBlocks(decryptedData, data)
	return decryptedData
}

/* Note: This should be replaced once crypto/ecdh gets released (Go 1.20?) */
type ECDHKey struct {
	Priv []byte
	X, Y *big.Int
}

func GenerateECDHKey() *ECDHKey {
	priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	util.CheckErr(err, "Could not generate ECDH key")
	return &ECDHKey{Priv: priv, X: x, Y: y}
}

// ECDH returns the shared x-coordinate with the peer's point, or nil if the
// point is not on P-256.
func (key *ECDHKey) ECDH(remoteX, remoteY *big.Int) []byte {
	if remoteX == nil || remoteY == nil || remoteX.Sign() < 0 || remoteY.Sign() < 0 {
		return nil
	}
	secret, err := key.SharedSecret(remoteX.Bytes(), remoteY.Bytes())
	if err != nil {
		return nil
	}
	return secret
}

// SharedSecret performs P-256 ECDH with the peer's big-endian coordinates and
// returns the 32-byte shared x-coordinate. Points that are not on the curve
// (or the point at infinity) are rejected: the peer controls them, and
// elliptic's ScalarMult panics on invalid points.
func (key *ECDHKey) SharedSecret(remoteX, remoteY []byte) ([]byte, error) {
	if len(remoteX) == 0 || len(remoteY) == 0 || len(remoteX) > 32 || len(remoteY) > 32 {
		return nil, errors.New("invalid ECDH public key coordinates")
	}
	point := make([]byte, 65)
	point[0] = 4 // uncompressed
	copy(point[1+32-len(remoteX):33], remoteX)
	copy(point[33+32-len(remoteY):], remoteY)
	peer, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDH public key: %w", err)
	}
	privateBytes := make([]byte, 32)
	if len(key.Priv) > 32 {
		return nil, errors.New("invalid ECDH private key")
	}
	copy(privateBytes[32-len(key.Priv):], key.Priv)
	private, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	return private.ECDH(peer)
}

func (key *ECDHKey) PublicKeyBytes() []byte {
	return elliptic.Marshal(elliptic.P256(), key.X, key.Y)
}

func RandomBytes(length int) []byte {
	randBytes := make([]byte, length)
	_, err := rand.Read(randBytes)
	util.CheckErr(err, "Could not generate random bytes")
	return randBytes
}
