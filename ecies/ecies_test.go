package ecies

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

const privateKeyPem = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICqetgUe4k7mYXgR/nOKV7JRYO/6ETgmQheWqyL9EIwhoAoGCCqGSM49
AwEHoUQDQgAE83buecyru7JmdZZFoUdY9jn12ht7YYHXMGhMmXjX4dd8gz/VuWdV
I2G4LStZ2hn0cfgzT8VdJCkRo+cynYpTOA==
-----END EC PRIVATE KEY-----
`
const publicKeyPem = `
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE83buecyru7JmdZZFoUdY9jn12ht7
YYHXMGhMmXjX4dd8gz/VuWdVI2G4LStZ2hn0cfgzT8VdJCkRo+cynYpTOA==
-----END EC PUBLIC KEY-----
`

func TestDecrypt(t *testing.T) {

	priv, errKeyPriv := PrivateKeyFromPemStr(privateKeyPem)
	if errKeyPriv != nil {
		t.Errorf("could not load private key from pem: %v", errKeyPriv)
	}

	pub, errKeyPub := PublicKeyFromPemStr(publicKeyPem)
	if errKeyPub != nil {
		t.Errorf("could not load private key from pem: %v", errKeyPub)
	}

	privateKey, errImpPriv := ImportECDSA(priv)
	if errImpPriv != nil {
		t.Errorf("import ecdsa private key: %v", errImpPriv)
	}

	publicKey, errImpPub := ImportECDSAPublic(pub)
	if errImpPub != nil {
		t.Errorf("import ecdsa public key: %v", errImpPub)
	}

	clearText := "abc123"

	encrypted, errEncrypt := Encrypt(rand.Reader, publicKey, []byte(clearText), nil, nil)
	if errEncrypt != nil {
		t.Errorf("encrypt: %v", errEncrypt)
	}

	decrypted, errDecrypt := Decrypt(privateKey, encrypted, nil, nil)
	if errEncrypt != nil {
		t.Errorf("decrypt: %v", errDecrypt)
	}

	decryptedStr := string(decrypted)

	if clearText != decryptedStr {
		t.Errorf("wanted=[%s] got=[%s]", clearText, decryptedStr)
	}
}

// PrivateKeyFromPemStr creates private key from PEM string.
func PrivateKeyFromPemStr(privPEM string) (*ecdsa.PrivateKey, error) {
	me := "PrivateKeyFromPemStr"

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", me, err)
	}

	return priv, nil
}

// PublicKeyFromPemStr creates public key from PEM string.
func PublicKeyFromPemStr(pubPEM string) (*ecdsa.PublicKey, error) {
	me := "PublicKeyFromPemStr"

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", me, err)
	}

	p, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA public key", me)
	}

	return p, nil
}
