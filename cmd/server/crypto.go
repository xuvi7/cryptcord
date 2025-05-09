package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// takes base64 encoded public key and data
func encrypt(key string, data string) (string, error) {
	block, _ := pem.Decode([]byte(key))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pubkey := pub.(*rsa.PublicKey)

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	encryptedBytes, err := rsa.EncryptOAEP(nil, rand.Reader, pubkey, decoded, nil)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(encryptedBytes)
	return encoded, nil
}

func encode(data []byte) (string) {
	return base64.StdEncoding.EncodeToString(data)
}