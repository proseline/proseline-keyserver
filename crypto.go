package main

import (
	"bytes"
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"io"
	"math/rand"
)

// ClientCalculations stores the cryptographic calculations of a client.
type ClientCalculations struct {
	PasswordProof []byte
	UnwrapKey     []byte
}

// CalculateClient calculates password proof and encryption unwrap key for a client.
func CalculateClient(email, password string) ClientCalculations {
	clientStretched := clientStretch(email, password)
	return ClientCalculations{
		PasswordProof: deriveKey(clientStretched, "passwordProof"),
		UnwrapKey:     deriveKey(clientStretched, "clientUnwrap"),
	}
}

func clientStretch(email, password string) []byte {
	var saltBuffer bytes.Buffer
	saltBuffer.WriteString("clientStretched")
	saltBuffer.WriteString(email)
	return pbkdf2.Key([]byte(password), saltBuffer.Bytes(), 1000, 32, sha256.New)
}

func deriveKey(input []byte, info string) []byte {
	hkdf := hkdf.New(sha256.New, input, []byte{}, []byte(info))
	output := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, output); err != nil {
		panic(err)
	}
	return output
}

// VerificationHash calculates and a hash for verying password proofs.
func VerificationHash(email string, proof, salt []byte) []byte {
	serverStretched := serverStretch(proof, salt)
	return deriveKey(serverStretched, "verificationHash")
}

// VerifyProof checks a password proof against a stored verification hash.
func VerifyProof(email string, proof, salt, storedVerificationHash []byte) bool {
	computedVerificationHash := VerificationHash(email, proof, salt)
	return bytes.Equal(computedVerificationHash, storedVerificationHash)
}

func randomBytes(length int) []byte {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

func serverStretch(proof, salt []byte) []byte {
	key, err := scrypt.Key(proof, salt, 64*1024, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return key
}

// UnwrapKey unwraps a wrapped key.
func UnwrapKey(wrapped, unwrap []byte) []byte {
	result := make([]byte, len(wrapped))
	for i := range wrapped {
		result[i] = wrapped[i] ^ unwrap[i]
	}
	return result
}
