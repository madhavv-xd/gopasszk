package crypto

import (
	"testing"
	"crypto/cipher"
	"crypto/aes"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	salt , err := GenerateSalt()
	if err != nil {
		t.Fatalf("generationSalt failed: %v" , err)
	}

	password := []byte("test-password-123")
	key := DeriveKey(password, salt)

	plaintext := []byte("my-git-pass")

	nonce , ciphertext , err := Encrypt(key , plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v" , err)
	}
	decrypted, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
	t.Fatalf("round trip mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}
//now the sharednonce one
func sealWithFixedNonce(t *testing.T, key []byte, nonce []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	return gcm.Seal(nil, nonce, plaintext, nil)
}

func TestNonceReuseIsDangerous(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	password := []byte("test-password-123")
	key := DeriveKey(password, salt)

	plaintext1 := []byte("AAAAAAAAAAAAAAAA")
	plaintext2 := []byte("BBBBBBBBBBBBBBBB")

	fixedNonce := make([]byte, 12)

	ciphertext1 := sealWithFixedNonce(t, key, fixedNonce, plaintext1)
	ciphertext2 := sealWithFixedNonce(t, key, fixedNonce, plaintext2)

	// XOR comparison goes here — next step
	xorCiphertexts := xorBytes(ciphertext1[:len(plaintext1)], ciphertext2[:len(plaintext2)])
	xorPlaintexts := xorBytes(plaintext1, plaintext2)

	if string(xorCiphertexts) != string(xorPlaintexts) {
		t.Fatalf("expected XOR of ciphertexts to equal XOR of plaintexts — attack demonstration failed")
	}
}

func xorBytes(a []byte, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}