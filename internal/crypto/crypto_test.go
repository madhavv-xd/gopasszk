package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("generationSalt failed: %v", err)
	}

	password := []byte("test-password-123")
	key := DeriveKey(password, salt)

	plaintext := []byte("my-git-pass")

	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	decrypted, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

// now the sharednonce one
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

func TestAuthAndEncKeyDiffer(t *testing.T) {
	//pass the password and salt to both the funcs and assert that both the hashes i get are different
	password := []byte("hunter2")
	salt := []byte("0123456789abcdef")

	//the initial authHash
	first := DeriveAuthHash(password, salt)
	//2nd -> encryption hash
	second := DeriveEncryptionKey(password, salt)

	//if they;re equal , then equal else , false
	if bytes.Equal(first, second) {
		t.Errorf("auth and enc key must differ ")
	}
}

// test determinism
func TestDeterForAuth(t *testing.T) {
	password := []byte("hunter2")
	salt := []byte("0123456789abcdef")

	first := DeriveAuthHash(password, salt)
	second := DeriveAuthHash(password, salt)

	if !bytes.Equal(first, second) {
		t.Errorf("DeriveAuthHash returned different output for identical inputs")
	}
}

func TestDeterForEnc(t *testing.T) {
	password := []byte("hunter2")
	salt := []byte("0123456789abcdef")

	first := DeriveEncryptionKey(password, salt)
	second := DeriveEncryptionKey(password, salt)

	if !bytes.Equal(first, second) {
		t.Errorf("DeriveEncryptionKey returned different output for identical inputs")
	}
}

func TestHelperDoesNotCorruptSalt(t *testing.T) {
	salt := make([]byte, 16, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	authInput := helperSalt(salt, authLabel)
	encInput := helperSalt(salt, encLabel)

	if !bytes.Equal(authInput[16:], []byte(authLabel)) {
		t.Errorf("auth input tail corrupted, got %q", authInput[16:])
	}
	if !bytes.Equal(encInput[16:], []byte(encLabel)) {
		t.Errorf("enc input tail corrupted, got %q", encInput[16:])
	}
}
