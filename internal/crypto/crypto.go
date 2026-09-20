package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)

const authLabel = "auth"
const encLabel = "enc"

func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func helperSalt(salt []byte, label string) []byte {
	out := append([]byte{}, salt...)
	out = append(out, label...)
	return out
}

func DeriveAuthHash(password []byte, salt []byte) []byte {
	//first call helper and build
	strg := helperSalt(salt, authLabel)
	//now build the argon2id key
	authKey := DeriveKey(password, strg)

	return authKey
}

func DeriveEncryptionKey(password []byte, salt []byte) []byte {
	//first call helper and build
	strg := helperSalt(salt, encLabel)
	//now build the argon2id key
	encKey := DeriveKey(password, strg)

	return encKey
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func Encrypt(key []byte, plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	} //block has been made , now wrap it inside the gcm

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	} //gcm has been made , now make it to the encryption part

	//generate a nonce -> nonce is unique and necessary for encryption and decyption
	//nonce will also be a byte
	nonce = make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}
	//now the encryption step
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

//now the decrypt function -> for decrypting
func Decrypt(key []byte, nonce []byte, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	} //get a block , then make a new gcm and then open it

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	} //gcm has been made now -> open the gcm

	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
