package auth

import (
	"encoding/base64"

	"github.com/alexedwards/argon2id"
)

var params = &argon2id.Params{
	Memory:      19 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

func HashAuthKey(authHash []byte) (string, error) {
	encoded := encodesAuthKey(authHash)
	hash, err := argon2id.CreateHash(encoded, params)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func encodesAuthKey(authHash []byte) string {
	return base64.StdEncoding.EncodeToString(authHash)
}

func VerifyAuthKey(authHash []byte , storedHash string) (bool , error) {
	encoded := encodesAuthKey(authHash)
	decoded , err:= argon2id.ComparePasswordAndHash(encoded , storedHash)
	if err != nil {
		return false , err 
	}
	return decoded , nil 
}