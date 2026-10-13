package vault

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/crypto"
)

const nonceSize = 12

func EncryptField(key []byte, plaintext string) (string, error) {
	nonce, ct, err := crypto.Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	combined := make([]byte, 0, len(nonce)+len(ct))
	combined = append(combined, nonce...)
	combined = append(combined, ct...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func DecryptField(key []byte, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	pt, err := crypto.Decrypt(key, data[:nonceSize], data[nonceSize:])
	if err != nil {
		return "", errors.New("decryption failed")
	}
	return string(pt), nil
}

// findcredential -> fetches user's creds , finds one with this id ,
// returns its site , deccrypted username and decypted password
// findCredential fetches the user's credentials, finds the one with this ID,
// and returns its site, decrypted username, and decrypted password.
func FindCredential(c *client.Client, key []byte, id string) (string, string, string, error) {
	creds, err := c.ListCredentials()
	if err != nil {
		return "", "", "", err
	}
	for _, cr := range creds {
		if cr.ID == id {
			user, err := DecryptField(key, cr.UsernameCiphertext)
			if err != nil {
				return "", "", "", err
			}
			pass, err := DecryptField(key, cr.PasswordCiphertext)
			if err != nil {
				return "", "", "", err
			}
			return cr.SiteName, user, pass, nil
		}
	}
	return "", "", "", errors.New("no credential with id " + id)
}

func Unlock(serverURL, email string, pw []byte) (*client.Client, []byte, error) {
	c := client.New(serverURL)
	salt, err := c.GetSalt(email)
	if err != nil {
		return nil, nil, err
	}

	token, wrappedVK, err := c.Login(email, crypto.DeriveAuthHash(pw, salt))
	if err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return nil, nil, errors.New("wrong master password")
		}
		return nil, nil, err
	}
	c.Token = token

	pwKey := crypto.DeriveEncryptionKey(pw, salt)
	key, err := crypto.UnwrapKey(pwKey, wrappedVK)
	if err != nil {
		return nil, nil, errors.New("could not unlock vault")
	}
	return c, key, nil
}
