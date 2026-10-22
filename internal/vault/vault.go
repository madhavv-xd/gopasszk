package vault

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/crypto"
)

const nonceSize = 12

var (
	// ErrWrongPassword is returned by Unlock when the server rejects the auth hash.
	ErrWrongPassword = errors.New("wrong master password")
	// ErrBadPhrase and ErrWrongRecovery are returned by Recover.
	ErrBadPhrase     = errors.New("invalid recovery phrase (check the words and spelling)")
	ErrWrongRecovery = errors.New("wrong email or recovery phrase")
)

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
			return nil, nil, ErrWrongPassword
		}
		return nil, nil, err
	}
	c.Token = token

	pwKey := crypto.DeriveEncryptionKey(pw, salt)
	defer clear(pwKey)
	key, err := crypto.UnwrapKey(pwKey, wrappedVK)
	if err != nil {
		return nil, nil, errors.New("could not unlock vault")
	}
	return c, key, nil
}

// Register creates an account and returns its recovery phrase, which the
// caller shows to the user once and never stores.
func Register(serverURL, email string, pw []byte) (string, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return "", err
	}
	pwKey := crypto.DeriveEncryptionKey(pw, salt)
	defer clear(pwKey)
	vaultKey, err := crypto.GenerateVaultKey()
	if err != nil {
		return "", err
	}
	defer clear(vaultKey)
	wrappedVK, err := crypto.WrapKey(pwKey, vaultKey)
	if err != nil {
		return "", err
	}

	phrase, err := crypto.NewRecoveryPhrase()
	if err != nil {
		return "", err
	}
	recWrapKey, recAuth, err := crypto.DeriveRecoveryKeys(phrase)
	if err != nil {
		return "", err
	}
	defer clear(recWrapKey)
	recWrapped, err := crypto.WrapKey(recWrapKey, vaultKey)
	if err != nil {
		return "", err
	}

	c := client.New(serverURL)
	if err := c.Register(email, salt, crypto.DeriveAuthHash(pw, salt), wrappedVK, recWrapped, recAuth); err != nil {
		return "", err
	}
	return phrase, nil
}

// ChangePassword verifies oldPw, then rewraps the same vault key under newPw.
// Saved credentials are not re-encrypted. It returns a client holding a fresh token.
func ChangePassword(serverURL, email string, oldPw, newPw []byte) (*client.Client, error) {
	c := client.New(serverURL)
	salt, err := c.GetSalt(email)
	if err != nil {
		return nil, err
	}
	oldAuth := crypto.DeriveAuthHash(oldPw, salt)
	token, wrappedVK, err := c.Login(email, oldAuth)
	if err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return nil, ErrWrongPassword
		}
		return nil, err
	}
	c.Token = token

	oldKey := crypto.DeriveEncryptionKey(oldPw, salt)
	defer clear(oldKey)
	vaultKey, err := crypto.UnwrapKey(oldKey, wrappedVK)
	if err != nil {
		return nil, errors.New("could not unlock vault")
	}
	defer clear(vaultKey)

	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, err
	}
	newKey := crypto.DeriveEncryptionKey(newPw, newSalt)
	defer clear(newKey)
	newWrapped, err := crypto.WrapKey(newKey, vaultKey)
	if err != nil {
		return nil, err
	}
	return c, c.ChangePassword(oldAuth, newSalt, crypto.DeriveAuthHash(newPw, newSalt), newWrapped)
}

// Recover proves knowledge of the recovery phrase, then rewraps the same
// vault key under newPw, so existing credentials stay readable.
func Recover(serverURL, email, phrase string, newPw []byte) error {
	recWrapKey, recAuth, err := crypto.DeriveRecoveryKeys(phrase)
	if err != nil {
		return ErrBadPhrase
	}
	defer clear(recWrapKey)

	c := client.New(serverURL)
	recWrapped, err := c.RecoverKey(email, recAuth)
	if err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return ErrWrongRecovery
		}
		return err
	}
	vaultKey, err := crypto.UnwrapKey(recWrapKey, recWrapped)
	if err != nil {
		return errors.New("could not unlock vault with this phrase")
	}
	defer clear(vaultKey)

	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	newKey := crypto.DeriveEncryptionKey(newPw, newSalt)
	defer clear(newKey)
	newWrapped, err := crypto.WrapKey(newKey, vaultKey)
	if err != nil {
		return err
	}
	return c.RecoverReset(email, recAuth, newSalt, crypto.DeriveAuthHash(newPw, newSalt), newWrapped)
}
