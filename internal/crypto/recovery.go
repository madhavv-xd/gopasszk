package crypto

import (
	"crypto/sha256"
	"io"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
)

// NewRecoveryPhrase returns 24 random words (256 bits of entropy).
func NewRecoveryPhrase() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// DeriveRecoveryKeys turns a phrase into two separate values:
// a key that wraps the vault key, and a hash that proves you have the phrase.
func DeriveRecoveryKeys(phrase string) (wrapKey, authHash []byte, err error) {
	normalized := strings.Join(strings.Fields(strings.ToLower(phrase)), " ")
	entropy, err := bip39.EntropyFromMnemonic(normalized)
	if err != nil {
		return nil, nil, err // typo, wrong word, or bad checksum
	}

	wrapKey, err = hkdfExpand(entropy, "gopass-recovery-wrap")
	if err != nil {
		return nil, nil, err
	}
	authHash, err = hkdfExpand(entropy, "gopass-recovery-auth")
	if err != nil {
		return nil, nil, err
	}
	return wrapKey, authHash, nil
}

func hkdfExpand(secret []byte, label string) ([]byte, error) {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, secret, nil, []byte(label))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}