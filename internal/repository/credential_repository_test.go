package repository_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/madhavv-xd/gopasszk/internal/crypto"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/models"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
)

func TestCredentialsByFidelity(t *testing.T) {
	db, err := database.Connect()
	if err != nil {
		t.Fatalf("failed to connect to the db %v", err)
	}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("error generating the salt %v", err)
	}

	password := []byte("Madhav@123") //password -> sample password
	plaintext := []byte("madhav")

	key := crypto.DeriveKey(password, salt) //key generation

	nonce, ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("error encrypting %v", err)
	}

	//combine nonce and ciphertext together
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	encodedCipherText := base64.StdEncoding.EncodeToString(combined)

	user := models.User{
		Email:    "madhav@gmail.com",
		AuthHash: "placeholder-auth-hash",
		Salt:     salt,
	}

	err = repository.CreateUser(db, &user)
	if err != nil {
		t.Fatalf("error creating user %v", err)
	}
	defer func() {
		err := repository.DeleteUser(db, &user)
		if err != nil {
			t.Errorf("failed to cleanup the test user: %v", err)
		}
	}()

	//creating the credential
	credential := models.Credential{
		UserID:             user.ID,
		SiteName:           "example.com",
		UsernameCiphertext: encodedCipherText,
	}

	err = repository.CreateCredential(db, &credential)
	if err != nil {
		t.Fatalf("error creating credential %v", err)
	}

	defer func() {
		err := repository.DeleteCredential(db, credential.ID , user.ID)
		if err != nil {
			t.Errorf("failed to cleanup the test credential %v", err)
		}
	}()

	retreived, err := repository.GetCredentialById(db, credential.ID , user.ID)
	if err != nil {
		t.Fatalf("error retreiving credential: %v", err)
	}

	if retreived.UsernameCiphertext != encodedCipherText {
		t.Fatalf("byte fidelity broken: expected %s , got %s", encodedCipherText, retreived.UsernameCiphertext)
	}

}

func TestSaltByFidelity(t *testing.T) {
	db, err := database.Connect()
	if err != nil {
		t.Fatalf("failed connecting to the db %v", err)
	}
	testSalt := []byte{
		0x00, 0x8B, 0x3F, 0xFF,
		0x21, 0x80, 0xC4, 0x0A,
		0x5D, 0xE7, 0x12, 0x9A,
		0x00, 0x6C, 0xF3, 0x47,
	}

	user := models.User{
		Email:    "mega@gmail.com",
		AuthHash: "sample-auth-hash",
		Salt:     testSalt,
	}

	err = repository.CreateUser(db, &user)
	if err != nil {
		t.Fatalf("error creating user %v", err)
	}
	defer func() {
		err := repository.DeleteUser(db, &user)
		if err != nil {
			t.Errorf("failed to cleanup the test user: %v", err)
		}
	}() //defered and deleted user

	got, err := repository.GetUserByEmail(db, user.Email)
	if err != nil {
		t.Fatalf("error getting the user %v", err)
	}

	if len(got.Salt) != 16 {
		t.Errorf("salt lenght: expected 16 , got %d", len(got.Salt))
	}

	if !bytes.Equal(got.Salt, testSalt) {
		t.Errorf("salt bytes changed: expected %x, got %x", testSalt, got.Salt)
	}
}

func TestCrossUserCredentialAccess(t *testing.T) {
	db, err := database.Connect()
	if err != nil {
		t.Fatalf("failed connecting to the db %v", err)
	} // however your Phase 3 tests get their DB connection

	// Two users. Emails must be unique across test runs; see note below.
	alice := models.User{Email: "alice@test.com", AuthHash: "test-hash", Salt: []byte("0123456789abcdef")}
	bob := models.User{Email: "bob@test.com", AuthHash: "test-hash", Salt: []byte("fedcba9876543210")}
	if err := repository.CreateUser(db, &alice); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	defer func() {
	if err := repository.DeleteUser(db, &alice); err != nil {
		t.Errorf("cleanup alice: %v", err)
	}
}()
	if err := repository.CreateUser(db, &bob); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	defer func() {
	if err := repository.DeleteUser(db, &bob); err != nil {
		t.Errorf("cleanup bob: %v", err)
	}
}()
	
	// Alice's credential, with known values to compare against later.
	cred := models.Credential{
		UserID:             alice.ID,
		SiteName:           "github.com",
		UsernameCiphertext: "original-username-ct",
		PasswordCiphertext: "original-password-ct",
	}
	if err := repository.CreateCredential(db, &cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	defer func() {
	if err := repository.DeleteCredential(db, cred.ID, alice.ID); err != nil {
		t.Errorf("cleanup credential: %v", err)
	}
}()
	// Bob tries to overwrite Alice's credential.
		hijack := models.Credential{SiteName: "hacked", UsernameCiphertext: "evil", PasswordCiphertext: "evil"}
	err = repository.UpdateCredentialForUser(db, cred.ID, bob.ID, hijack)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("bob's update: expected not found, got %v", err)
	}

	// Bob tries to delete it.
	err = repository.DeleteCredential(db, cred.ID, bob.ID)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("bob's delete: expected not found, got %v", err)
	}

	// Alice's row must be untouched.
	got, err := repository.GetCredentialById(db, cred.ID, alice.ID)
	if err != nil {
		t.Fatalf("alice read back: %v", err)
	}
	if got.SiteName != "github.com" || got.UsernameCiphertext != "original-username-ct" || got.PasswordCiphertext != "original-password-ct" {
		t.Fatalf("alice's credential was modified: %+v", got)
	}
}