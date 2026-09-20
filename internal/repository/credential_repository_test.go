package repository_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/madhavv-xd/gopasszk/internal/crypto"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/models"
	"github.com/madhavv-xd/gopasszk/internal/repository"
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
		Salt: salt,
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
		err := repository.DeleteCredential(db, &credential)
		if err != nil {
			t.Errorf("failed to cleanup the test credential %v", err)
		}
	}()

	retreived, err := repository.GetCredentialById(db, credential.ID)
	if err != nil {
		t.Fatalf("error retreiving credential: %v", err)
	}

	if retreived.UsernameCiphertext != encodedCipherText {
		t.Fatalf("byte fidelity broken: expected %s , got %s", encodedCipherText, retreived.UsernameCiphertext)
	}

}

func TestSaltByFidelity(t *testing.T) {
	db , err := database.Connect()
	if err != nil {
		t.Fatalf("failed connecting to the db %v",err)
	}
	testSalt := []byte{
    0x00, 0x8B, 0x3F, 0xFF,
    0x21, 0x80, 0xC4, 0x0A,
    0x5D, 0xE7, 0x12, 0x9A,
    0x00, 0x6C, 0xF3, 0x47,
	}

	user := models.User {
		Email: "mega@gmail.com",
		AuthHash: "sample-auth-hash",
		Salt: testSalt,
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

	got , err := repository.GetUserByEmail(db , user.Email)
	if err != nil {
		t.Fatalf("error getting the user %v" , err)
	}

	if len(got.Salt) == 16 && (bytes.Equal(got.Salt , testSalt)) {
		
	}

	if len(got.Salt) != 16 {
		t.Errorf("salt lenght: expected 16 , got %d" , len(got.Salt))
	}

	if	!bytes.Equal(got.Salt , testSalt) {
		t.Errorf("salt bytes changed: expected %x, got %x" , testSalt , got.Salt)
	}
}