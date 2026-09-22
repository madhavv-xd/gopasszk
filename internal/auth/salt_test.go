package auth

import (
	"bytes"
	"testing"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/models"
	"github.com/madhavv-xd/gopasszk/internal/repository"
) 

func TestGetSaltForEmail(t *testing.T) {
	db, err := database.Connect()
	if err != nil {
		t.Fatalf("db connection error %v" , err )
	}
	secret := []byte("test-secret-for-me") //secret for the hmac function 

	testSalt := []byte{
		0x00, 0x8B, 0x3F, 0xFF,
		0x21, 0x80, 0xC4, 0x0A,
		0x5D, 0xE7, 0x12, 0x9A,
		0x00, 0x6C, 0xF3, 0x47,
	}

	user := models.User{
		Email:    "megaxx@gmail.com",
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

	got , err := GetSaltForEmail(db, user.Email , secret)
	if err != nil {
		t.Fatalf("error getting the user %v", err)
	} //getting the user by the email

	if !bytes.Equal(got , testSalt) {
		t.Errorf("known user: expected %x , got %x" , testSalt , got)
	}

	unknownEmail1 := "definitely-not-registered-1@example.com"
	unknownEmail2 := "definitely-not-registered-2@example.com"

	fake1, err := GetSaltForEmail(db, unknownEmail1, secret)
	if err != nil {
		t.Fatalf("unknown email should not error: %v", err)
	}
	if len(fake1) != 16 {
		t.Errorf("fake salt length: expected 16, got %d", len(fake1))
	}

	fake1Again, err := GetSaltForEmail(db, unknownEmail1, secret)
	if err != nil {
		t.Fatalf("unknown email should not error: %v", err)
	}
	if !bytes.Equal(fake1, fake1Again) {
		t.Errorf("same unknown email should return identical fake salt: got %x then %x", fake1, fake1Again)
	}

	fake2, err := GetSaltForEmail(db, unknownEmail2, secret)
	if err != nil {
		t.Fatalf("unknown email should not error: %v", err)
	}
	if bytes.Equal(fake1, fake2) {
		t.Errorf("different unknown emails should return different fake salts, both got %x", fake1)
	}
	
}