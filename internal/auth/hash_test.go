package auth

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	tst := make([]byte , 32)
	
	hash , err := HashAuthKey(tst)
	if err != nil {
		t.Fatalf("error creating user %v" , err)
	}
	if !strings.HasPrefix(hash , "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("wrong params in hash: %s" , hash)
	}
}

//tests 
func VerifyHash(t *testing.T) {
	authHash := make([]byte , 32)
	
	hash , err := HashAuthKey(authHash)
	if err != nil {
		t.Fatalf("error creating user %v" , err)
	}
	match , err := VerifyAuthKey(authHash , hash) 
	if err != nil {
		t.Fatalf("doesnt match %v" , err)
	}
	if match == false {
		t.Errorf("correct auth hash was rejected")
	}
}

//tests 
func VerifyHash2(t *testing.T) {
	authHash := make([]byte , 32)
	authHash[0] = 1
	hash , err := HashAuthKey(authHash)
	if err != nil {
		t.Fatalf("error creating user %v" , err)
	}
	match , err := VerifyAuthKey(authHash , hash) 
	if err != nil {
		t.Fatalf("doesnt match %v" , err)
	}
	if match == false {
		t.Errorf("wrong was accepted")
	}
}