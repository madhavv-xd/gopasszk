package main

import (
	"fmt"

	"github.com/madhavv-xd/gopasszk/internal/crypto"
)

func main() {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		fmt.Println(err)
		return
	}

	password := []byte("test-password-123")
	key := crypto.DeriveKey(password, salt)

	fmt.Printf("salt: %x\n", salt)
	fmt.Printf("key: %x\n", key)
	//now the encryption and decryption matching
	plaintext := []byte("my-git-pass")

	nonce , ciphertext , err  := crypto.Encrypt(key , plaintext)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("nonce: %x\n" , nonce)
	fmt.Printf("ciphertext: %x\n" , ciphertext)

	decrypted , err := crypto.Decrypt(key , nonce , ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("decrypted: %x\n" , string(decrypted))

	if(string(decrypted) == string(plaintext)) {
		fmt.Println("round trip successful")
	} else {
		fmt.Println("round trip failed")	
	}
}