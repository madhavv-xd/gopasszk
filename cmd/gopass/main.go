package main

import (
	"errors"
	"fmt"
	"os"
	"github.com/madhavv-xd/gopasszk/internal/crypto"
	"github.com/madhavv-xd/gopasszk/internal/client"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "register":
		err = runRegister(args)
	case "login":
		err = runLogin(args)
	case "add":
		err = runAdd(args)
	case "list":
		err = runList(args)
	case "edit":
		err = runEdit(args)
	case "delete":
		err = runDelete(args)
	case "logout":
		err = runLogout(args)
	case "help" , "-h" , "--help":
		err = runHelp(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: gopass <command>

commands:
  register      create an account
  login         log in and save a session token
  add           add a credential
  list          list and decrypt your credentials
  edit <id>     change a credential
  delete <id>   delete a credential
  logout 		logout of the cli
  `)
}

func runRegister(args []string) error {
	email, err := promptLine("Email: ")
	if err != nil {
		return err
	}
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if string(pw) != string(confirm) {
		return errors.New("passwords don't match")
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	authHash := crypto.DeriveAuthHash(pw, salt)

	u , err := serverURL()
	if err != nil {
		return err 
	}
	c := client.New(u)
	if err := c.Register(email, salt, authHash); err != nil {
		return err
	}
	fmt.Println("Registered. Now run: gopass login")
	return nil
}

func runLogin(args []string) error {
	email, err := promptLine("Email: ")
	if err != nil {
		return err
	}
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}

	u , err := serverURL()
	if err != nil {
		return err 
	}
	c := client.New(u)
	salt, err := c.GetSalt(email)
	if err != nil {
		return err
	}
	authHash := crypto.DeriveAuthHash(pw, salt)

	token, err := c.Login(email, authHash)
	if err != nil {
		return err
	}
	if err := saveSession(session{Email: email, Token: token}); err != nil {
		return err
	}
	fmt.Println("Logged in.")
	return nil
}

func runLogout(args []string) error{
	if err := deleteSession(); err != nil {
		return err 
	}
	fmt.Println("logged out.")
	return nil 
}

func runAdd(args []string) error {
	c, key, err := unlock()
	if err != nil {
		return err
	}
	site, err := promptLine("Site: ")
	if err != nil {
		return err
	}
	username, err := promptLine("Username: ")
	if err != nil {
		return err
	}
	password, err := promptPassword("Password to store: ")
	if err != nil {
		return err
	}

	userCT, err := encryptField(key, username)
	if err != nil {
		return err
	}
	passCT, err := encryptField(key, string(password))
	if err != nil {
		return err
	}

	cred, err := c.CreateCredential(site, userCT, passCT)
	if err != nil {
		return err
	}
	fmt.Println("Added:", cred.ID)
	return nil
}

func runList(args []string) error {
	c, key, err := unlock()
	if err != nil {
		return err
	}
	creds, err := c.ListCredentials()
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		fmt.Println("No credentials yet.")
		return nil
	}
	for _, cr := range creds {
		user, err := decryptField(key, cr.UsernameCiphertext)
		if err != nil {
			user = "<cannot decrypt>"
		}
		pass, err := decryptField(key, cr.PasswordCiphertext)
		if err != nil {
			pass = "<cannot decrypt>"
		}
		fmt.Printf("%s  %-20s  %-25s  %s\n", cr.ID, cr.SiteName, user, pass)
	}
	return nil
}

func runEdit(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gopass edit <id>")
	}
	id := args[0]

	c, key, err := unlock()
	if err != nil {
		return err
	}
	site, err := promptLine("New site: ")
	if err != nil {
		return err
	}
	username, err := promptLine("New username: ")
	if err != nil {
		return err
	}
	password, err := promptPassword("New password: ")
	if err != nil {
		return err
	}

	userCT, err := encryptField(key, username)
	if err != nil {
		return err
	}
	passCT, err := encryptField(key, string(password))
	if err != nil {
		return err
	}

	if err := c.UpdateCredential(id, site, userCT, passCT); err != nil {
		return err
	}
	fmt.Println("Updated.")
	return nil
}

func runDelete(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gopass delete <id>")
	}
	s, err := loadSession()
	if err != nil {
		return err
	}
	u , err := serverURL()
	if err != nil {
		return err 
	}
	c := client.New(u)
	c.Token = s.Token

	if err := c.DeleteCredential(args[0]); err != nil {
		return err
	}
	fmt.Println("Deleted.")
	return nil
}

func runHelp(args []string) error {
	usage()
	return nil 
}