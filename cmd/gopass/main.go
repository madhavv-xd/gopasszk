package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/crypto"
	"github.com/madhavv-xd/gopasszk/internal/pwgn"
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
	case "show":
		err = runShow(args)
	case "generate":
		err = runGenerate(args)
	case "copy":
		err = runCopy(args)
	case "search":
		err = runSearch(args)
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
  register        create an account
  login           log in and save a session token
  add             add a credential
  list            list your credentials (site and ID only)
  show <id>       show one credential, decrypted
  generate [len]  generate a random password (default 20)
  edit <id>       change a credential
  delete <id>     delete a credential
  logout          clear the saved session
  help            show this help
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

	var password []byte
	for {
		p, err := promptPassword("Password to store (Enter to generate): ")
		if err != nil {
			return err
		}
		if len(p) > 0 {
			password = p
			break
		}

		answer, err := promptLine("Generate a random password? [Y/n]: ")
		if err != nil {
			return err
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer == "" || answer == "y" || answer == "yes" {
			lenStr, err := promptLine("Length [20]: ")
			if err != nil {
				return err
			}
			length := 20
			if s := strings.TrimSpace(lenStr); s != "" {
				n, err := strconv.Atoi(s)
				if err != nil {
					fmt.Println("Length must be a number.")
					continue
				}
				length = n
			}

			gen, err := pwgn.Generate(length)
			if err != nil {
				fmt.Println(err)
				continue
			}
			password = []byte(gen)
			fmt.Printf("Generated a %d-character password.\n", length)
			break
		}
		// anything else (e.g. "n"): loop and ask for the password again
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
	//run list will show the list using the current session and load the creds directly
	//there will be another one to show the creds by the ids 
	s, err := loadSession()
	if err != nil {
		return err 
	}
	u , err := serverURL()
	if err != nil {
		return  err 
	}
	c := client.New(u)
	c.Token = s.Token

	creds , err := c.ListCredentials()
	if err != nil {
		return  err 
	}
	if len(creds) == 0 {
		fmt.Println("No credentials yet.")
		return  nil 
	}
	for _, cr := range creds {
		fmt.Printf("%s  %s\n", cr.ID, cr.SiteName)
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
	site, user, pass, err := findCredential(c, key, id)
	if err != nil {
		return err
	}

	newSite, err := promptLine(fmt.Sprintf("Site [%s]: ", site))
	if err != nil {
		return err
	}
	if newSite == "" {
		newSite = site
	}

	newUser, err := promptLine(fmt.Sprintf("Username [%s]: ", user))
	if err != nil {
		return err
	}
	if newUser == "" {
		newUser = user
	}

	newPass, err := promptPassword("Password [Press enter to keep current]: ")
	if err != nil {
		return err
	}
	if len(newPass) == 0 {
		newPass = []byte(pass)
	}

	userCT, err := encryptField(key, newUser)
	if err != nil {
		return err
	}
	passCT, err := encryptField(key, string(newPass))
	if err != nil {
		return err
	}

	if err := c.UpdateCredential(id, newSite, userCT, passCT); err != nil {
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

func runShow(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gopass show <id>")
	}
	c, key, err := unlock()
	if err != nil {
		return err
	}
	site, user, pass, err := findCredential(c, key, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("Site:     %s\nUsername: %s\nPassword: %s\n", site, user, pass)
	return nil
}

func runGenerate(args []string) error {
	length := 20 
	if len(args) == 1 {
		n , err := strconv.Atoi(args[0])
		if err != nil {
			return errors.New("length must be a number")
		}
		length = n 
	}
	pw , err := pwgn.Generate(length)
	if err != nil {
		return  err 
	}
	fmt.Println(pw)
	return nil 
}

func runCopy(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gopass copy <id>")
	}
	c, key, err := unlock()
	if err != nil {
		return err
	}
	site, _, pass, err := findCredential(c, key, args[0])
	if err != nil {
		return err
	}

	if err := clipboard.WriteAll(pass); err != nil {
		return err
	}
	fmt.Printf("Copied password for %s. Clearing in 30s (Ctrl+C to clear now)...\n", site)

	//make a channel with a buffered input so that it can deliver os.Signal value 
	interrupt := make(chan os.Signal , 1) //basically a channel for handling the ctrl c 
	signal.Notify(interrupt , os.Interrupt)
	defer signal.Stop(interrupt)

	select {
	case <-time.After(30* time.Second):
	case <- interrupt:
	}

	current , err := clipboard.ReadAll()
	if err == nil && current == pass {
		if err := clipboard.WriteAll(""); err != nil {
			return err 
		}
		fmt.Println("clipboard cleared.")
	}
	return nil 
}

func runSearch(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gopass search <term>")
	}
	s, err := loadSession()
	if err != nil {
		return err
	}
	u, err := serverURL()
	if err != nil {
		return err
	}
	c := client.New(u)
	c.Token = s.Token

	creds, err := c.SearchCredentials(args[0])
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		fmt.Println("No matches.")
		return nil
	}
	for _, cr := range creds {
		fmt.Printf("%s  %s\n", cr.ID, cr.SiteName)
	}
	return nil
}