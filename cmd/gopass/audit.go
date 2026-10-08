package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

//a function for checking the password validation

func isWeak(pass string) bool {
	if len(pass) < 12 {
		return true 
	}
	var hasLower , hasUpper , hasDigit , hasSymbol bool 
	for _, r := range pass {
		switch {
		case unicode.IsLower(r):
			hasLower = true 
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true 
		default:
			hasSymbol = true
		}
	}
	return !(hasLower && hasUpper && hasDigit && hasSymbol)
}

//okay , we will use the  k-anonimity of haveiBeenPwned api , that will detect the top 5 chars of the SHA-1 hashed password 
func pwnedCount(pass string) (int , error){
	sum := sha1.Sum([]byte(pass))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix , suffix := hash[:5] , hash[5:] //for k-anomi , we send the top 5 to it only 

	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "gopasszk-cli") //user agent is kinda something / sftware name that your brower send with every request 
	resp , err := httpClient.Do(req)
	if err != nil {
		return 0 , err 
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0 , fmt.Errorf("breach check failed: status %d", resp.StatusCode)
	}

	//now a new scanner for parsing the response 
	scanner := bufio.NewScanner(resp.Body)
	for  scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line , ":" , 2)
		if len(parts) == 2 && parts[0] == suffix {
			return strconv.Atoi(parts[1])
		}
	}
	return 0 , scanner.Err()
}