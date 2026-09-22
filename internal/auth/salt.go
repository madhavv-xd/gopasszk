package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	

	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
)

func GetSaltForEmail(db *gorm.DB , email string , secret []byte)([]byte , error){
	user , err := repository.GetUserByEmail(db , email)
	if err == nil {
		 return user.Salt , nil 
	} else if errors.Is(err , gorm.ErrRecordNotFound) {
		mac := hmac.New(sha256.New , secret)
		mac.Write([]byte(email))
		digest := mac.Sum(nil)
		fakeSalt := digest[:16]
		return fakeSalt ,nil 
	} else {
		return nil , err 
	}
}

