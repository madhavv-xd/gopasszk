package models 

import (
	"time"
)

//7 col -> id , uid , site_name , uname_ct , ps_ct , created_At , updated_At
type Credential struct {
	ID string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID string `gorm:"type:uuid;not null"`
	User User `gorm:"foreignKey:UserID; references:ID"`
	SiteName string 
	UsernameCiphertext string 
	PasswordCiphertext string 
	CreatedAt time.Time 
	UpdatedAt time.Time 
}