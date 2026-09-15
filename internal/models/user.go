package models //user model 
//it will be a user struct

import "time"

type User struct {
	ID string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email string `gorm:"unique"` 
	AuthHash string 
	CreatedAt time.Time
	UpdatedAt time.Time
}
