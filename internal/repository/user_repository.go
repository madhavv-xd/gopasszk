package repository

import (
	"gorm.io/gorm"
	"github.com/madhavv-xd/gopasszk/internal/models"
);

func CreateUser(db *gorm.DB ,user *models.User) error {
	result := db.Create(user)
	return result.Error
}

func DeleteUser(db *gorm.DB ,user *models.User) error {
	result := db.Delete(user)
	return result.Error
}


func GetUserByEmail(db *gorm.DB , email string) (*models.User , error) {
	var user models.User
	result := db.First(&user , "email = ?" , email)
	if result.Error != nil {
		return nil , result.Error
	}
	return &user , nil 
}