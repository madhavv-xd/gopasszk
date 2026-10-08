package repository

import (
	"github.com/madhavv-xd/gopasszk/internal/models"
	"gorm.io/gorm"
)

func CreateUser(db *gorm.DB, user *models.User) error {
	result := db.Create(user)
	return result.Error
}

func DeleteUser(db *gorm.DB, user *models.User) error {
	result := db.Delete(user)
	return result.Error
}

func GetUserByEmail(db *gorm.DB, email string) (*models.User, error) {
	var user models.User
	result := db.First(&user, "email = ?", email)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func GetUserByID(db *gorm.DB, id string) (*models.User, error) {
	var user models.User
	result := db.First(&user, "id = ?", id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func UpdateUserPassword(db *gorm.DB, id string, salt []byte, authHash string, wrappedVK []byte) error {
	result := db.Model(&models.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"salt":              salt,
			"auth_hash":         authHash,
			"wrapped_vault_key": wrappedVK,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}