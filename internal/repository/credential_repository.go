package repository

import (
	"github.com/madhavv-xd/gopasszk/internal/models"
	"gorm.io/gorm"
)

func CreateCredential(db *gorm.DB, credential *models.Credential) error {
	//this function will return an error or just done
	result := db.Create(credential)
	return result.Error
}

func DeleteCredential(db *gorm.DB, id string , userID string) error {
	//this function will return an error or just done
	result := db.Where("id = ? AND user_id = ?" , id , userID).Delete(&models.Credential{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil 
}

func GetCredentialById(db *gorm.DB, id string , userID string) (*models.Credential, error) {
	var cred models.Credential
	result := db.First(&cred, "id = ? AND user_id = ?", id , userID)
	if result.Error != nil {
		return nil, result.Error
	}
	return &cred, nil
}

func ListCredentialsByUser(db *gorm.DB, userID string) ([]models.Credential, error) {
	creds := []models.Credential{}

	result := db.Where("user_id = ?", userID).Find(&creds)
	if result.Error != nil {
		return nil, result.Error
	}
	return creds, nil
}

func UpdateCredentialForUser(db *gorm.DB, id string , userID string , updated models.Credential) error {
	result := db.Model(&models.Credential{}).
	Where("user_id = ? AND id = ?" , userID , id).
	Select("site_name" , "username_ciphertext" , "password_ciphertext").
	Updates(updated)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil 
}
