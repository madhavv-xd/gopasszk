package repository

import (
	"github.com/madhavv-xd/gopasszk/internal/models"
	"gorm.io/gorm"
);

func CreateCredential(db *gorm.DB , credential *models.Credential) error {
	//this function will return an error or just done
	result := db.Create(credential)
 	return result.Error
}

func DeleteCredential(db *gorm.DB , credential *models.Credential) error {
	//this function will return an error or just done
	result := db.Delete(credential)
 	return result.Error
}


func GetCredentialById(db *gorm.DB , id string ) (*models.Credential , error) {
	var cred models.Credential
	result := db.First(&cred , "id = ?" , id)
	if result.Error != nil {
		return nil , result.Error
	}
	return &cred , nil  
}