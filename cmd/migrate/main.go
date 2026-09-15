package main

import (
	"log"

	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/models"
)


func main () {
	db , err := database.Connect()
	if err != nil {
		log.Fatal("Unable to connect")
		return
	}
	err = db.AutoMigrate(&models.User{} , &models.Credential{})
	if err != nil {
		log.Fatal("migration failed")
		return 
	}
	
}