package main

import (
	"fmt"
	"log"

	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/models"
)

func main() {
	db, err := database.Connect()
	if err != nil {
		log.Fatalf("Unable to connect: %v" , err)
		return
	}
	err = db.AutoMigrate(&models.User{}, &models.Credential{})
	if err != nil {
		log.Fatal("migration failed: %v" , err)
		return
	}
	fmt.Println("migration successful")
}
