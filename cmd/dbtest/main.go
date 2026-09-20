package main

import (
	"fmt"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"log"
)

func main() {
	db, err := database.Connect()
	if err != nil {
		log.Fatal("failed to connect")
		return
	}
	fmt.Println("connection has been made")

	err = database.Ping(db)
	if err != nil {
		log.Fatal("cant ping , problem is there")
		return
	}
	fmt.Println("both connextion and ping successful")
}
