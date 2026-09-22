package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/config"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/handlers"
)

func main() {
	router := gin.Default()
	db , err := database.Connect()
	if err != nil{
		log.Fatalf("error connecting to the db %v" , err)
	}
	cfg := config.LoadConfig()
	h := &handlers.Handler{DB: db , Secret:[]byte(cfg.ServerSecret)} //handler has been created here 

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	router.POST("/register", h.Register)
	router.GET("/salt" , h.GetSalt)
	router.POST("/login" , h.Login)
	err = router.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
