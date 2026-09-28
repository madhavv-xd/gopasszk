package main

import (
	"log"
	_ "github.com/madhavv-xd/gopasszk/docs"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/config"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/handlers"
	"github.com/madhavv-xd/gopasszk/internal/middleware"
)

// @title           Gopass API
// @version         1.0
// @description     Zero-knowledge password manager backend. The server only stores auth hashes and ciphertext.
// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
func main() {
	router := gin.Default()
	db , err := database.Connect()
	if err != nil{
		log.Fatalf("error connecting to the db %v" , err)
	}
	cfg := config.LoadConfig()
	h := &handlers.Handler{DB: db , Secret:[]byte(cfg.ServerSecret) , JWTSecret: []byte(cfg.JWTSecret)} //handler has been created here 

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})	
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	router.POST("/register", h.Register)
	router.GET("/salt" , h.GetSalt)
	router.POST("/login" , h.Login)
	router.GET("/me" , middleware.RequireAuth(h.JWTSecret) , h.Me)
	creds := router.Group("/credentials")
	creds.Use(middleware.RequireAuth(h.JWTSecret))
	{	
		creds.POST("" , h.CreateCredential)
		creds.GET("" , h.ListCredentials)
		creds.PUT("/:id", h.UpdateCredential)
		creds.DELETE("/:id" , h.DeleteCredential)
	}

	err = router.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
