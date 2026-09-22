package handlers

import (
	"encoding/base64"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/auth"
)

func (h* Handler) GetSalt(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest , gin.H{"error" : "email is reqd"})
		return 
	}

	salt , err  := auth.GetSaltForEmail(h.DB , email , h.Secret)
	if err != nil {
		log.Printf("get salt failed: %v" , err)
		c.JSON(http.StatusInternalServerError , gin.H{"error" : "internal error"})
		return 
	}
	c.JSON(http.StatusOK , gin.H{"salt" : base64.StdEncoding.EncodeToString(salt)})
}
