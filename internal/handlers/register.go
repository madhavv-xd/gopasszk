package handlers

import (
	"encoding/base64"
	"net/http"

	"errors"
	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/auth"
	"github.com/madhavv-xd/gopasszk/internal/models"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
	"log"
)

//this will contain the struct for register request
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Salt     string `json:"salt" binding:"required,base64"`
	AuthHash string `json:"auth_hash" binding:"required,base64"`
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	saltDecoded, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error decoding the salt from string"})
		return
	}
	authHash, err := base64.StdEncoding.DecodeString(req.AuthHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error decoding the authHash"})
		return
	}
	if len(saltDecoded) != 16 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "salt length is not appropriate"})
		return
	}
	if len(authHash) != 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "authhash length isnt appropriate"})
		return
	}

	phc, err := auth.HashAuthKey(authHash)
	if err != nil {
		log.Printf("creating the phc string failed %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server failed to generate the phc string"})
		return
	}

	user := models.User{
		Email:    req.Email,
		Salt:     saltDecoded,
		AuthHash: phc,
	}

	err = repository.CreateUser(h.DB, &user)
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			c.JSON(http.StatusConflict, gin.H{"error": "unable to register"})
			return
		}
		log.Printf("create user failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create the user"})
		return

	}
	c.JSON(http.StatusCreated, gin.H{"message": "reigstered"})
}
