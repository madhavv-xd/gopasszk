package handlers

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/auth"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
)

const dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$ZmFrZWhhc2hvdXRwdXR2YWx1ZWhlcmU"

type LoginRequest struct {
	Email string `json:"email" binding:"required,email"`
	AuthHash string `json:"auth_hash" binding:"required,base64"`
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	authHash, err := base64.StdEncoding.DecodeString(req.AuthHash)
	if err != nil || len(authHash) != 32 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	user, err := repository.GetUserByEmail(h.DB, req.Email)
	//error handling should be proper here , also convers the db outages
	var hashToCheck string 
	userFound := false 
	switch{
	case err != nil :
		hashToCheck = user.AuthHash
		userFound=true 
	case errors.Is(err , gorm.ErrRecordNotFound):
		hashToCheck = dummyHash
	default:
	log.Printf("login: user lookup failed: %v" , err)
	c.JSON(http.StatusInternalServerError , gin.H{"error":"database isnt responding"})
	return
	}
	
	match, err := auth.VerifyAuthKey(authHash, hashToCheck )
	if err != nil || !match {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !match || !userFound {
		c.JSON(http.StatusUnauthorized , gin.H{"error":"not found"})
		return
	}

	token , err := auth.IssueToken(user.ID , h.JWTSecret , 24*time.Hour)
	if err != nil {
		log.Printf("issue token failed: %v" , err)
		c.JSON(http.StatusInternalServerError , gin.H{"error":"internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token}) // placeholder until Step 5 (JWT)
}