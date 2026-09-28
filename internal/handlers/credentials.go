package handlers // same as login.go

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/madhavv-xd/gopasszk/internal/models"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
	// where Credential lives
)

type CredentialRequest struct {
	SiteName           string `json:"site_name" binding:"required,max=255"`
	UsernameCiphertext string `json:"username_ciphertext" binding:"required,base64"`
	PasswordCiphertext string `json:"password_ciphertext" binding:"required,base64"`
}

type CredentialResponse struct {
	ID                 string `json:"id"`
	SiteName           string `json:"site_name"`
	UsernameCiphertext string `json:"username_ciphertext"`
	PasswordCiphertext string `json:"password_ciphertext"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

func toCredentialResponse(c models.Credential) CredentialResponse {
	return CredentialResponse{
		ID:                 c.ID,
		SiteName:           c.SiteName,
		UsernameCiphertext: c.UsernameCiphertext,
		PasswordCiphertext: c.PasswordCiphertext,
		CreatedAt:          c.CreatedAt,
		UpdatedAt:          c.UpdatedAt,
	}
}

const (
	gcmNonceSize = 12
	gcmTagSize = 16
	minCiphertextLen = gcmNonceSize + gcmTagSize
	maxCiphertextLen = 4096
)

func validateCipherText(s string) error {
	decoded , err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return errors.New("not valid base64")
	}
	if len(decoded) < minCiphertextLen {
		return errors.New("ciphertext too short")
	}
	if len(decoded) > maxCiphertextLen {
		return errors.New("ciphertext too long")
	}
	return nil 
}

// CreateCredential godoc
// @Summary      Create a credential
// @Description  Stores an encrypted credential. The owner comes from the JWT, never the body.
// @Tags         credentials
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CredentialRequest  true  "Encrypted credential"
// @Success      201      {object}  CredentialResponse
// @Failure      400      {object}  map[string]string
// @Failure      401      {object}  map[string]string
// @Failure      500      {object}  map[string]string
// @Router       /credentials [post]
func(h *Handler) CreateCredential(c *gin.Context){
	var req CredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error":"invalid request"})
		return 
	}
	if err := validateCipherText(req.UsernameCiphertext); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
		return
	}
	if err := validateCipherText(req.PasswordCiphertext); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
		return
	}
	userID , ok := c.MustGet("userID").(string)
	if !ok {
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	return 
	}

	cred := models.Credential{
		UserID:             userID,
		SiteName:           req.SiteName,
		UsernameCiphertext: req.UsernameCiphertext,
		PasswordCiphertext: req.PasswordCiphertext,
	}

	if err := repository.CreateCredential(h.DB, &cred); err != nil {
		log.Printf("create credential: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, toCredentialResponse(cred))
}

// ListCredentials godoc
// @Summary      List credentials
// @Description  Returns all of the authenticated user's credentials, still encrypted.
// @Tags         credentials
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string][]CredentialResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /credentials [get]
func(h *Handler) ListCredentials(c *gin.Context) {
	userID , ok := c.MustGet("userID").(string)
	if !ok {
		c.JSON(http.StatusInternalServerError , gin.H{"error" : "internal server error"})
		return 
	}
	creds , err := repository.ListCredentialsByUser(h.DB , userID) 
	if err != nil {
		log.Printf("list credentials: %v" , err)
		c.JSON(http.StatusInternalServerError , gin.H{"error":"internal server error"})
		return 
	}
	responses := make([]CredentialResponse , 0, len(creds))
	for _ , cred := range creds {
		responses = append(responses , toCredentialResponse(cred))
	}
	c.JSON(http.StatusOK , gin.H{"credentials" : responses})
}

//now the put and delete funcs
// UpdateCredential godoc
// @Summary      Update a credential
// @Description  Replaces a credential's site name and ciphertexts. Returns 404 if it doesn't exist or isn't yours.
// @Tags         credentials
// @Accept       json
// @Security     BearerAuth
// @Param        id       path  string             true  "Credential ID (UUID)"
// @Param        request  body  CredentialRequest  true  "New encrypted values"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /credentials/{id} [put]
func(h *Handler) UpdateCredential(c *gin.Context) {
	userID , ok := c.MustGet("userID").(string)
	if !ok {
		c.JSON(http.StatusInternalServerError , gin.H{"error" : "internal server errir"})
		return 
	}
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest , gin.H{"error":"invalid id"})
		return 
	}

	var req CredentialRequest 
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if err := validateCipherText(req.UsernameCiphertext); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateCipherText(req.PasswordCiphertext); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated := models.Credential {
		SiteName: req.SiteName,
		UsernameCiphertext: req.UsernameCiphertext,
		PasswordCiphertext: req.PasswordCiphertext,
	}

	err := repository.UpdateCredentialForUser(h.DB , id , userID , updated)
	switch {
		case err == nil: 
			c.Status(http.StatusNoContent)
	case errors.Is(err , gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound , gin.H{"error":"credential not found"})
	default:
		log.Printf("updated credential: %v" , err) 
		c.JSON(http.StatusInternalServerError , gin.H{"error":"internal server error"})
	}
}

// DeleteCredential godoc
// @Summary      Delete a credential
// @Description  Deletes a credential. Returns 404 if it doesn't exist or isn't yours.
// @Tags         credentials
// @Security     BearerAuth
// @Param        id  path  string  true  "Credential ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /credentials/{id} [delete]
func(h *Handler) DeleteCredential(c *gin.Context) {
	userID , ok := c.MustGet("userID").(string)
	if !ok {
		c.JSON(http.StatusInternalServerError , gin.H{"error":"internal server error"})
		return 
	}
	id := c.Param("id")
	if _,err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error":"invalid id"})
		return 
	}
	err := repository.DeleteCredential(h.DB , id , userID)
	switch {
	case err == nil:
		c.Status(http.StatusNoContent)
	case errors.Is(err , gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound , gin.H{"error":"credential not found"})
	default:
		log.Printf("delete credential: %v" , err)
		c.JSON(http.StatusInternalServerError, gin.H{"error":"interval server error"})
	}
}