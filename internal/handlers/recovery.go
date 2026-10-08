package handlers

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/auth"
	"github.com/madhavv-xd/gopasszk/internal/models"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
)

type RecoverKeyRequest struct {
	Email            string `json:"email" binding:"required,email"`
	RecoveryAuthHash string `json:"recovery_auth_hash" binding:"required,base64"`
}

type RecoverResetRequest struct {
	Email              string `json:"email" binding:"required,email"`
	RecoveryAuthHash   string `json:"recovery_auth_hash" binding:"required,base64"`
	NewSalt            string `json:"new_salt" binding:"required,base64"`
	NewAuthHash        string `json:"new_auth_hash" binding:"required,base64"`
	NewWrappedVaultKey string `json:"new_wrapped_vault_key" binding:"required,base64"`
}

// verifyRecovery checks the recovery auth hash for an email.
// Unknown emails still run a verify (against dummyHash) so timing and response match a wrong phrase.
// Returns the user only if the phrase is correct; ok=false means "invalid credentials".
func (h *Handler) verifyRecovery(email, recoveryAuthB64 string) (*models.User, bool, error) {
	recAuth, ok := decodeExact(recoveryAuthB64, 32)
	if !ok {
		return nil, false, nil
	}

	user, err := repository.GetUserByEmail(h.DB, email)
	hashToCheck := dummyHash
	switch {
	case err == nil:
		hashToCheck = user.RecoveryAuthHash
	case errors.Is(err, gorm.ErrRecordNotFound):
		user = nil
	default:
		return nil, false, err
	}

	match, err := auth.VerifyAuthKey(recAuth, hashToCheck)
	if err != nil || !match || user == nil {
		return nil, false, nil
	}
	return user, true, nil
}

// RecoverKey godoc
// @Summary      Start account recovery
// @Description  Verifies the recovery auth hash and returns the recovery-wrapped vault key.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body  RecoverKeyRequest  true  "Email and recovery auth hash (base64, 32 bytes)"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /recover/key [post]
func (h *Handler) RecoverKey(c *gin.Context) {
	var req RecoverKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	user, ok, err := h.verifyRecovery(req.Email, req.RecoveryAuthHash)
	if err != nil {
		log.Printf("recover key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"recovery_wrapped_key": base64.StdEncoding.EncodeToString(user.RecoveryWrappedKey),
	})
}

// RecoverReset godoc
// @Summary      Finish account recovery
// @Description  Verifies the recovery auth hash again, then sets a new salt, auth hash, and password-wrapped vault key.
// @Tags         auth
// @Accept       json
// @Param        request  body  RecoverResetRequest  true  "Email, recovery auth hash, new salt (16), new auth hash (32), new wrapped vault key (60)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /recover/reset [post]
func (h *Handler) RecoverReset(c *gin.Context) {
	var req RecoverResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	newSalt, ok1 := decodeExact(req.NewSalt, 16)
	newAuth, ok2 := decodeExact(req.NewAuthHash, 32)
	newWrapped, ok3 := decodeExact(req.NewWrappedVaultKey, 60)
	if !(ok1 && ok2 && ok3) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid field length or encoding"})
		return
	}

	user, ok, err := h.verifyRecovery(req.Email, req.RecoveryAuthHash)
	if err != nil {
		log.Printf("recover reset: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	newPHC, err := auth.HashAuthKey(newAuth)
	if err != nil {
		log.Printf("recover reset: hashing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if err := repository.UpdateUserPassword(h.DB, user.ID, newSalt, newPHC, newWrapped); err != nil {
		log.Printf("recover reset: update failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}