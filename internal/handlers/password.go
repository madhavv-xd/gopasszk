package handlers

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/auth"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
)

type ChangePasswordRequest struct {
	OldAuthHash        string `json:"old_auth_hash" binding:"required,base64"`
	NewSalt            string `json:"new_salt" binding:"required,base64"`
	NewAuthHash        string `json:"new_auth_hash" binding:"required,base64"`
	NewWrappedVaultKey string `json:"new_wrapped_vault_key" binding:"required,base64"`
}

// decodeExact base64-decodes s and checks it has exactly n bytes.
func decodeExact(s string, n int) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

// ChangePassword godoc
// @Summary      Change master password
// @Description  Verifies the old auth hash, then stores a new salt, auth hash, and re-wrapped vault key. Credentials are untouched.
// @Tags         auth
// @Accept       json
// @Security     BearerAuth
// @Param        request  body  ChangePasswordRequest  true  "Old auth hash plus new salt (16), auth hash (32), wrapped vault key (60), all base64"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /me/password [put]
func (h *Handler) ChangePassword(c *gin.Context) {
	userID, ok := c.MustGet("userID").(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	oldAuth, ok1 := decodeExact(req.OldAuthHash, 32)
	newSalt, ok2 := decodeExact(req.NewSalt, 16)
	newAuth, ok3 := decodeExact(req.NewAuthHash, 32)
	newWrapped, ok4 := decodeExact(req.NewWrappedVaultKey, 60)
	if !(ok1 && ok2 && ok3 && ok4) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid field length or encoding"})
		return
	}

	user, err := repository.GetUserByID(h.DB, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		log.Printf("change password: lookup failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	match, err := auth.VerifyAuthKey(oldAuth, user.AuthHash)
	if err != nil || !match {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	newPHC, err := auth.HashAuthKey(newAuth)
	if err != nil {
		log.Printf("change password: hashing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err := repository.UpdateUserPassword(h.DB, userID, newSalt, newPHC, newWrapped); err != nil {
		log.Printf("change password: update failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.Status(http.StatusNoContent)
}