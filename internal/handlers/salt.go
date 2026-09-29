package handlers

import (
	"encoding/base64"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/auth"
)

// GetSalt godoc
// @Summary      Get the salt for an email
// @Description  Returns the account's salt so the client can derive its keys. Unknown emails get a deterministic fake salt, so this can't be used to check which emails are registered.
// @Tags         auth
// @Produce      json
// @Param        email  query     string  true  "Account email"
// @Success      200    {object}  map[string]string
// @Failure      400    {object}  map[string]string
// @Router       /salt [get]
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
