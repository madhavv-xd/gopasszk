package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Me godoc
// @Summary      Current user
// @Description  Returns the user ID from the JWT. Useful for checking a token.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /me [get]
func (h *Handler) Me(c *gin.Context) {
	userID := c.MustGet("userID").(string)
	c.JSON(http.StatusOK , gin.H{"user_id":userID})
}