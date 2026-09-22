package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Me(c *gin.Context) {
	userID := c.MustGet("userID").(string)
	c.JSON(http.StatusOK , gin.H{"user_id":userID})
}