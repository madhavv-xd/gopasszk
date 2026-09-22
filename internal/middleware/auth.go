package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/madhavv-xd/gopasszk/internal/auth"
)

func RequireAuth(jwtsecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized , gin.H{"error" : "missing auth header"})
			c.Abort()
			return 
		}
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader , bearerPrefix) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			c.Abort()
			return
		}
		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)

		claims := &auth.Claims{}
		token , err := jwt.ParseWithClaims(tokenString , claims , func(t *jwt.Token) (interface{}, error) {
			return jwtsecret, nil 
		})
		if err != nil || !token.Valid{
			c.JSON(http.StatusUnauthorized , gin.H{"error" : "invalid or expired token"})
			c.Abort()
			return 
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}
