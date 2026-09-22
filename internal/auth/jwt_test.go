package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueToken(t *testing.T) {
	secret := []byte("test-jwt-secret")
	userID := "some-fake-uuid-1234"

	tokenStr, err := IssueToken(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	claims := &Claims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("expected UserID %q, got %q", userID, claims.UserID)
	}
}