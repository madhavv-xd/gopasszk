package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/madhavv-xd/gopasszk/internal/database"
	"github.com/madhavv-xd/gopasszk/internal/repository"
	"gorm.io/gorm"
)

func b64(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

// validPayload is a fully valid register body; tests override one field to hit one check.
func validPayload(email string) map[string]string {
	return map[string]string{
		"email":                email,
		"salt":                 b64(16),
		"auth_hash":            b64(32),
		"wrapped_vault_key":    b64(60),
		"recovery_wrapped_key": b64(60),
		"recovery_auth_hash":   b64(32),
	}
}

func TestRegisterSuccess(t *testing.T) {
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success@example.com")
	payload := validPayload("handler-success@example.com")
	w := postRegister(t , router , payload)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 , got %d: %s" , w.Code , w.Body.String())
	}
}

func setupRouter(t *testing.T )(*gin.Engine , *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db , err := database.Connect()
	if err != nil {
		t.Fatalf("error connecting to the db: %v" , err)
	}
	h := &Handler{DB: db}

	router := gin.New()

	router.POST("/register" , h.Register)

	return router , db 
}

func cleanupUser(t *testing.T , db *gorm.DB , email string) {
	t.Helper()
	res, err := repository.GetUserByEmail(db, email)
	if err != nil {
		return
	}
	err = repository.DeleteUser(db, res)
	if err != nil {
		t.Errorf("cleanup failed: %v", err)
	}
}

func postRegister(t *testing.T , router *gin.Engine , payload map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("erorr getting the payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register" ,  bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w , req)

	return w
}

func TestRegisterWrongSaltLength(t *testing.T) {
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success2@example.com")
	payload := validPayload("handler-success2@example.com")
	payload["salt"] = b64(3)
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterWrongAuthHashLength(t *testing.T) {
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success3@example.com")
	payload := validPayload("handler-success3@example.com")
	payload["auth_hash"] = b64(3)
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterMissingEmail(t *testing.T) {
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "")
	payload := validPayload("")
	delete(payload, "email")
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterBadBase64(t *testing.T) {
	router , _:= setupRouter(t)
	payload := validPayload("handler-success3@example.com")
	payload["salt"] = "not b64"
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterSuccessDupe(t *testing.T) {
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success5@example.com")
	payload := validPayload("handler-success5@example.com")
	w := postRegister(t , router , payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 , got %d: %s" , w.Code , w.Body.String())
	}
	w2 := postRegister(t , router , payload)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 , got %d: %s" , w.Code , w.Body.String())
	}
}
func TestRegisterWrongWrappedKeyLengths(t *testing.T) {
	router, _ := setupRouter(t)
	for _, field := range []string{"wrapped_vault_key", "recovery_wrapped_key", "recovery_auth_hash"} {
		payload := validPayload("handler-wrapped@example.com")
		payload[field] = b64(3)
		if w := postRegister(t, router, payload); w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", field, w.Code, w.Body.String())
		}
	}
}
