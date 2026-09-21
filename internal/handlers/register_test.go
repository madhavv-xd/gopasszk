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

func TestRegisterSuccess(t *testing.T) {
	salt := make([]byte, 16)
	authHash := make([]byte, 32)
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success@example.com")
	payload := map[string]string{
		"email":     "handler-success@example.com",
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"auth_hash": base64.StdEncoding.EncodeToString(authHash),
	}
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
	salt := make([]byte, 3)
	authHash := make([]byte, 32)
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success2@example.com")
	payload := map[string]string{
		"email":     "handler-success2@example.com",
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"auth_hash": base64.StdEncoding.EncodeToString(authHash),
	}
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterWrongAuthHashLength(t *testing.T) {
	salt := make([]byte, 16)
	authHash := make([]byte, 3)
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success3@example.com")
	payload := map[string]string{
		"email":     "handler-success3@example.com",
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"auth_hash": base64.StdEncoding.EncodeToString(authHash),
	}
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterMissingEmail(t *testing.T) {
	salt := make([]byte, 16)
	authHash := make([]byte, 32)
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "")
	payload := map[string]string{
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"auth_hash": base64.StdEncoding.EncodeToString(authHash),
	}
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterBadBase64(t *testing.T) {
	salt := "not b64"
	authHash := make([]byte, 32)
	router , _:= setupRouter(t)
		payload := map[string]string{
		"email":     "handler-success3@example.com" ,
		"salt":     salt,
		"auth_hash": base64.StdEncoding.EncodeToString(authHash),
	}
	w := postRegister(t , router , payload)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 , got %d: %s" , w.Code , w.Body.String())
	}
}

func TestRegisterSuccessDupe(t *testing.T) {
	salt := make([]byte, 16)
	authHash := make([]byte, 32)
	router , db := setupRouter(t)
	defer cleanupUser(t , db , "handler-success5@example.com")
	payload := map[string]string{
		"email":     "handler-success5@example.com",
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"auth_hash": base64.StdEncoding.EncodeToString(authHash),
	}
	w := postRegister(t , router , payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 , got %d: %s" , w.Code , w.Body.String())
	}
	w2 := postRegister(t , router , payload)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 , got %d: %s" , w.Code , w.Body.String())
	}
}