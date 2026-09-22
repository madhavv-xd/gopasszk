package handlers

import "gorm.io/gorm"

type Handler struct {
	DB *gorm.DB
	Secret []byte 
}