package database

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect() (*gorm.DB , error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Warning: no .env file found: " , err)
	}

	dsn := fmt.Sprintf("host=localhost user=%s password=%s dbname=%s port=5432 sslmode=disable" ,
	os.Getenv("POSTGRES_USER") , os.Getenv("POSTGRES_PASSWORD") , os.Getenv("POSTGRES_DB"))
	db , err := gorm.Open(postgres.Open(dsn) , &gorm.Config{})
	if err != nil {
		return nil ,err
	}
	return db , nil
}

func Ping(db *gorm.DB) error {
    sqlDB, err := db.DB()
    if err != nil {
        return err 
    }
	err = sqlDB.Ping()	
	if err != nil {
		return err 
	}
	return nil
}
