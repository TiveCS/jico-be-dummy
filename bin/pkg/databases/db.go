package databases

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type ORM struct {
	DB *gorm.DB
}

func (o *ORM) InitDB(dsn string) *ORM {
	db, err := gorm.Open(postgres.Open(dsn)) // make db instance from postgres dsn
	if err != nil {
		log.Fatal(err)
	}

	o.DB = db
	return o
}

// check if database orm ready
func (o *ORM) Ready() bool {
	return o.DB != nil
}
