package utils

import (
	"login-api-jwt/bin/modules/user/models"

	"gorm.io/gorm"
)

type Result struct {
	Data  interface{}
	DB    *gorm.DB
	Error error
}

type MultiDataResult struct {
	Data  interface{}
	DB    []*gorm.DB
	Error error
}

type FindPasswordResult struct {
	Data     models.User
	Password string
	DB       *gorm.DB
	Error    error
}

type ResultResponse struct {
	Code    int         `json:"code"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
	Status  bool        `json:"status"`
}

type ResultNotificationResponse struct {
	Code         int         `json:"code"`
	Data         interface{} `json:"data"`
	PostResponse interface{} `json:"post response"`
	Message      string      `json:"message"`
	Status       bool        `json:"status"`
}

type ResultResponsePagination struct {
	Code      int         `json:"code"`
	Data      interface{} `json:"data"`
	Limit     int         `json:"limit"`
	Page      int         `json:"page"`
	TotalData int         `json:"totalData"`
	TotalPage int         `json:"totalPage"`
	Message   string      `json:"message"`
	Status    bool        `json:"status"`
}
