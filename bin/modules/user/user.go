package user

import (
	"login-api-jwt/bin/modules/user/models"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

type UsecaseQuery interface {
	GetByID(ctx *gin.Context)
	GetAccess(ctx *gin.Context)
	GetByUsername(ctx *gin.Context)
	GetByEmail(ctx *gin.Context)
	GetAll(ctx *gin.Context)
}

type UsecaseCommand interface {
	PostRegister(ctx *gin.Context)
	PostLogin(ctx *gin.Context)
	DeleteUser(ctx *gin.Context)
}

type RepositoryQuery interface {
	FindOneByID(ctx *gin.Context, id string) utils.Result
	FindAll(ctx *gin.Context, skip, limit int) utils.Result
	FindOneByUsername(ctx *gin.Context, username string) utils.Result
	FindOneByEmail(ctx *gin.Context, username string) utils.Result

	CountData(ctx *gin.Context) utils.Result
}

type RepositoryCommand interface {
	Create(ctx *gin.Context, u models.User) utils.Result
	Save(ctx *gin.Context, u models.User) utils.Result
	FindPassword(ctx *gin.Context, u string) utils.FindPasswordResult
	Delete(ctx *gin.Context, id string) utils.Result
}
