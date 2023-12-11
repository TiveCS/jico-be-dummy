package connection

import (
	"login-api-jwt/bin/modules/connection/models"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

type UsecaseQuery interface {
	GetByID(ctx *gin.Context)
	GetAccess(ctx *gin.Context)
	GetByProjectID(ctx *gin.Context)
	GetBYMessageProviderID(ctx *gin.Context)
	GetAll(ctx *gin.Context)
}

type UsecaseCommand interface {
	PostConnection(ctx *gin.Context)
	PutConnection(ctx *gin.Context)
	DeleteConnection(ctx *gin.Context)
}

type RepositoryQuery interface {
	FindAll(ctx *gin.Context, skip, limit int) utils.Result
	FindOneByID(ctx *gin.Context, id string) utils.Result
	FindOneByProjectID(ctx *gin.Context, id string) utils.Result
	FindOneByMessageProviderID(ctx *gin.Context, id string) utils.Result
	CountData(ctx *gin.Context) utils.Result
}

type RepositoryCommand interface {
	Create(ctx *gin.Context, u models.Connection) utils.Result
	Save(ctx *gin.Context, u models.Connection) utils.Result
	Updates(ctx *gin.Context, u models.Connection) utils.Result
	Delete(ctx *gin.Context, id string) utils.Result
}
