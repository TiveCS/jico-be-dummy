package messageprovider

import (
	"login-api-jwt/bin/modules/messageprovider/models"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

type UsecaseQuery interface {
	GetByID(ctx *gin.Context)
	GetAccess(ctx *gin.Context)
	GetAll(ctx *gin.Context)
	GetUserOwned(ctx *gin.Context)
	GetConnectedByID(ctx *gin.Context)
	GetConnectedUserOwned(ctx *gin.Context)
}

type UsecaseCommand interface {
	PostMessageProvider(ctx *gin.Context)
	PutMessageProvider(ctx *gin.Context)
	DeleteMessageProvider(ctx *gin.Context)
	SendNotification(ctx *gin.Context)
}

type RepositoryQuery interface {
	FindAll(ctx *gin.Context, skip, limit int) utils.Result
	FindOneByID(ctx *gin.Context, id string) utils.Result
	FindConnectedOneByID(ctx *gin.Context, id string) utils.Result
	FindByUserID(ctx *gin.Context, id string, skip, limit int) utils.Result
	FindConnectedByUserID(ctx *gin.Context, id string, skip, limit int) utils.Result
	CountData(ctx *gin.Context) utils.Result
}

type RepositoryCommand interface {
	Create(ctx *gin.Context, u models.MessageProvider) utils.Result
	Save(ctx *gin.Context, u models.MessageProvider) utils.Result
	Updates(ctx *gin.Context, u models.MessageProvider) utils.Result
	Delete(ctx *gin.Context, id string) utils.MultiDataResult
}
