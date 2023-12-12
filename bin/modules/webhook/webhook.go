package webhook

import "github.com/gin-gonic/gin"

type UsecaseQuery interface {
	GetListenerURL(ctx *gin.Context)
}

type UsecaseCommand interface {
	Listen(ctx *gin.Context)
}
