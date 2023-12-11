package servers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *GinServer) HandleGetInit(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"message": "access success"})
}

func (s *GinServer) InitTryRoutes() {
	s.Gin.GET("/", s.HandleGetInit)
}
