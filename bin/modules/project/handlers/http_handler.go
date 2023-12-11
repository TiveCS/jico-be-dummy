package handlers

import (
	"login-api-jwt/bin/modules/project"
	"login-api-jwt/bin/pkg/servers"
	"login-api-jwt/bin/pkg/utils"
)

type ProjectHttpHandler struct {
	ProjectUsecaseQuery   project.UsecaseQuery
	ProjectUsecaseCommand project.UsecaseCommand
}

func InitProjectHTTPHandler(uq project.UsecaseQuery, uc project.UsecaseCommand, s *servers.GinServer) {
	// Create an instance of ProjectHttpHandler with provided use cases
	handler := &ProjectHttpHandler{
		ProjectUsecaseQuery:   uq,
		ProjectUsecaseCommand: uc,
	}

	// Define and register various routes and their corresponding handlers
	// These routes are associated with different project-related operations
	s.Gin.GET("/project", handler.ProjectUsecaseQuery.GetAccess)
	s.Gin.GET("/project/all", handler.ProjectUsecaseQuery.GetAll)
	s.Gin.GET("/project/id/:id", handler.ProjectUsecaseQuery.GetByID)
	s.Gin.GET("/project/id/connected/:id", utils.JWTAuthVerifyToken, handler.ProjectUsecaseQuery.GetConnectedByID)
	s.Gin.GET("/project/user/:id", utils.JWTAuthVerifyToken, handler.ProjectUsecaseQuery.GetUserOwned)
	s.Gin.GET("/project/user/connected/:id", utils.JWTAuthVerifyToken, handler.ProjectUsecaseQuery.GetConnectedUserOwned)
	s.Gin.POST("/project/new", utils.JWTAuthVerifyToken, handler.ProjectUsecaseCommand.PostProject)
	s.Gin.PUT("/project/edit/:id", utils.JWTAuthVerifyToken, handler.ProjectUsecaseCommand.PutProject)
	s.Gin.DELETE("/project/id/:id", utils.JWTAuthVerifyToken, handler.ProjectUsecaseCommand.DeleteProject)
}
