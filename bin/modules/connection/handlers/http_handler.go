package handlers

import (
	"login-api-jwt/bin/modules/connection"
	"login-api-jwt/bin/pkg/servers"
)

type ConnectionHttpHandler struct {
	ConnectionUsecaseQuery   connection.UsecaseQuery
	ConnectionUsecaseCommand connection.UsecaseCommand
}

func InitConnectionHTTPHandler(uq connection.UsecaseQuery, uc connection.UsecaseCommand, s *servers.GinServer) {
	// Create an instance of ConnectionHttpHandler with provided use cases
	handler := &ConnectionHttpHandler{
		ConnectionUsecaseQuery:   uq,
		ConnectionUsecaseCommand: uc,
	}

	// Define and register various routes and their corresponding handlers
	// These routes are associated with different connection-related operations
	s.Gin.GET("/connection/", handler.ConnectionUsecaseQuery.GetAccess)
	s.Gin.GET("/connection/all", handler.ConnectionUsecaseQuery.GetAll)
	s.Gin.GET("/connection/id/:id", handler.ConnectionUsecaseQuery.GetByID)
	s.Gin.GET("/connection/project/:id", handler.ConnectionUsecaseQuery.GetByProjectID)
	s.Gin.GET("/connection/message-provider/:id", handler.ConnectionUsecaseQuery.GetBYMessageProviderID)
	s.Gin.POST("/connection/new", handler.ConnectionUsecaseCommand.PostConnection)
	s.Gin.PUT("/connection/edit/:id", handler.ConnectionUsecaseCommand.PutConnection)
	s.Gin.DELETE("/connection/id/:id", handler.ConnectionUsecaseCommand.DeleteConnection)
}
