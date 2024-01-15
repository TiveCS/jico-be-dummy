package handlers

import (
	"login-api-jwt/bin/modules/messageprovider"
	"login-api-jwt/bin/pkg/servers"
	"login-api-jwt/bin/pkg/utils"
)

type MessageProviderHttpHandler struct {
	MessageProviderUsecaseQuery   messageprovider.UsecaseQuery
	MessageProviderUsecaseCommand messageprovider.UsecaseCommand
}

func InitMessageProviderHTTPHandler(uq messageprovider.UsecaseQuery, uc messageprovider.UsecaseCommand, s *servers.GinServer) {
	// Create an instance of MessageProviderHttpHandler with provided use cases
	handler := &MessageProviderHttpHandler{
		MessageProviderUsecaseQuery:   uq,
		MessageProviderUsecaseCommand: uc,
	}

	s.Gin.GET("/message-provider/", handler.MessageProviderUsecaseQuery.GetAccess)
	s.Gin.GET("/message-provider/all", handler.MessageProviderUsecaseQuery.GetAll)
	s.Gin.GET("/message-provider/id/:id", handler.MessageProviderUsecaseQuery.GetByID)
	s.Gin.GET("/message-provider/id/connected/:id", handler.MessageProviderUsecaseQuery.GetConnectedByID)
	// s.Gin.GET("/message-provider/user/:id", handler.MessageProviderUsecaseQuery.GetUserOwned)
	s.Gin.GET("/message-provider/user/connected/owned", utils.JWTAuthVerifyToken, handler.MessageProviderUsecaseQuery.GetConnectedUserOwned)
	s.Gin.GET("/message-provider/owned", utils.JWTAuthVerifyToken, handler.MessageProviderUsecaseQuery.GetUserOwned)
	s.Gin.POST("/message-provider/new", utils.JWTAuthVerifyToken, handler.MessageProviderUsecaseCommand.PostMessageProvider)
	s.Gin.POST("/message-provider/webhook", handler.MessageProviderUsecaseCommand.SendNotification)
	s.Gin.PUT("/message-provider/edit/:id", utils.JWTAuthVerifyToken, handler.MessageProviderUsecaseCommand.PutMessageProvider)
	s.Gin.DELETE("/message-provider/id/:id", utils.JWTAuthVerifyToken, handler.MessageProviderUsecaseCommand.DeleteMessageProvider)
}
