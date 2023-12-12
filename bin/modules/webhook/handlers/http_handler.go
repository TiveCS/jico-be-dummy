package handlers

import (
	"login-api-jwt/bin/modules/webhook"
	"login-api-jwt/bin/pkg/servers"
)

type WebhookHttpHandler struct {
	WebhookUsecaseQuery   webhook.UsecaseQuery
	WebhookUsecaseCommand webhook.UsecaseCommand
}

func InitWebhookHTTPHandler(uq webhook.UsecaseQuery, uc webhook.UsecaseCommand, s *servers.GinServer) {
	// Create an instance of ConnectionHttpHandler with provided use cases
	handler := &WebhookHttpHandler{
		WebhookUsecaseQuery:   uq,
		WebhookUsecaseCommand: uc,
	}

	// Define and register various routes and their corresponding handlers
	// These routes are associated with different connection-related operations
	s.Gin.GET("/webhook/:connectionId", handler.WebhookUsecaseQuery.GetListenerURL)
	s.Gin.POST("/webhook/:connectionId/listen", handler.WebhookUsecaseCommand.Listen)
}
