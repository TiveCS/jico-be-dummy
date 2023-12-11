package models

import (
	messageProviderModels "login-api-jwt/bin/modules/messageprovider/models"
	projectModels "login-api-jwt/bin/modules/project/models"
)

type Connection struct {
	ConnectionID                string                                `json:"id" gorm:"primaryKey;column:connection_id"`
	ConnectionProjectID         string                                `json:"project_id" form:"project_id"`
	ConnectionMessageProviderID string                                `json:"message_provider_id" form:"message_provider_id"`
	MessageProvider             messageProviderModels.MessageProvider `gorm:"foreignkey:ConnectionMessageProviderID"`
	Project                     projectModels.Project                 `gorm:"foreignkey:ConnectionMessageProviderID"`
}

type UpsertConnection struct {
	ConnectionProjectID         string `json:"project_id" form:"project_id"`
	ConnectionMessageProviderID string `json:"message_provider_id" form:"message_provider_id"`
}

func (p Connection) UpsertConnection() UpsertConnection {
	return UpsertConnection{
		ConnectionMessageProviderID: p.ConnectionMessageProviderID,
		ConnectionProjectID:         p.ConnectionProjectID,
	}
}

type GetConnectionRequest struct {
	ConnectionID string `json:"id"`
}

type GetConnectionResponse struct {
	ConnectionID                string `json:"id"`
	ConnectionProjectID         string `json:"project_id"`
	ConnectionMessageProviderID string `json:"message_provider_id"`
}

type PostConnectionResponse struct {
	ConnectionID                string `json:"id"`
	ConnectionProjectID         string `json:"project_id"`
	ConnectionMessageProviderID string `json:"message_provider_id"`
}
