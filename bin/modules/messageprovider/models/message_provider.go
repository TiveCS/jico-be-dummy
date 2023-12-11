package models

type MessageProvider struct {
	MessageProviderID     string `json:"id" gorm:"primaryKey;column:message_provider_id"`
	MessageProviderUserID string `json:"user_id" form:"user_id"`
	ProviderType          string `json:"provider_type" form:"provider_type"`
	ProviderLabel         string `json:"provider_label" form:"provider_label"`
	Webhook               string `json:"webhook" form:"webhook"`
}

type UpsertMessageProvider struct {
	UserID        string `json:"user_id" form:"user_id"`
	ProviderType  string `json:"provider_type" form:"provider_type"`
	ProviderLabel string `json:"provider_label" form:"provider_label"`
	Webhook       string `json:"webhook" form:"webhook"`
}

func (p MessageProvider) UpsertMessageProvider() UpsertMessageProvider {
	return UpsertMessageProvider{
		UserID:        p.MessageProviderUserID,
		ProviderType:  p.ProviderType,
		ProviderLabel: p.ProviderLabel,
		Webhook:       p.Webhook,
	}
}

type GetMessageProviderRequest struct {
	MessageProviderID string `json:"id"`
}

type GetMessageProviderResponse struct {
	MessageProviderID     string `json:"id"`
	MessageProviderUserID string `json:"user_id" form:"user_id"`
	ProviderType          string `json:"provider_type" form:"provider_type"`
	ProviderLabel         string `json:"provider_label" form:"provider_label"`
	Webhook               string `json:"webhook" form:"webhook"`
}

type PostMessageProviderResponse struct {
	MessageProviderID string `json:"id"`
	UserID            string `json:"user_id"`
	ProviderType      string `json:"provider_type"`
	ProviderLabel     string `json:"provider_label"`
	Webhook           string `json:"webhook"`
}
