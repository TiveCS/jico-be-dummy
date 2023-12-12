package models

type WebhookPayload struct {
	WebhookUrl string `json:"webhookUrl"`
	Payload    any    `json:"payload"`
}
