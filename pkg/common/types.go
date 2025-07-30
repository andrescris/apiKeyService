package common

import "time"

// APIKeyData representa la estructura completa de una API Key.
type APIKeyData struct {
	ID          string      `json:"id" firestore:"id"`
	Name        string      `json:"name" firestore:"name"`
	ProjectID   string      `json:"project_id" firestore:"projectId"` // CAMPO AÑADIDO
	Description string      `json:"description" firestore:"description"`
	APIKey      string      `json:"api_key" firestore:"apiKey"`
	HashedSecret string      `json:"-" firestore:"hashedSecret"` // No se expone en JSON
	UserID      string      `json:"user_id" firestore:"userId"`
	UserEmail   string      `json:"user_email" firestore:"userEmail"`
	Status      string      `json:"status" firestore:"status"`
	Environment string      `json:"environment" firestore:"environment"`
	Permissions []string    `json:"permissions" firestore:"permissions"`
	RateLimits  RateLimits  `json:"rate_limits" firestore:"rateLimits"`
	Usage       Usage       `json:"usage" firestore:"usage"`
	CreatedAt   time.Time   `json:"created_at" firestore:"createdAt"`
	UpdatedAt   time.Time   `json:"updated_at" firestore:"updatedAt"`
}

// RateLimits define las reglas de límite de tasa.
type RateLimits struct {
	RequestsPerMinute int `json:"requests_per_minute" firestore:"requestsPerMinute"`
	RequestsPerHour   int `json:"requests_per_hour" firestore:"requestsPerHour"`
}

// Usage rastrea el uso de la clave.
type Usage struct {
	TotalRequests    int64     `json:"total_requests" firestore:"totalRequests"`
	LastUsedAt       time.Time `json:"-" firestore:"lastUsedAt"` // Solo para uso interno
}