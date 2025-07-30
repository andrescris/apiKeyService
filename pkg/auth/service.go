package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"cloud.google.com/go/firestore"
	"golang.org/x/crypto/bcrypt"
)

// APIKeyData representa la estructura de una API Key en Firestore.
type APIKeyData struct {
	APIKey       string    `firestore:"apiKey"`
	HashedSecret string    `firestore:"hashedSecret"`
	ClientID     string    `firestore:"clientId"`
	Status       string    `firestore:"status"`
	CreatedAt    time.Time `firestore:"createdAt"`
}

// AuthService encapsula la lógica de autenticación.
type AuthService struct {
	firestoreClient *firestore.Client
	collectionName  string
}

// NewService crea una nueva instancia del servicio de autenticación.
func NewService() *AuthService {
	// ... (código de inicialización de Firestore sin cambios)
	ctx := context.Background()
	client, err := firestore.NewClient(ctx, "tu-proyecto-de-firebase")
	if err != nil {
		log.Fatalf("Failed to create Firestore client: %v", err)
	}
	return &AuthService{
		firestoreClient: client,
		collectionName:  "api_keys",
	}
}

// CreateNewKey genera, hashea y guarda una nueva API key.
func (s *AuthService) CreateNewKey(ctx context.Context, clientID string) (string, string, error) {
	// 1. Generar Key y Secret seguros
	apiKey, err := generateSecureKey(16)
	if err != nil {
		return "", "", err
	}
	apiSecret, err := generateSecureKey(32)
	if err != nil {
		return "", "", err
	}

	// 2. Hashear el Secret para guardarlo
	hashedSecret, err := hashSecret(apiSecret)
	if err != nil {
		return "", "", err
	}

	// 3. Preparar los datos para Firestore
	newKeyData := APIKeyData{
		APIKey:       apiKey,
		HashedSecret: hashedSecret,
		ClientID:     clientID,
		Status:       "active",
		CreatedAt:    time.Now(),
	}

	// 4. Guardar en la base de datos
	_, err = s.firestoreClient.Collection(s.collectionName).Doc(apiKey).Set(ctx, newKeyData)
	if err != nil {
		return "", "", err
	}

	// 5. Devolver la key y el secret en texto plano (solo esta vez)
	return apiKey, apiSecret, nil
}


// ValidateCredentials verifica la key y el secret.
func (s *AuthService) ValidateCredentials(ctx context.Context, apiKey, apiSecret string) (*APIKeyData, error) {
    // ... (código de validación sin cambios)
	doc, err := s.firestoreClient.Collection(s.collectionName).Doc(apiKey).Get(ctx)
	if err != nil {
		return nil, errors.New("invalid API Key")
	}
	var keyData APIKeyData
	doc.DataTo(&keyData)
	if keyData.Status != "active" || !checkSecretHash(apiSecret, keyData.HashedSecret) {
		return nil, errors.New("invalid credentials")
	}
	return &keyData, nil
}


// --- Funciones auxiliares de criptografía ---

func generateSecureKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashSecret(secret string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func checkSecretHash(secret, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	return err == nil
}