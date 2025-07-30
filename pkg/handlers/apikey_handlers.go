package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/andrescris/apiKeyService/pkg/common"

	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/auth"
	"github.com/andrescris/firestore/lib/firebase/firestore"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateAPIKeyHandler genera una clave avanzada asociándola a un usuario y proyecto.
func CreateAPIKeyHandler(c *gin.Context) {
	// 1. Vincular y validar el cuerpo de la petición.
	var requestBody struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		UserID      string   `json:"userId" binding:"required"`
		Environment string   `json:"environment"`
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	ctx := context.Background()

	// 2. Obtener datos del usuario desde Auth y Firestore.
	userRecord, err := auth.GetUser(ctx, requestBody.UserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User specified not found in Firebase Auth"})
		return
	}

	queryOptions := firebase.QueryOptions{
		Filters: []firebase.QueryFilter{
			{Field: "user_id", Operator: "==", Value: requestBody.UserID},
		},
		Limit: 1,
	}
	profiles, err := firestore.QueryDocuments(ctx, "profiles", queryOptions)
	if err != nil || len(profiles) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User profile not found in Firestore"})
		return
	}
	projectID, _ := profiles[0].Data["project_id"].(string)

	// 3. Generar los componentes de la clave.
	docID := uuid.New().String()
	apiKey, _ := common.GenerateSecureKey(24)
	apiSecret, _ := common.GenerateSecureKey(32)
	hashedSecret, _ := common.HashSecret(apiSecret)

	// 4. Construir el objeto completo de la API Key.
	newKey := common.APIKeyData{
		ID:           docID,
		Name:         requestBody.Name,
		Description:  requestBody.Description,
		ProjectID:    projectID,
		APIKey:       "ak_" + apiKey,
		HashedSecret: hashedSecret,
		UserID:       requestBody.UserID,
		UserEmail:    userRecord.Email,
		Status:       "active",
		Environment:  requestBody.Environment,
		Permissions:  requestBody.Permissions,
		RateLimits:   common.RateLimits{RequestsPerMinute: 60},
		Usage:        common.Usage{TotalRequests: 0},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// 5. Convertir la struct a un mapa para guardarlo en Firestore.
	jsonBytes, err := json.Marshal(newKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process key data"})
		return
	}
	var dataMap map[string]interface{}
	json.Unmarshal(jsonBytes, &dataMap)

	// Añadir manualmente el hash al mapa, ya que `json:"-"` lo omite.
	dataMap["hashedSecret"] = newKey.HashedSecret

	// 6. Guardar el nuevo documento de la clave.
	if err := firestore.CreateDocumentWithID(ctx, "api_keys_v2", newKey.ID, dataMap); err != nil {
		log.Printf("Error saving API key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save API key"})
		return
	}

	// 7. Devolver la respuesta exitosa.
	c.JSON(http.StatusCreated, gin.H{
		"success":    true,
		"message":    "API Key created successfully",
		"warning":    "⚠️ Save the API Secret securely. It will not be shown again!",
		"data":       newKey, // Se devuelve la struct segura (sin el hash)
		"api_secret": "as_" + apiSecret,
	})
}

// AdminDashboardHandler es un handler de ejemplo para una ruta protegida.
func AdminDashboardHandler(c *gin.Context) {
	userID, _ := c.Get("userId")
	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to the protected admin area!",
		"userId":  userID,
	})
}

func AssignAPIKeyToUserHandler(c *gin.Context) {
	// 1. Obtener parámetros de la petición
	uid := c.Param("uid")
	var requestBody struct {
		APIKey string `json:"apiKey" binding:"required"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: apiKey is required in body"})
		return
	}

	ctx := context.Background()

	// 2. Validar que el usuario de Firebase Auth exista
	if _, err := auth.GetUser(ctx, uid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Firebase Auth user not found", "uid": uid})
		return
	}

	// 3. Buscar el perfil del usuario usando firebase.QueryOptions y firebase.QueryFilter
	queryOptions := firebase.QueryOptions{
		// --- CORRECCIÓN FINAL AQUÍ ---
		// El nombre correcto de la struct es QueryFilter
		Filters: []firebase.QueryFilter{
			{Field: "user_id", Operator: "==", Value: uid},
		},
		Limit: 1,
	}

	profiles, err := firestore.QueryDocuments(ctx, "profiles", queryOptions)
	if err != nil || len(profiles) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User profile not found in Firestore", "uid": uid})
		return
	}
	userProfile := profiles[0]

	// 4. Extraer el project_id y validar la API Key
	projectID, ok := userProfile.Data["project_id"].(string)
	if !ok || projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User profile does not have a valid project_id"})
		return
	}

	apiKeyDoc, err := firestore.GetDocument(ctx, "api_keys", requestBody.APIKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API Key not found", "apiKey": requestBody.APIKey})
		return
	}
	if _, assigned := apiKeyDoc.Data["userId"]; assigned {
		c.JSON(http.StatusConflict, gin.H{"error": "API Key is already assigned to a user"})
		return
	}

	// 5. Actualizar el documento de la API Key
	updateData := map[string]interface{}{
		"userId":   uid,
		"clientId": projectID,
		"status":   "assigned",
	}
	if err := firestore.UpdateDocument(ctx, "api_keys", requestBody.APIKey, updateData); err != nil {
		log.Printf("Error updating API key document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign API key"})
		return
	}

	// 6. Enviar respuesta de éxito
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "API Key assigned successfully",
		"apiKey":   requestBody.APIKey,
		"userId":   uid,
		"clientId": projectID,
	})
}