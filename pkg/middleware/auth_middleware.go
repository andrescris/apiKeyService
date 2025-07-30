package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	gfs "cloud.google.com/go/firestore" // Alias para el cliente oficial
	"github.com/andrescris/apiKeyService/pkg/common"
	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/firestore"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		apiSecret := c.GetHeader("X-API-Secret") // Esto tiene el prefijo "as_"

		// ... (código para buscar la clave no cambia) ...
		opts := firebase.QueryOptions{
			Filters: []firebase.QueryFilter{{Field: "api_key", Operator: "==", Value: apiKey}},
			Limit:   1,
		}
		keys, err := firestore.QueryDocuments(context.Background(), "api_keys_v2", opts)
		if err != nil || len(keys) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API Key"})
			return
		}
		keyDoc := keys[0]

		// --- CORRECCIÓN FINAL AQUÍ ---
		// 1. Quitamos el prefijo "as_" del secreto que nos envió el usuario.
		secretWithoutPrefix := strings.TrimPrefix(apiSecret, "as_")

		// 2. Validamos el secreto y el estado
		hashedSecret := keyDoc.Data["hashedSecret"].(string)
		// 3. Usamos el secreto SIN prefijo para la comparación.
		if !common.CheckSecretHash(secretWithoutPrefix, hashedSecret) || keyDoc.Data["status"] != "active" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials or inactive key"})
			return
		}

		// ... (el resto del middleware no cambia)
		permissions, _ := keyDoc.Data["permissions"].([]interface{})
		hasPermission := false
		for _, p := range permissions {
			if p.(string) == requiredPermission {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		go func() {
			updateData := []gfs.Update{
				{Path: "usage.totalRequests", Value: gfs.Increment(1)},
				{Path: "usage.lastUsedAt", Value: time.Now()},
			}
			firestore.UpdateDocumentFields(context.Background(), "api_keys_v2", keyDoc.ID, updateData)
		}()

		c.Set("userId", keyDoc.Data["user_id"])
		c.Next()
	}
}