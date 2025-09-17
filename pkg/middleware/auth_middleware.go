package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	gfs "cloud.google.com/go/firestore"
	"github.com/andrescris/apiKeyService/pkg/common"
	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/auth" // <-- NECESARIO PARA OBTENER EL USUARIO
	"github.com/andrescris/firestore/lib/firebase/firestore"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. API Key & Secret
		apiKey := c.GetHeader("X-API-Key")
		apiSecret := c.GetHeader("X-API-Secret")
		if apiKey == "" || apiSecret == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "X-API-Key and X-API-Secret headers are required"})
			return
		}

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
		secretWithoutPrefix := strings.TrimPrefix(apiSecret, "as_")
		hashedSecret := keyDoc.Data["hashedSecret"].(string)
		if !common.CheckSecretHash(secretWithoutPrefix, hashedSecret) || keyDoc.Data["status"] != "active" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials or inactive key"})
			return
		}

		// 2. Permisos
		permissions, _ := keyDoc.Data["permissions"].([]interface{})
		hasPermission := false
		for _, p := range permissions {
			if p.(string) == requiredPermission {
				hasPermission = true
				break
			}
		}

		// Primero, verificamos si la clave tiene el "super permiso".
		for _, p := range permissions {
			if p.(string) == "super:admin" {
				hasPermission = true
				break
			}
		}

		// Si no tiene el super permiso, verificamos el permiso específico requerido por la ruta.
		if !hasPermission {
			for _, p := range permissions {
				if p.(string) == requiredPermission {
					hasPermission = true
					break
				}
			}
		}

		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		// 3. Extraer subdomain del hostname
		var subdomain string

		// Prioridad #1: La cabecera explícita que tú controlas.
		subdomain = c.GetHeader("X-Client-Subdomain")

		// Prioridad #2 (Fallback): Si la cabecera no existe, intenta con el Host.
		if subdomain == "" {
			host := c.Request.Host
			parts := strings.Split(host, ".")
			// Funciona para sub.dominio.com y sub.localhost
			if len(parts) >= 2 {
				subdomain = parts[0]
			}
		}

		// Si después de ambos intentos sigue vacío, es un error.
		if subdomain == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Subdomain not found in X-Client-Subdomain header or Host"})
			return
		}

		// 4. Validar que el subdomain esté en los claims del usuario
		userID, ok := keyDoc.Data["user_id"].(string)
		if !ok || userID == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "API Key not associated with a user"})
			return
		}

		userRecord, err := auth.GetUser(context.Background(), userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Could not retrieve user data"})
			return
		}

		allowed := false
		if claims := userRecord.CustomClaims; claims != nil {
			if subs, exists := claims["subdomain"]; exists {
				if subList, ok := subs.([]interface{}); ok {
					for _, s := range subList {
						if strings.EqualFold(s.(string), subdomain) {
							allowed = true
							break
						}
					}
				}
			}
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Subdomain not allowed"})
			return
		}

		// 5. Guardar en context
		c.Set("subdomain", subdomain)
		c.Set("userId", userID)
		c.Set("permissions", permissions)

		// 6. Actualizar uso de la clave (igual que antes)
		go func() {
			updateData := []gfs.Update{
				{Path: "usage.totalRequests", Value: gfs.Increment(1)},
				{Path: "usage.lastUsedAt", Value: time.Now()},
			}
			firestore.UpdateDocumentFields(context.Background(), "api_keys_v2", keyDoc.ID, updateData)
		}()

		c.Next()
	}
}
