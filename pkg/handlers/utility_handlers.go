package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// APIDocsHandler muestra la documentación actualizada de la API de Keys.
func APIDocsHandler(c *gin.Context) {
	docs := `
🔑 API Key Service Documentation

BASE URL: http://localhost:8080/api/v1

---
=== CREACIÓN DE API KEYS (Público) ===

POST /keys          - Crea un nuevo par de API Key y Secret con todas sus propiedades.

  Body (JSON):
  {
      "name": "Mi Clave para App Móvil",
      "description": "Clave con permisos de lectura para la app de iOS.",
      "userId": "oSXtytzfgmMuhYMQKRwhEm5tFIs2",
      "environment": "production",
      "permissions": [
          "read:documents",
          "read:admin"
      ]
  }

---
=== RUTAS PROTEGIDAS ===

Estos endpoints requieren los encabezados X-API-Key y X-API-Secret, y que la clave tenga los permisos adecuados.

GET /admin/dashboard - Endpoint de ejemplo que requiere el permiso "read:admin".

---
=== UTILIDADES ===

GET /docs            - Muestra esta documentación.
`

	c.String(http.StatusOK, docs)
}