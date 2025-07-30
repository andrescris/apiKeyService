package main

import (
	"log"
	"net/http"

	"github.com/andrescris/apiKeyService/pkg/handlers"
	"github.com/andrescris/apiKeyService/pkg/middleware"
	"github.com/andrescris/firestore/lib/firebase" // USAMOS TU LIBRERÍA
	"github.com/gin-gonic/gin"
)

func main() {
	// Inicializar Firebase usando tu librería
	if err := firebase.InitFirebaseFromEnv(); err != nil {
		log.Fatalf("Error initializing Firebase: %v", err)
	}
	defer firebase.Close()

	// Configurar Gin
	r := gin.Default()
	
    // Aquí puedes añadir tu middleware de CORS si lo necesitas

	// Health check en la raíz
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "🔑 API Key Service",
			"status":  "running",
			"project": firebase.GetProjectID(),
		})
	})

	// Configurar rutas
	setupRoutes(r)

	log.Println("🚀 API Key Service iniciado en http://localhost:8081")
	log.Println("📖 Documentación en http://localhost:8081/api/v1/docs")

	r.Run(":8081")
}

func setupRoutes(r *gin.Engine) {
	// Rutas de API v1
	api := r.Group("/api/v1")
	{
		// === API KEYS (Público) ===
		// Endpoint para que los clientes soliciten una nueva clave
		api.POST("/keys", handlers.CreateAPIKeyHandler)
		api.POST("/users/:uid/assign-key", handlers.AssignAPIKeyToUserHandler)


		// === ADMIN (Protegido) ===
		// Grupo de rutas que requieren una API Key válida
		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware("read:admin"))
    {
        admin.GET("/dashboard", handlers.AdminDashboardHandler)
    }

		// === UTILIDADES ===
		api.GET("/docs", handlers.APIDocsHandler)
	}
}