package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"linux-firewall-backend/pkg/api/handlers"
	"linux-firewall-backend/pkg/config"
	"linux-firewall-backend/pkg/firewall"
	"linux-firewall-backend/pkg/audit"
	"linux-firewall-backend/pkg/middleware"
	"linux-firewall-backend/pkg/storage"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewAuditLogger(cfg.AuditLogPath)
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}
	defer auditLogger.Close()

	// Initialize storage
	store, err := storage.NewRuleStore(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Initialize firewall engine
	ctx := context.Background()
	engine, err := firewall.NewNftablesEngine(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize nftables engine: %v", err)
	}

	// Create Echo instance
	e := echo.New()

	// Middleware
	e.Use(echoMiddleware.Recover())
	e.Use(echoMiddleware.Logger())
	e.Use(echoMiddleware.CORSWithConfig(echoMiddleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:5173"}, // Adjust for production
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders: []string{echo.HeaderAuthorization, echo.HeaderContentType},
	}))
	e.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	e.Use(middleware.RateLimitMiddleware(100, 1*time.Minute)) // 100 requests per minute
	e.Use(middleware.AuditMiddleware(auditLogger))

	// Register handlers
	ruleHandler := handlers.NewRuleHandler(store, engine, auditLogger)

	api := e.Group("/api/v1")

	// Public endpoint
	api.GET("/health", handlers.HealthCheck)

	// Protected endpoints
	rules := api.Group("/rules")
	{
		rules.GET("", ruleHandler.ListRules)
		rules.GET("/:id", ruleHandler.GetRule)
		rules.POST("", ruleHandler.CreateRule)
		rules.PUT("/:id", ruleHandler.UpdateRule)
		rules.DELETE("/:id", ruleHandler.DeleteRule)
		rules.POST("/:id/toggle", ruleHandler.ToggleRule)
		rules.GET("/:id/counters", ruleHandler.GetCounts)
	}

	// Graceful shutdown
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
		<-sigchan

		log.Println("Shutting down server...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := e.Shutdown(shutdownCtx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}

		// Clean up engine
		engine.Cleanup()
	}()

	// Start server
	addr := ":" + cfg.ServerPort
	log.Printf("Server starting on %s", addr)
	if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
