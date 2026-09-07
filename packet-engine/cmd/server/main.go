package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/netguard/packet-engine/internal/health"
	"github.com/netguard/packet-engine/internal/parser"
)

func main() {
	port := os.Getenv("PACKET_ENGINE_PORT")
	if port == "" {
		port = "8001"
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	health.RegisterRoutes(r)
	parser.RegisterRoutes(r)

	addr := fmt.Sprintf(":%s", port)
	log.Printf("NETGUARD Packet Engine starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
