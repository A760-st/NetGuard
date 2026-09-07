package parser

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ParseRequest struct {
	FilePath string `json:"file_path" binding:"required"`
}

type ParseResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	FilePath    string `json:"file_path"`
	PacketCount int    `json:"packet_count"`
}

func RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api/v1")
	{
		api.POST("/parse", handleParse)
		api.GET("/parse/status", handleParseStatus)
	}
}

func handleParse(c *gin.Context) {
	var req ParseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, ParseResponse{
		Status:      "not_implemented",
		Message:     "PCAP parsing will be implemented in Phase 2",
		FilePath:    req.FilePath,
		PacketCount: 0,
	})
}

func handleParseStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ready",
		"message": "Packet engine is operational",
	})
}
