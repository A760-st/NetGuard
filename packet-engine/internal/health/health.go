package health

import (
	"net/http"
	"runtime"

	"github.com/gin-gonic/gin"
)

type HealthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Language string `json:"language"`
	GoVersion string `json:"go_version"`
}

const version = "0.1.0"

func RegisterRoutes(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, HealthResponse{
			Status:    "healthy",
			Version:   version,
			Language:  "go",
			GoVersion: runtime.Version(),
		})
	})
}
