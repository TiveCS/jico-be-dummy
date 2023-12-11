package servers

import (
	"errors"
	"fmt"
	"log"
	"login-api-jwt/bin/pkg/databases"
	"net/http"

	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
)

// make new gin server struct
type GinServer struct {
	Gin *gin.Engine
}

// initiate new gin server
func (s *GinServer) InitGin() *GinServer {
	g := gin.Default()
	g.Use(CORSMiddleware()) // make new gin instance
	s.Gin = g               // assign new gin instace from g variable
	return s                // return new gin server
}

// ready
func (s *GinServer) Ready() bool {
	return s.Gin != nil // if GinServer instance have no engine, return false
}

func (s *GinServer) Start(port string, db *databases.ORM) error {
	if !s.Ready() && !db.Ready() {
		return errors.New("server isn't ready - make sure to init db and gin")
	}

	// Setup the endpoint
	endpoint := "0.0.0.0:" + port

	// s.Gin.Use(cors.Default())

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "https://jico-api.up.railway.app/"} // Replace with your frontend origin
	config.AllowCredentials = true

	config.AllowHeaders = []string{"Content-Type", "Authorization", "Origin", "Accept", "Access-Control-Allow-Origin", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Credentials"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

	s.Gin.Use(cors.New(config))

	// Create a message indicating server startup
	startupMessage := fmt.Sprintf("Server is running on %s", endpoint)
	log.Println(startupMessage) // Log the startup message
	if err := http.ListenAndServe(endpoint, s.Gin.Handler()); err != nil {
		log.Fatal(err)
	}
	return nil
}

func CORSMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("Access-Control-Allow-Origin", "*")
		fmt.Println("check cors ok")
		ctx.Next()
	}
}
