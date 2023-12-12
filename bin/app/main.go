package main

import (
	userHandler "login-api-jwt/bin/modules/user/handlers"
	userRepositoryCommands "login-api-jwt/bin/modules/user/repositories/commands"
	userRepositoryQueries "login-api-jwt/bin/modules/user/repositories/queries"
	userUsecases "login-api-jwt/bin/modules/user/usecases"
	"net/http"

	projectHandler "login-api-jwt/bin/modules/project/handlers"
	projectRepositoryCommands "login-api-jwt/bin/modules/project/repositories/commands"
	projectRepositoryQueries "login-api-jwt/bin/modules/project/repositories/queries"
	projectUsecases "login-api-jwt/bin/modules/project/usecases"

	messageproviderHandler "login-api-jwt/bin/modules/messageprovider/handlers"
	messageproviderRepositoryCommands "login-api-jwt/bin/modules/messageprovider/repositories/commands"
	messageproviderRepositoryQueries "login-api-jwt/bin/modules/messageprovider/repositories/queries"
	messageproviderUsecases "login-api-jwt/bin/modules/messageprovider/usecases"

	connectionHandler "login-api-jwt/bin/modules/connection/handlers"
	connectionRepositoryCommands "login-api-jwt/bin/modules/connection/repositories/commands"
	connectionRepositoryQueries "login-api-jwt/bin/modules/connection/repositories/queries"
	connectionUsecases "login-api-jwt/bin/modules/connection/usecases"

	webhookHandler "login-api-jwt/bin/modules/webhook/handlers"
	webhookUsecases "login-api-jwt/bin/modules/webhook/usecases"

	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/servers"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	godotenv.Load()

	// Create instance of Gin server
	srv := &servers.GinServer{}
	orm := &databases.ORM{}
	// userHandler := &handlers.UserServer{}

	// Get dsn from environment variables
	dsn := os.Getenv("DB_DSN")

	// Initialize Gin server
	srv.InitGin()
	orm.InitDB(dsn)
	// srv.InitTryRoutes()

	// Set up HTTP routes(orm) and handlers(srv)
	srv.Gin.GET("/", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "This service already running"})
	})
	setUserHTTP(orm, srv)
	setProjectHTTP(orm, srv)
	setMessageProviderHTTP(orm, srv)
	setConnectionHTTP(orm, srv)
	setWebhookHTTP(orm, srv)

	// Get port from environment variables, or use default port 8050
	defaultPort := "8050"
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// Start Gin server on given port
	err := srv.Start(port, orm)

	if err != nil {
		panic(err)
	}
}

func setUserHTTP(orm *databases.ORM, srv *servers.GinServer) {
	// Create a user query repository and use case for reading user data
	userQueryRepository := userRepositoryQueries.NewQueryRepository(orm)
	userQueryUsecase := userUsecases.NewQueryUsecase(userQueryRepository, orm)

	// Create a user command repository and use case for writing user data
	userCommandRepository := userRepositoryCommands.NewCommandRepository(orm)
	userCommandUsecase := userUsecases.NewCommandUsecase(userCommandRepository, orm)

	// Initialize user HTTP handlers with query and command use cases, and link them with the Gin server
	userHandler.InitUserHTTPHandler(userQueryUsecase, userCommandUsecase, srv)
}

func setProjectHTTP(orm *databases.ORM, srv *servers.GinServer) {
	// Create a user query repository and use case for reading project data
	projectQueryRepository := projectRepositoryQueries.NewQueryRepository(orm)
	projectQueryUsecase := projectUsecases.NewQueryUsecase(projectQueryRepository, orm)

	// Create a project command repository and use case for writing project data
	projectCommandRepository := projectRepositoryCommands.NewCommandRepository(orm)
	projectCommandUsecase := projectUsecases.NewCommandUsecase(projectCommandRepository, orm)

	// Initialize project HTTP handlers with query and command use cases, and link them with the Gin server
	projectHandler.InitProjectHTTPHandler(projectQueryUsecase, projectCommandUsecase, srv)
}

func setMessageProviderHTTP(orm *databases.ORM, srv *servers.GinServer) {
	// Create a user query repository and use case for reading messageprovider data
	messageproviderQueryRepository := messageproviderRepositoryQueries.NewQueryRepository(orm)
	messageproviderQueryUsecase := messageproviderUsecases.NewQueryUsecase(messageproviderQueryRepository, orm)

	// Create a messageprovider command repository and use case for writing messageprovider data
	messageproviderCommandRepository := messageproviderRepositoryCommands.NewCommandRepository(orm)
	messageproviderCommandUsecase := messageproviderUsecases.NewCommandUsecase(messageproviderCommandRepository, orm)

	// Initialize messageprovider HTTP handlers with query and command use cases, and link them with the Gin server
	messageproviderHandler.InitMessageProviderHTTPHandler(messageproviderQueryUsecase, messageproviderCommandUsecase, srv)
}

func setConnectionHTTP(orm *databases.ORM, srv *servers.GinServer) {
	// Create a user query repository and use case for reading connection data
	connectionQueryRepository := connectionRepositoryQueries.NewQueryRepository(orm)
	connectionQueryUsecase := connectionUsecases.NewQueryUsecase(connectionQueryRepository, orm)

	// Create a connection command repository and use case for writing connection data
	connectionCommandRepository := connectionRepositoryCommands.NewCommandRepository(orm)
	connectionCommandUsecase := connectionUsecases.NewCommandUsecase(connectionCommandRepository, connectionQueryRepository, orm)

	// Initialize connection HTTP handlers with query and command use cases, and link them with the Gin server
	connectionHandler.InitConnectionHTTPHandler(connectionQueryUsecase, connectionCommandUsecase, srv)
}

func setWebhookHTTP(orm *databases.ORM, srv *servers.GinServer) {
	// Initialize webhook HTTP handlers with query and command use cases, and link them with the Gin server
	connectionQueryRepository := connectionRepositoryQueries.NewQueryRepository(orm)

	webhookQueryUsecase := webhookUsecases.NewQueryUsecase(connectionQueryRepository)
	webhookCommandUsecase := webhookUsecases.NewCommandUsecase(connectionQueryRepository)

	webhookHandler.InitWebhookHTTPHandler(webhookQueryUsecase, webhookCommandUsecase, srv)
}
