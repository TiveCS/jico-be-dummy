package usecases

import (
	"login-api-jwt/bin/modules/connection"
	"login-api-jwt/bin/modules/connection/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CommandUsecase implements connection.UsecaseCommand interface
type CommandUsecase struct {
	ConnectionRepositoryCommand connection.RepositoryCommand
	ORM                         *databases.ORM
}

// NewCommandUsecase creates a new instance of CommandUsecase
func NewCommandUsecase(q connection.RepositoryCommand, query connection.RepositoryQuery, orm *databases.ORM) connection.UsecaseCommand {
	return &CommandUsecase{
		ConnectionRepositoryCommand: q,
		ORM:                         orm,
	}
}

// PostRegister handles connection registration
func (q CommandUsecase) PostConnection(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Post Connection",
		Status:  false,
	}
	var connectionModel models.Connection
	err := ctx.ShouldBind(&connectionModel)
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Generate a unique ConnectionID for connection
	connectionModel.ConnectionID = uuid.NewString()

	// Create connection record in the database
	r := q.ConnectionRepositoryCommand.Create(ctx, connectionModel)
	if r.DB.Error != nil {

		if strings.Contains(r.DB.Error.Error(), "insert or update on table \"connections\" violates foreign key constraint \"connections_connection_project_id_fkey\"") {
			// If data user id not valid return message "user id not valid"
			result.Message = "project id not valid"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		if strings.Contains(r.DB.Error.Error(), "insert or update on table \"connections\" violates foreign key constraint \"connections_connection_message_provider_id_fkey\"") {
			// If data user id not valid return message "user id not valid"
			result.Message = "message_provider id not valid"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}
		if strings.Contains(r.DB.Error.Error(), "duplicate key value violates unique constraint") {
			// If data is not found in the database, abort with status Unauthorized
			result.Code = http.StatusBadRequest
			result.Message = "Connection Exist Already"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, result)
		return
	}

	// Response data for successful registration
	connectionRegisterResponse := models.PostConnectionResponse{
		ConnectionID:                connectionModel.ConnectionID,
		ConnectionMessageProviderID: connectionModel.ConnectionMessageProviderID,
		ConnectionProjectID:         connectionModel.ConnectionProjectID,
	}

	// Save connection record again after successful registration
	r = q.ConnectionRepositoryCommand.Save(ctx, connectionModel)

	// Check if an error occurred while saving
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    connectionRegisterResponse,
		Message: "Success Post Connection",
		Status:  true,
	}
	// If connection record was successfully saved, respond with connection's registration data
	ctx.JSON(http.StatusOK, result)
}

func (q CommandUsecase) PutConnection(ctx *gin.Context) {
	var result = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Update Data Connection",
		Status:  false,
	}

	connectionID := ctx.Param("id")
	var connectionModel models.Connection
	err := ctx.ShouldBind(&connectionModel)
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
	}

	connectionModel.ConnectionID = connectionID

	// Response data for successful registration
	Response := connectionModel

	r := q.ConnectionRepositoryCommand.Updates(ctx, Response)
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if r.DB.RowsAffected == 0 {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusNotFound
		result.Message = "Data not found"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    r.Data,
		Message: "Success Get Data Connection",
		Status:  true,
	}
	// If messageprovider record was successfully saved, respond with messageprovider's registration data
	ctx.JSON(http.StatusOK, Response)

}

func (q CommandUsecase) DeleteConnection(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Delete Connection",
		Status:  false,
	}

	var id string = ctx.Param("id")

	deletedConnection := q.ConnectionRepositoryCommand.Delete(ctx, id)
	if deletedConnection.DB.Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if deletedConnection.DB.RowsAffected == 0 {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusBadRequest
		result.Message = "project not found"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    deletedConnection.Data,
		Message: "Success Delete Connection",
		Status:  true,
	}
	ctx.JSON(result.Code, result)
}
