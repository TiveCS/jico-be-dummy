package usecases

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"login-api-jwt/bin/modules/messageprovider"
	"login-api-jwt/bin/modules/messageprovider/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CommandUsecase implements messageprovider.UsecaseCommand interface
type CommandUsecase struct {
	MessageProviderRepositoryCommand messageprovider.RepositoryCommand
	ORM                              *databases.ORM
}

// NewCommandUsecase creates a new instance of CommandUsecase
func NewCommandUsecase(q messageprovider.RepositoryCommand, orm *databases.ORM) messageprovider.UsecaseCommand {
	return &CommandUsecase{
		MessageProviderRepositoryCommand: q,
		ORM:                              orm,
	}
}

// PostRegister handles messageprovider registration
func (q CommandUsecase) PostMessageProvider(ctx *gin.Context) {
	var result = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Post Message Provider",
		Status:  false,
	}

	user := ctx.MustGet("user").(jwt.MapClaims)
	var messageProviderModel models.MessageProvider
	err := ctx.ShouldBind(&messageProviderModel)
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
	}
	messageProviderModel.MessageProviderUserID = user["id"].(string)

	// Generate a unique MessageProviderID for messageprovider
	messageProviderModel.MessageProviderID = uuid.NewString()

	// Create messageprovider record in the database

	r := q.MessageProviderRepositoryCommand.Create(ctx, messageProviderModel)
	if r.DB.Error != nil {
		if strings.Contains(r.DB.Error.Error(), "insert or update on table \"message_providers\" violates foreign key constraint \"message_providers_messageProvider_id_fkey\"") {
			// If data is already found, abort with status "email or messageProvidername already used"
			result.Message = "User id not valid"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Response data for successful registration
	messageproviderRegisterResponse := messageProviderModel

	// Save messageprovider record again after successful registration
	r = q.MessageProviderRepositoryCommand.Save(ctx, messageProviderModel)

	// Check if an error occurred while saving
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    messageproviderRegisterResponse,
		Message: "Success Register Data Message Provider",
		Status:  true,
	}
	// If messageprovider record was successfully saved, respond with messageprovider's registration data
	ctx.JSON(http.StatusOK, result)
}

func (q CommandUsecase) PutMessageProvider(ctx *gin.Context) {
	var result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    nil,
		Message: "Failed Post Message Provider",
		Status:  false,
	}

	user := ctx.MustGet("user").(jwt.MapClaims)
	messageProviderID := ctx.Param("id")
	var messageProviderModel models.MessageProvider
	err := ctx.ShouldBind(&messageProviderModel)
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
	}

	messageProviderModel.MessageProviderID = messageProviderID
	messageProviderModel.MessageProviderUserID = user["id"].(string)

	// Response data for successful registration
	Response := messageProviderModel

	r := q.MessageProviderRepositoryCommand.Updates(ctx, Response)
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if r.DB.RowsAffected == 0 {
		// If there was an error, return Internal Server Error with error message
		result.Message = "Message Provider ID not available"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    Response,
		Message: "Success Update MessageProvider",
		Status:  true,
	}
	// If messageprovider record was successfully saved, respond with messageprovider's registration data
	ctx.JSON(result.Code, result)

}

func (q CommandUsecase) DeleteMessageProvider(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Delete MessageProvider",
		Status:  false,
	}

	var id string = ctx.Param("id")

	deletedMessageProvider := q.MessageProviderRepositoryCommand.Delete(ctx, id)
	if deletedMessageProvider.DB[0].Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if deletedMessageProvider.DB[1].Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if deletedMessageProvider.DB[1].RowsAffected == 0 {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusBadRequest
		result.Message = "messageProvider not found"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    deletedMessageProvider.Data,
		Message: "Success Delete MessageProvider",
		Status:  true,
	}
	ctx.JSON(result.Code, result)
}

func (q CommandUsecase) SendNotification(ctx *gin.Context) {
	var jsonData map[string]interface{}
	var result = utils.ResultNotificationResponse{
		Code:         http.StatusInternalServerError,
		Data:         nil,
		PostResponse: nil,
		Message:      "Failed Post Notification",
		Status:       false,
	}

	if err := ctx.BindJSON(&jsonData); err != nil {
		ctx.Error(err)
		result.Message = "bind json failed"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	payloadData := jsonData
	payloadBytes, err := json.Marshal(payloadData)
	if err != nil {
		ctx.Error(err)
		result.Message = "Marshal Payload failed"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	resp, err := http.Post(os.Getenv("NOTIFICATION_URL"), "application/json", bytes.NewBuffer(payloadBytes))
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ctx.Error(err)
		result.PostResponse = responseBody
		result.Message = "Send Request to Target Failed"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	defer resp.Body.Close()

	result.Code = http.StatusAccepted
	result.Data = jsonData
	result.PostResponse = responseBody
	result.Message = "Success Post Notification"
	result.Status = true

	ctx.JSON(result.Code, result)

}
