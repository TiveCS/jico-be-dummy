package usecases

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"login-api-jwt/bin/modules/connection"
	"login-api-jwt/bin/modules/webhook"
	"login-api-jwt/bin/modules/webhook/models"
	"login-api-jwt/bin/pkg/utils"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type CommandUsecase struct {
	ConnectionRepositoryQuery connection.RepositoryQuery
}

func NewCommandUsecase(c connection.RepositoryQuery) webhook.UsecaseCommand {
	return &CommandUsecase{
		ConnectionRepositoryQuery: c,
	}
}

// Listen implements webhook.UsecaseCommand.
func (c *CommandUsecase) Listen(ctx *gin.Context) {
	var result = utils.ResultNotificationResponse{
		Code:         http.StatusInternalServerError,
		Data:         nil,
		PostResponse: nil,
		Message:      "Failed Post Notification",
		Status:       false,
	}

	id := ctx.Param("connectionId")

	println("ID: " + id)

	var preparedData models.WebhookPayload = models.WebhookPayload{}

	var payload interface{}

	// Bind request body to the data struct
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		println("Error:" + err.Error())
		result.Code = http.StatusBadRequest
		result.Message = err.Error()
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	preparedData.Payload = payload

	// Call FindOneByID method to retrieve connection data by ID
	ret := c.ConnectionRepositoryQuery.FindOneByID(ctx, id)

	// If there was an error during query, abort with a Bad Request status
	if ret.DB.Error != nil {
		if errors.Is(ret.DB.Error, gorm.ErrRecordNotFound) {
			// If data is not found in the database, abort with status Unauthorized
			result.Code = http.StatusNotFound
			result.Message = "Data not found"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	var connectionInfo []map[string]interface{} = ret.Data.([]map[string]interface{})

	targetUrl := connectionInfo[0]["webhook"].(string)

	preparedData.WebhookUrl = targetUrl

	preparedDataBytes, err := json.Marshal(preparedData)
	if err != nil {
		ctx.Error(err)
		result.Message = "Marshal Payload failed"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	resp, err := http.Post(os.Getenv("NOTIFICATION_URL"), "application/json", bytes.NewBuffer(preparedDataBytes))
	if err != nil {
		ctx.Error(err)
		result.Message = "Send Request to Target Failed"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		ctx.Error(err)
		result.PostResponse = responseBody
		result.Message = "Send Request to Target Failed"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	defer resp.Body.Close()

	result.Code = http.StatusAccepted
	result.Data = preparedData
	result.PostResponse = responseBody
	result.Message = "Success Post Notification"
	result.Status = true

	ctx.JSON(result.Code, result)
}
