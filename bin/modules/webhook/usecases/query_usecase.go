package usecases

import (
	"errors"
	"login-api-jwt/bin/modules/connection"
	"login-api-jwt/bin/modules/webhook"
	"login-api-jwt/bin/pkg/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type QueryUsecase struct {
	ConnectionRepositoryQuery connection.RepositoryQuery
}

func NewQueryUsecase(c connection.RepositoryQuery) webhook.UsecaseQuery {
	return &QueryUsecase{
		ConnectionRepositoryQuery: c,
	}
}

// GetListenerURL implements webhook.UsecaseQuery.
func (q *QueryUsecase) GetListenerURL(ctx *gin.Context) {
	var result = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Get Listener URL",
		Status:  false,
	}

	id := ctx.Param("connectionId")

	// Call FindOneByID method to retrieve connection data by ID
	ret := q.ConnectionRepositoryQuery.FindOneByID(ctx, id)
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

	// Extract connection data from the result
	url := "http://localhost:8080/webhook/" + id + "/listen"
	targetURL := connectionInfo[0]["webhook"].(string)

	// Respond with retrieved connection data in JSON format
	result = utils.ResultResponse{
		Code: http.StatusOK,
		Data: map[string]string{
			"listener_url": url,
			"target_url":   targetURL,
		},
		Message: "Success Get Listener URL",
		Status:  true,
	}

	ctx.JSON(http.StatusOK, result)
}
