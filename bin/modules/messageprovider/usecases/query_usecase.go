package usecases

import (
	"errors"
	"fmt"
	"login-api-jwt/bin/modules/messageprovider"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"
	"math"
	"net/http"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// QueryUsecase implements messageprovider.UsecaseQuery interface
type QueryUsecase struct {
	MessageProviderRepositoryQuery messageprovider.RepositoryQuery
	ORM                            *databases.ORM
}

// NewQueryUsecase creates a new instance of QueryUsecase
func NewQueryUsecase(q messageprovider.RepositoryQuery, orm *databases.ORM) messageprovider.UsecaseQuery {
	return &QueryUsecase{
		MessageProviderRepositoryQuery: q,
		ORM:                            orm,
	}
}

// GetByID retrieves messageprovider data by ID and responds with the result
func (q QueryUsecase) GetByID(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Get Provider",
		Status:  false,
	}
	id := ctx.Param("id")

	// Call FindOneByID method to retrieve messageprovider data by ID
	ret := q.MessageProviderRepositoryQuery.FindOneByID(ctx, id)
	// If there was an error during query, abort with a Bad Request status
	if ret.DB.Error != nil {
		if errors.Is(ret.DB.Error, gorm.ErrRecordNotFound) {
			// If data is not found in the database, abort with status Unauthorized
			result.Code = http.StatusNotFound
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}
		ctx.Error(ret.DB.Error)
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Respond with retrieved messageprovider data in JSON format
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    ret.Data,
		Message: "Success Get Provider",
		Status:  true,
	}
	ctx.JSON(http.StatusOK, result)
}

// GetByID retrieves project data by ID and responds with the result
func (q QueryUsecase) GetConnectedByID(ctx *gin.Context) {
	id := ctx.Param("id")

	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Internal Server Error",
		Status:  false,
	}

	// Call FindOneByID method to retrieve project data by ID
	ret := q.MessageProviderRepositoryQuery.FindConnectedOneByID(ctx, id)
	// If there was an error during query, abort with a Bad Request status
	if ret.DB.Error != nil {
		if errors.Is(ret.DB.Error, gorm.ErrRecordNotFound) {
			// If data is not found in the database, abort with status Unauthorized
			result.Code = http.StatusNotFound
			result.Message = fmt.Sprintf("MessageProvider with id %s not found", id)
			ctx.AbortWithStatusJSON(http.StatusNotFound, result)
			return
		}

		result.Code = http.StatusInternalServerError
		ctx.Error(ret.DB.Error)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, result)
		return
	}

	// Respond with retrieved project data in JSON format
	result.Code = http.StatusOK
	result.Data = ret.Data
	result.Message = "Get MessageProvider Connected By ID Success"
	result.Status = true
	ctx.JSON(http.StatusOK, result)
}

// Get All retrieves All messageprovider data with pagination result
func (q QueryUsecase) GetAll(ctx *gin.Context) {
	var totalCount, page, limit int
	var err error

	page, err = strconv.Atoi(ctx.Query("page"))
	// handling when error set default page value 1
	if err != nil || page < 1 {
		page = 1
	}

	// handling when error set default limit value 10
	limit, err = strconv.Atoi(ctx.Query("limit"))
	if err != nil || limit == 0 {
		limit = 10
	}

	// count data messageprovider
	var count = q.MessageProviderRepositoryQuery.CountData(ctx)

	// parsing result count data to Integer
	if reflect.ValueOf(count.Data).CanInt() {
		totalCount = int(reflect.ValueOf(count.Data).Int())
	}

	// calculate total page
	var totalPage int = int(math.Ceil(float64(totalCount) / float64(limit)))
	// handling if max total page
	if page > totalPage {
		page = totalPage
	}

	// set skip for offset data
	var skip = limit * (page - 1)
	var result utils.ResultResponsePagination = utils.ResultResponsePagination{
		Code:      http.StatusBadRequest,
		Data:      nil,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Failed Get Data MessageProvider",
		Status:    false,
	}

	// if totalCount == 0 {
	// 	result.Code = http.StatusNotFound
	// 	result.Message = "Data Not Found"
	// 	ctx.AbortWithStatusJSON(result.Code, result)
	// 	return
	// }

	getMessageProviderData := q.MessageProviderRepositoryQuery.FindAll(ctx, skip, limit)
	if getMessageProviderData.DB.Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.Error(getMessageProviderData.DB.Error)
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponsePagination{
		Code:      http.StatusOK,
		Data:      getMessageProviderData.Data,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Success Get Data MessageProvider",
		Status:    true,
	}
	ctx.JSON(http.StatusOK, result)
}

// GetAccess responds with a success message indicating messageprovider access
func (q QueryUsecase) GetAccess(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"message": "messageprovider access success"})
}

func (q QueryUsecase) GetUserOwned(ctx *gin.Context) {
	id := ctx.Param("id")
	var totalCount, page, limit int
	var err error

	page, err = strconv.Atoi(ctx.Query("page"))
	// handling when error set default page value 1
	if err != nil || page < 1 {
		page = 1
	}

	// handling when error set default limit value 10
	limit, err = strconv.Atoi(ctx.Query("limit"))
	if err != nil || limit == 0 {
		limit = 10
	}

	// count data messageprovider
	var count = q.MessageProviderRepositoryQuery.CountData(ctx)

	// parsing result count data to Integer
	if reflect.ValueOf(count.Data).CanInt() {
		totalCount = int(reflect.ValueOf(count.Data).Int())
	}

	// calculate total page
	var totalPage int = int(math.Ceil(float64(totalCount) / float64(limit)))
	// handling if max total page
	if page > totalPage {
		page = totalPage
	}

	// set skip for offset data
	var skip = limit * (page - 1)
	var resultPagination utils.ResultResponsePagination = utils.ResultResponsePagination{
		Code:      http.StatusBadRequest,
		Data:      nil,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Failed Get Data MessageProvider",
		Status:    false,
	}

	// if totalCount == 0 {
	// 	resultPagination.Code = http.StatusNotFound
	// 	resultPagination.Message = "Data Not Found"
	// 	ctx.AbortWithStatusJSON(resultPagination.Code, resultPagination)
	// 	return
	// }

	getMessageProviderData := q.MessageProviderRepositoryQuery.FindByUserID(ctx, id, skip, limit)
	if getMessageProviderData.DB.Error != nil {
		resultPagination.Code = http.StatusInternalServerError
		ctx.Error(getMessageProviderData.Error)
		ctx.AbortWithStatusJSON(resultPagination.Code, resultPagination)
		return
	}

	resultPagination = utils.ResultResponsePagination{
		Code:      http.StatusOK,
		Data:      getMessageProviderData.Data,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Success Get Owned Data MessageProvider",
		Status:    true,
	}
	ctx.JSON(resultPagination.Code, resultPagination)
}

func (q QueryUsecase) GetConnectedUserOwned(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Get Data MessageProvider",
		Status:  false,
	}

	id := ctx.Param("id")
	var totalCount, page, limit int
	var err error
	page, err = strconv.Atoi(ctx.Query("page"))
	// handling when error set default page value 1
	if err != nil || page < 1 {
		page = 1
	}

	// handling when error set default limit value 10
	limit, err = strconv.Atoi(ctx.Query("limit"))
	if err != nil || limit == 0 {
		limit = 10
	}

	// count data project
	var count = q.MessageProviderRepositoryQuery.CountData(ctx)

	// parsing result count data to Integer
	if reflect.ValueOf(count.Data).CanInt() {
		totalCount = int(reflect.ValueOf(count.Data).Int())
	}

	// calculate total page
	var totalPage int = int(math.Ceil(float64(totalCount) / float64(limit)))
	// handling if max total page
	if page > totalPage {
		page = totalPage
	}

	// set skip for offset data
	var skip = limit * (page - 1)
	var resultPagination utils.ResultResponsePagination = utils.ResultResponsePagination{
		Code:      http.StatusBadRequest,
		Data:      nil,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Failed Get Data MessageProvider",
		Status:    false,
	}

	// if totalCount == 0 {
	// 	resultPagination.Code = http.StatusNotFound
	// 	resultPagination.Message = "Data Not Found"
	// 	ctx.AbortWithStatusJSON(resultPagination.Code, resultPagination)
	// 	return
	// }

	getProjectData := q.MessageProviderRepositoryQuery.FindConnectedByUserID(ctx, id, skip, limit)
	if getProjectData.DB.Error != nil {
		result.Code = http.StatusInternalServerError
		result.Message = "Internal Server Error"
		ctx.Error(getProjectData.DB.Error)
		ctx.AbortWithStatusJSON(result.Code, resultPagination)
		return
	}

	resultPagination = utils.ResultResponsePagination{
		Code:      http.StatusOK,
		Data:      getProjectData.Data,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Success Get Owned Data MessageProvider",
		Status:    true,
	}
	ctx.JSON(resultPagination.Code, resultPagination)
}
