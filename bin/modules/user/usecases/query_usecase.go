package usecases

import (
	"errors"
	"fmt"
	"login-api-jwt/bin/modules/user"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"
	"math"
	"net/http"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// QueryUsecase implements user.UsecaseQuery interface
type QueryUsecase struct {
	UserRepositoryQuery user.RepositoryQuery
	ORM                 *databases.ORM
}

// NewQueryUsecase creates a new instance of QueryUsecase
func NewQueryUsecase(q user.RepositoryQuery, orm *databases.ORM) user.UsecaseQuery {
	return &QueryUsecase{
		UserRepositoryQuery: q,
		ORM:                 orm,
	}
}

// GetByID retrieves user data by ID and responds with the result
func (q QueryUsecase) GetByID(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Get Data User",
		Status:  false,
	}
	id := ctx.Param("id")

	// Call FindOneByID method to retrieve user data by ID
	userData := q.UserRepositoryQuery.FindOneByID(ctx, id)
	// If there was an error during query, abort with a Bad Request status
	if userData.DB.Error != nil {
		if errors.Is(userData.DB.Error, gorm.ErrRecordNotFound) {
			if errors.Is(userData.DB.Error, gorm.ErrRecordNotFound) {
				result.Code = http.StatusNotFound
				result.Message = "Data Not Found"
				ctx.AbortWithStatusJSON(result.Code, result)
				return
			}
			// If data is not found in the database, abort with status Unauthorized
			ctx.AbortWithStatusJSON(http.StatusNotFound, result)
			return
		}

		ctx.AbortWithStatusJSON(http.StatusBadRequest, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    userData.Data,
		Message: "Success Get Data User",
		Status:  true,
	}

	// Respond with retrieved user data in JSON format
	ctx.JSON(http.StatusOK, result)
}

// GetAccess responds with a success message indicating user access
func (q QueryUsecase) GetAccess(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"message": "user access success"})
}

// GetByName retrieves user data by name and responds with the result
func (q QueryUsecase) GetByUsername(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Get Data User",
		Status:  false,
	}
	username := ctx.Param("username")
	fmt.Printf("username access %s", username)

	// Call FindOneByUsername method to retrieve user data by username
	userData := q.UserRepositoryQuery.FindOneByUsername(ctx, username)
	if userData.DB.Error != nil {
		if errors.Is(userData.DB.Error, gorm.ErrRecordNotFound) {
			result.Code = http.StatusNotFound
			result.Message = "Data Not Found"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    userData.Data,
		Message: "Success Get Data User",
		Status:  true,
	}
	// Respond with retrieved user data in JSON format
	ctx.JSON(http.StatusOK, result)
}

func (q QueryUsecase) GetByEmail(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Get Data User",
		Status:  false,
	}
	email := ctx.Param("email")
	fmt.Printf("username access %s", email)

	// Call FindOneByUsername method to retrieve user data by email
	userData := q.UserRepositoryQuery.FindOneByEmail(ctx, email)
	if userData.DB.Error != nil {
		if errors.Is(userData.DB.Error, gorm.ErrRecordNotFound) {
			result.Code = http.StatusNotFound
			result.Message = "Data Not Found"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    userData.Data,
		Message: "Success Get Data User",
		Status:  true,
	}
	// Respond with retrieved user data in JSON format
	ctx.JSON(http.StatusOK, result)
}

// Get All retrieves All user data with pagination result
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

	// count data user
	var count = q.UserRepositoryQuery.CountData(ctx)

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
		Message:   "Failed Get Data User",
		Status:    false,
	}

	// if totalCount == 0 {
	// 	result.Code = http.StatusNotFound
	// 	result.Message = "Data Not Found"
	// 	ctx.AbortWithStatusJSON(result.Code, result)
	// 	return
	// }

	getUserData := q.UserRepositoryQuery.FindAll(ctx, skip, limit)
	if getUserData.DB.Error != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponsePagination{
		Code:      http.StatusOK,
		Data:      getUserData.Data,
		Limit:     limit,
		Page:      page,
		TotalData: totalCount,
		TotalPage: totalPage,
		Message:   "Success Get Data User",
		Status:    true,
	}
	ctx.JSON(http.StatusOK, result)
}
