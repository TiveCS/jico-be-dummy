package usecases

import (
	"errors"
	"log"
	"login-api-jwt/bin/modules/user"
	"login-api-jwt/bin/modules/user/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"login-api-jwt/bin/pkg/utils/validators"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// CommandUsecase implements user.UsecaseCommand interface
type CommandUsecase struct {
	UserRepositoryCommand user.RepositoryCommand
	ORM                   *databases.ORM
}

// NewCommandUsecase creates a new instance of CommandUsecase
func NewCommandUsecase(q user.RepositoryCommand, orm *databases.ORM) user.UsecaseCommand {
	return &CommandUsecase{
		UserRepositoryCommand: q,
		ORM:                   orm,
	}
}

// PostRegister handles user registration
func (q CommandUsecase) PostRegister(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Register User",
		Status:  false,
	}
	var userModel models.User
	err := ctx.ShouldBind(&userModel)
	if err != nil {
		result.Code = http.StatusConflict
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Generate a unique UserID for user
	userModel.UserID = uuid.NewString()

	// Capitalize first letter of user's name
	userModel.Name = strings.Title(userModel.Name)

	ctx.Header("Access-Control-Allow-Origin", "*")

	log.Println(userModel.Username)

	// Validate user's email format
	validEmail := validators.IsValidEmail(userModel.Email)
	if !validEmail {
		result.Message = "email not valid"
		ctx.AbortWithStatusJSON(http.StatusBadRequest, result)
		return
	}

	validUsername := validators.IsValidUsername(userModel.Username)
	if !validUsername {
		result.Message = "username not valid"
		ctx.AbortWithStatusJSON(http.StatusBadRequest, result)
		return
	}

	ValidPassword := validators.IsValidPassword(userModel.Password)
	if !ValidPassword {
		result.Message = "password not valid"
		ctx.AbortWithStatusJSON(http.StatusBadRequest, result)
		return
	}

	// Hash user's password before storing it in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userModel.Password), bcrypt.DefaultCost)
	if err != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	userModel.Password = string(hashedPassword)

	// Create user record in the database
	r := q.UserRepositoryCommand.Create(ctx, userModel)
	if r.DB.Error != nil {

		// Check if the error is due to a duplicate email or username

		if strings.Contains(r.DB.Error.Error(), "duplicate key value violates unique constraint \"users_username_key\"") {
			// If data is already found, abort with status "email or username already used"
			result.Message = "email or username already registered"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		if strings.Contains(r.DB.Error.Error(), "duplicate key value violates unique constraint \"users_email_key\"") {
			// If data is already found, abort with status "email or username already used"
			result.Message = "email or username already registered"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Response data for successful registration
	userRegisterResponse := models.RegisterResponse{
		UserID:   userModel.UserID,
		Name:     userModel.Name,
		Username: userModel.Username,
		Email:    userModel.Email,
	}

	// Save user record again after successful registration
	r = q.UserRepositoryCommand.Save(ctx, userModel)

	// Check if an error occurred while saving
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    userRegisterResponse,
		Message: "Success Register User",
		Status:  true,
	}
	// If user record was successfully saved, respond with user's registration data
	ctx.JSON(http.StatusOK, result)
}

// PostLogin handles user login
func (q CommandUsecase) PostLogin(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusUnauthorized,
		Data:    nil,
		Message: "Incorrect username or password",
		Status:  false,
	}
	var userLoginRequest models.LoginRequest
	err := ctx.ShouldBind(&userLoginRequest)
	ctx.Header("Access-Control-Allow-Origin", "*")
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Find user's password hash by username
	r := q.UserRepositoryCommand.FindPassword(ctx, userLoginRequest.Username)
	if r.DB.Error != nil {
		if errors.Is(r.DB.Error, gorm.ErrRecordNotFound) {
			// If data is not found in the database, abort with status Unauthorized
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Compare the provided password with the hashed password in the database
	err = bcrypt.CompareHashAndPassword([]byte(r.Password), []byte(userLoginRequest.Password))
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Create a new JWT token for user
	t, err := utils.GenerateUserJWT(r.Data) // create new jwt token
	if err != nil {
		// fmt.Println("found jwt error")
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	// Create a new instance of LoginResponse model, initializing its fields with data
	userLoginResponse := models.LoginResponse{
		UserID:      r.Data.UserID,
		Email:       r.Data.Email,
		Name:        r.Data.Name,
		Username:    r.Data.Username,
		AccessToken: t,
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    userLoginResponse,
		Message: "Success Login User",
		Status:  true,
	}

	// Respond to request with an HTTP 200 OK status code and userLoginResponse data in JSON format
	ctx.JSON(result.Code, result)
}

func (q CommandUsecase) DeleteUser(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Delete User",
		Status:  false,
	}

	var id string = ctx.Param("id")

	deletedUser := q.UserRepositoryCommand.Delete(ctx, id)
	if deletedUser.Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if deletedUser.DB.RowsAffected == 0 {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusBadRequest
		result.Message = "User not found"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    deletedUser.Data,
		Message: "Success Delete User",
		Status:  true,
	}
	ctx.JSON(result.Code, result)
}
