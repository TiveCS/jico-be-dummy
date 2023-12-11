package usecases

import (
	"login-api-jwt/bin/modules/project"
	"login-api-jwt/bin/modules/project/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CommandUsecase implements project.UsecaseCommand interface
type CommandUsecase struct {
	ProjectRepositoryCommand project.RepositoryCommand
	ORM                      *databases.ORM
}

// NewCommandUsecase creates a new instance of CommandUsecase
func NewCommandUsecase(q project.RepositoryCommand, orm *databases.ORM) project.UsecaseCommand {
	return &CommandUsecase{
		ProjectRepositoryCommand: q,
		ORM:                      orm,
	}
}

// PostRegister handles project registration
func (q CommandUsecase) PostProject(ctx *gin.Context) {
	user := ctx.MustGet("user").(jwt.MapClaims)
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Post Project",
		Status:  false,
	}
	var projectModel models.Project
	err := ctx.ShouldBind(&projectModel)
	if err != nil {
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	projectModel.ProjectUserID = user["id"].(string)

	// Generate a unique ProjectID for project
	projectModel.ProjectID = uuid.NewString()

	// Capitalize first letter of project's name
	projectModel.Name = strings.Title(projectModel.Name)

	// Create project record in the database
	r := q.ProjectRepositoryCommand.Create(ctx, projectModel)
	if r.DB.Error != nil {
		// Check if the error is due to a duplicate email or projectname
		if strings.Contains(r.DB.Error.Error(), "duplicate key value violates unique constraint \"projects_name_key\"") {
			// If data is already found, abort with status "email or projectname already used"
			result.Message = "project name already used"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}

		if strings.Contains(r.DB.Error.Error(), "insert or update on table \"projects\" violates foreign key constraint \"projects_user_id_fkey\"") {
			// If data user id not valid return message "user id not valid"
			result.Message = "user id not valid"
			ctx.AbortWithStatusJSON(result.Code, result)
			return
		}
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, result)
		return
	}

	// Response data for successful registration
	projectRegisterResponse := models.PostProjectResponse{
		ProjectID:     projectModel.ProjectID,
		Name:          projectModel.Name,
		ProjectUserID: projectModel.ProjectUserID,
	}

	// Save project record again after successful registration
	r = q.ProjectRepositoryCommand.Save(ctx, projectModel)

	// Check if an error occurred while saving
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    projectRegisterResponse,
		Message: "Success Post Project",
		Status:  true,
	}
	// If project record was successfully saved, respond with project's registration data
	ctx.JSON(result.Code, result)
}

func (q CommandUsecase) PutProject(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Update Project",
		Status:  false,
	}

	user := ctx.MustGet("user").(jwt.MapClaims)
	projectID := ctx.Param("id")

	var projectModel models.Project

	err := ctx.ShouldBind(&projectModel)
	if err != nil {
		result.Code = http.StatusBadRequest
		ctx.AbortWithStatusJSON(result.Code, result)
	}

	projectModel.ProjectID = projectID
	projectModel.ProjectUserID = user["id"].(string)

	// Response data for successful registration
	Response := projectModel

	r := q.ProjectRepositoryCommand.Updates(ctx, Response)
	if r.DB.Error != nil {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if r.DB.RowsAffected == 0 {
		result.Message = "Changes not Saved"
		ctx.AbortWithStatusJSON(http.StatusBadRequest, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    Response,
		Message: "Success Update Project",
		Status:  true,
	}
	// If messageprovider record was successfully saved, respond with messageprovider's registration data
	ctx.JSON(http.StatusOK, result)

}

func (q CommandUsecase) DeleteProject(ctx *gin.Context) {
	var result utils.ResultResponse = utils.ResultResponse{
		Code:    http.StatusBadRequest,
		Data:    nil,
		Message: "Failed Delete Project",
		Status:  false,
	}

	var id string = ctx.Param("id")

	deletedProject := q.ProjectRepositoryCommand.Delete(ctx, id)
	if deletedProject.DB[0].Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if deletedProject.DB[1].Error != nil {
		result.Code = http.StatusInternalServerError
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}

	if deletedProject.DB[1].RowsAffected == 0 {
		// If there was an error, return Internal Server Error with error message
		result.Code = http.StatusBadRequest
		result.Message = "project not found"
		ctx.AbortWithStatusJSON(result.Code, result)
		return
	}
	result = utils.ResultResponse{
		Code:    http.StatusOK,
		Data:    deletedProject.Data,
		Message: "Success Delete Project",
		Status:  true,
	}
	ctx.JSON(result.Code, result)
}
