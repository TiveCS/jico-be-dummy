package queries

import (
	connectionModels "login-api-jwt/bin/modules/connection/models"
	"login-api-jwt/bin/modules/project"
	"login-api-jwt/bin/modules/project/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// CommandRepository implements project.RepositoryCommand interface
type CommandRepository struct {
	ORM *databases.ORM
}

// NewCommandRepository creates a new instance of CommandRepository
func NewCommandRepository(orm *databases.ORM) project.RepositoryCommand {
	return &CommandRepository{
		ORM: orm,
	}
}

// Create creates a new project record in database
func (c *CommandRepository) Create(ctx *gin.Context, p models.Project) utils.Result {
	// Use ORM to create a new project record in database
	r := c.ORM.DB.Create(&p)
	// Prepare the result, including project data and database operation result
	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

// Save updates an existing project record in database
func (c *CommandRepository) Save(ctx *gin.Context, p models.Project) utils.Result {
	// Use ORM to update an existing project record in database
	r := c.ORM.DB.Save(&p)
	// Prepare the result, including project data and database operation result
	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Updates(ctx *gin.Context, p models.Project) utils.Result {

	r := c.ORM.DB.Updates(&p)

	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Delete(ctx *gin.Context, project_id string) utils.MultiDataResult {
	var projectModel models.Project
	var connectionModel connectionModels.Connection
	var projectInfo []map[string]interface{}

	// Use ORM to find project records by user ID with LEFT JOIN on connections and message_providers
	c.ORM.DB.
		Table("projects").
		Select("projects.*, connections.*, message_providers.*").
		Joins("LEFT JOIN connections ON connections.connection_project_id = projects.project_id").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Where("projects.project_id = ?", project_id).
		Scan(&projectInfo)

	connectionRecordset := c.ORM.DB.Delete(&connectionModel, "connection_project_id = ?", project_id)
	projectRecordset := c.ORM.DB.Delete(&projectModel, "project_id = ?", project_id)

	output := utils.MultiDataResult{
		Data: projectInfo,
		DB:   []*gorm.DB{connectionRecordset, projectRecordset},
	}
	return output
}
