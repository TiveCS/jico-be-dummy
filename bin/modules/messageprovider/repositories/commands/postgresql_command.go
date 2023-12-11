package queries

import (
	connectionModels "login-api-jwt/bin/modules/connection/models"
	"login-api-jwt/bin/modules/messageprovider"
	"login-api-jwt/bin/modules/messageprovider/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// CommandRepository implements messageprovider.RepositoryCommand interface
type CommandRepository struct {
	ORM *databases.ORM
}

// NewCommandRepository creates a new instance of CommandRepository
func NewCommandRepository(orm *databases.ORM) messageprovider.RepositoryCommand {
	return &CommandRepository{
		ORM: orm,
	}
}

// Create creates a new messageprovider record in database
func (c *CommandRepository) Create(ctx *gin.Context, p models.MessageProvider) utils.Result {
	// Use ORM to create a new messageprovider record in database
	r := c.ORM.DB.Create(&p)
	// Prepare the result, including messageprovider data and database operation result
	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

// Save updates an existing messageprovider record in database
func (c *CommandRepository) Save(ctx *gin.Context, p models.MessageProvider) utils.Result {
	// Use ORM to update an existing messageprovider record in database
	r := c.ORM.DB.Save(&p)
	// Prepare the result, including messageprovider data and database operation result
	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Updates(ctx *gin.Context, m models.MessageProvider) utils.Result {

	r := c.ORM.DB.Updates(&m)

	output := utils.Result{
		Data: m,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Delete(ctx *gin.Context, message_provider_id string) utils.MultiDataResult {
	var messageProviderModel models.MessageProvider
	var connectionModel connectionModels.Connection

	var messageProvidersInfo []map[string]interface{}

	// Use ORM to find project records by user ID with LEFT JOIN on connections and message_providers
	c.ORM.DB.
		Table("message_providers").
		Select("message_providers.*, connections.*, projects.*").
		Joins("LEFT JOIN connections ON connections.connection_message_provider_id = message_providers.message_provider_id").
		Joins("LEFT JOIN projects ON projects.project_id = connections.connection_project_id").
		Where("message_providers.message_provider_id = ?", message_provider_id).
		Scan(&messageProvidersInfo)

	connectionRecordset := c.ORM.DB.Delete(&connectionModel, "connection_message_provider_id = ?", message_provider_id)
	messageProviderRecordset := c.ORM.DB.Delete(&messageProviderModel, "message_provider_id = ?", message_provider_id)

	output := utils.MultiDataResult{
		Data: messageProvidersInfo,
		DB:   []*gorm.DB{connectionRecordset, messageProviderRecordset},
	}
	return output
}
