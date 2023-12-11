package queries

import (
	"login-api-jwt/bin/modules/connection"
	"login-api-jwt/bin/modules/connection/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

// CommandRepository implements connection.RepositoryCommand interface
type CommandRepository struct {
	ORM *databases.ORM
}

// NewCommandRepository creates a new instance of CommandRepository
func NewCommandRepository(orm *databases.ORM) connection.RepositoryCommand {
	return &CommandRepository{
		ORM: orm,
	}
}

// Create creates a new connection record in database
func (c *CommandRepository) Create(ctx *gin.Context, p models.Connection) utils.Result {
	// Use ORM to create a new connection record in database
	r := c.ORM.DB.Create(&p)
	// Prepare the result, including connection data and database operation result
	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

// Save updates an existing connection record in database
func (c *CommandRepository) Save(ctx *gin.Context, p models.Connection) utils.Result {
	// Use ORM to update an existing connection record in database
	r := c.ORM.DB.Save(&p)
	// Prepare the result, including connection data and database operation result
	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Updates(ctx *gin.Context, p models.Connection) utils.Result {

	r := c.ORM.DB.Updates(&p)

	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Delete(ctx *gin.Context, connection_id string) utils.Result {
	var connectionModel models.Connection

	var connectionInfo []map[string]interface{}

	// Use ORM to find a connection record by ID
	c.ORM.DB.
		Table("connections").
		Select("connections.*, projects.*, message_providers.*").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Joins("LEFT JOIN projects ON projects.project_id = connections.connection_project_id").
		Where("connections.connection_id = ?", connection_id).
		Scan(&connectionInfo)
	recordset := c.ORM.DB.Delete(&connectionModel, "connection_id = ?", connection_id)

	output := utils.Result{
		Data: connectionInfo,
		DB:   recordset,
	}
	return output
}
