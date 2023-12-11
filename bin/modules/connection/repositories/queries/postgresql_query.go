package queries

import (
	"login-api-jwt/bin/modules/connection"
	"login-api-jwt/bin/modules/connection/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

// QueryRepository implements connection.RepositoryQuery interface
type QueryRepository struct {
	ORM *databases.ORM
}

// NewQueryRepository creates a new instance of QueryRepository
func NewQueryRepository(orm *databases.ORM) connection.RepositoryQuery {
	return &QueryRepository{
		ORM: orm,
	}
}

// FindOneByID retrieves a connection record from database by ID

func (q QueryRepository) FindAll(ctx *gin.Context, skip, limit int) utils.Result {
	var connectionInfo []map[string]interface{}

	// Use ORM to find a connection record by ID
	r := q.ORM.DB.Table("connections").
		Select("connections.*, projects.*, message_providers.*").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Joins("LEFT JOIN projects ON projects.project_id = connections.connection_project_id").
		Offset(skip).Limit(limit).Scan(&connectionInfo)

	// Prepare the result, including retrieved connection data and database operation result
	output := utils.Result{
		Data: connectionInfo,
		DB:   r,
	}
	return output

}
func (q QueryRepository) FindOneByID(ctx *gin.Context, connection_id string) utils.Result {
	var connectionInfo []map[string]interface{}

	// Use ORM to find a connection record by ID
	r := q.ORM.DB.
		Table("connections").
		Select("connections.*, projects.*, message_providers.*").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Joins("LEFT JOIN projects ON projects.project_id = connections.connection_project_id").
		Where("connections.connection_id = ?", connection_id).
		Scan(&connectionInfo)

	output := utils.Result{
		Data: connectionInfo,
		DB:   r,
	}
	return output

}

func (q QueryRepository) FindOneByProjectID(ctx *gin.Context, project_id string) utils.Result {

	var connectionInfo []map[string]interface{}

	// Use ORM to find a connection record by project id
	r := q.ORM.DB.
		Table("connections").
		Select("connections.*, projects.*, message_providers.*").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Joins("LEFT JOIN projects ON projects.project_id = connections.connection_project_id").
		Where("connections.connection_project_id = ?", project_id).
		Scan(&connectionInfo)
	output := utils.Result{
		Data: connectionInfo,
		DB:   r,
	}
	return output

}

func (q QueryRepository) FindOneByMessageProviderID(ctx *gin.Context, message_provider_id string) utils.Result {
	var connectionInfo []map[string]interface{}

	// Use ORM to find a connection record by message provider id
	r := q.ORM.DB.
		Table("connections").
		Select("connections.*, projects.*, message_providers.*").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Joins("LEFT JOIN projects ON projects.project_id = connections.connection_project_id").
		Where("connections.connection_message_provider_id = ?", message_provider_id).
		Scan(&connectionInfo)
	output := utils.Result{
		Data: connectionInfo,
		DB:   r,
	}
	return output

}

func (q QueryRepository) CountData(ctx *gin.Context) utils.Result {
	var connectionModel models.Connection
	var count int64
	r := q.ORM.DB.Find(&connectionModel).Count(&count)

	output := utils.Result{
		Data: count,
		DB:   r,
	}
	return output
}
