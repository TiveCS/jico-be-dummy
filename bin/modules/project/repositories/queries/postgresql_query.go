package queries

import (
	"login-api-jwt/bin/modules/project"
	"login-api-jwt/bin/modules/project/models"

	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

// QueryRepository implements project.RepositoryQuery interface
type QueryRepository struct {
	ORM *databases.ORM
}

// NewQueryRepository creates a new instance of QueryRepository
func NewQueryRepository(orm *databases.ORM) project.RepositoryQuery {
	return &QueryRepository{
		ORM: orm,
	}
}

// FindOneByID retrieves a project record from database by ID

func (q QueryRepository) FindAll(ctx *gin.Context, skip, limit int) utils.Result {
	var projectsModel []models.Project

	// Use ORM to find a project record by ID
	r := q.ORM.DB.Offset(skip).Limit(limit).Find(&projectsModel)

	// Prepare the result, including retrieved project data and database operation result
	output := utils.Result{
		Data: projectsModel,
		DB:   r,
	}
	return output

}

func (q QueryRepository) FindOneByID(ctx *gin.Context, project_id string) utils.Result {
	var projectModel models.Project

	// Use ORM to find a project record by ID
	r := q.ORM.DB.First(&projectModel, "project_id = ?", project_id)
	// Prepare the result, including retrieved project data and database operation result
	output := utils.Result{
		Data: projectModel,
		DB:   r,
	}
	return output

}

func (q QueryRepository) FindConnectedOneByID(ctx *gin.Context, project_id string) utils.Result {
	var projectInfo []map[string]interface{}

	// Use ORM to find project records by user ID with LEFT JOIN on connections and message_providers
	r := q.ORM.DB.
		Table("projects").
		Select("projects.*, connections.*, message_providers.*").
		Joins("LEFT JOIN connections ON connections.connection_project_id = projects.project_id").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Where("projects.project_id = ?", project_id).
		Scan(&projectInfo)

	// Prepare the result, including retrieved project data and database operation result
	// Prepare the result
	output := utils.Result{
		Data: projectInfo,
		DB:   r,
	}

	return output
}

func (q QueryRepository) CountData(ctx *gin.Context) utils.Result {
	var projectModel models.Project
	var count int64
	r := q.ORM.DB.Find(&projectModel).Count(&count)

	output := utils.Result{
		Data: count,
		DB:   r,
	}
	return output
}

func (q QueryRepository) FindByUserID(ctx *gin.Context, user_id string, skip, limit int) utils.Result {
	var projectsModel []models.Project

	// Use ORM to find a project record by ID
	r := q.ORM.DB.Where("project_user_id = ?", user_id).Offset(skip).Limit(limit).Find(&projectsModel)

	// Prepare the result, including retrieved project data and database operation result
	output := utils.Result{
		Data: projectsModel,
		DB:   r,
	}
	return output

}

func (q QueryRepository) FindConnectedByUserID(ctx *gin.Context, user_id string, skip, limit int) utils.Result {
	var projectsInfo []map[string]interface{}

	// Use ORM to find project records by user ID with LEFT JOIN on connections and message_providers
	r := q.ORM.DB.
		Table("projects").
		Select("projects.*, connections.*, message_providers.*").
		Joins("LEFT JOIN connections ON connections.connection_project_id = projects.project_id").
		Joins("LEFT JOIN message_providers ON message_providers.message_provider_id = connections.connection_message_provider_id").
		Where("projects.project_user_id = ?", user_id).
		Offset(skip).
		Limit(limit).
		Scan(&projectsInfo)

	// Prepare the result, including retrieved project data and database operation result
	output := utils.Result{
		Data: projectsInfo,
		DB:   r,
	}
	return output
}
