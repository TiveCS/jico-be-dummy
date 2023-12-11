package queries

import (
	"login-api-jwt/bin/modules/user"
	"login-api-jwt/bin/modules/user/models"
	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

// QueryRepository implements user.RepositoryQuery interface
type QueryRepository struct {
	ORM *databases.ORM
}

// NewQueryRepository creates a new instance of QueryRepository
func NewQueryRepository(orm *databases.ORM) user.RepositoryQuery {
	return &QueryRepository{
		ORM: orm,
	}
}

// FindOneByID retrieves a user record from database by ID
func (q QueryRepository) FindOneByID(ctx *gin.Context, user_id string) utils.Result {
	var userModel models.User

	// Use ORM to find a user record by ID
	r := q.ORM.DB.First(&userModel, "user_id = ?", user_id)
	// Prepare the result, including retrieved user data and database operation result
	output := utils.Result{
		Data: userModel,
		DB:   r,
	}
	return output

}

// FindOneByUsername retrieves a user record from database by username
func (q QueryRepository) FindOneByUsername(ctx *gin.Context, username string) utils.Result {
	var userModel models.User

	// Use ORM to find a user record by username
	r := q.ORM.DB.First(&userModel, "username = ?", username)
	// Prepare the result, including retrieved user data and database operation result
	output := utils.Result{
		Data: userModel,
		DB:   r,
	}
	return output

}

func (q QueryRepository) FindOneByEmail(ctx *gin.Context, email string) utils.Result {
	var userModel models.User

	// Use ORM to find a user record by username
	r := q.ORM.DB.First(&userModel, "email = ?", email)
	// Prepare the result, including retrieved user data and database operation result
	output := utils.Result{
		Data: userModel,
		DB:   r,
	}
	return output

}

// FindOneByID retrieves a user record from database by ID

func (q QueryRepository) FindAll(ctx *gin.Context, skip, limit int) utils.Result {
	var usersModel []models.User

	// Use ORM to find a user record by ID
	r := q.ORM.DB.Offset(skip).Limit(limit).Find(&usersModel)

	// Prepare the result, including retrieved user data and database operation result
	output := utils.Result{
		Data: usersModel,
		DB:   r,
	}
	return output

}

func (q QueryRepository) CountData(ctx *gin.Context) utils.Result {
	var userModel models.User
	var count int64
	r := q.ORM.DB.Find(&userModel).Count(&count)

	output := utils.Result{
		Data: count,
		DB:   r,
	}
	return output
}
