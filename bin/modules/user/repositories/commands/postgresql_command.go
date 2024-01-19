package queries

import (
	connectionModels "login-api-jwt/bin/modules/connection/models"
	messageProviderModels "login-api-jwt/bin/modules/messageprovider/models"
	projectModels "login-api-jwt/bin/modules/project/models"

	"login-api-jwt/bin/modules/user"
	"login-api-jwt/bin/modules/user/models"

	"login-api-jwt/bin/pkg/databases"
	"login-api-jwt/bin/pkg/utils"

	"github.com/gin-gonic/gin"
)

// CommandRepository implements user.RepositoryCommand interface
type CommandRepository struct {
	ORM *databases.ORM
}

// NewCommandRepository creates a new instance of CommandRepository
func NewCommandRepository(orm *databases.ORM) user.RepositoryCommand {
	return &CommandRepository{
		ORM: orm,
	}
}

// Create creates a new user record in database
func (c *CommandRepository) Create(ctx *gin.Context, u models.User) utils.Result {
	// Use ORM to create a new user record in database
	r := c.ORM.DB.Create(&u)
	// Prepare the result, including user data and database operation result
	output := utils.Result{
		Data: u,
		DB:   r,
	}
	return output
}

// Save updates an existing user record in database
func (c *CommandRepository) Save(ctx *gin.Context, u models.User) utils.Result {
	// Use ORM to update an existing user record in database
	r := c.ORM.DB.Save(&u)
	// Prepare the result, including user data and database operation result
	output := utils.Result{
		Data: u,
		DB:   r,
	}
	return output
}

// FindPassword retrieves password for a user by username
func (c *CommandRepository) FindPasswordByUsername(ctx *gin.Context, u string) utils.FindPasswordResult {
	var userModel models.User
	userModel.Username = u
	// Use ORM to find user record by username
	r := c.ORM.DB.First(&userModel, "username = ?", u)
	// Prepare the result, including retrieved password, user data, and  database operation result
	output := utils.FindPasswordResult{
		Password: userModel.Password,
		Data:     userModel,
		DB:       r,
	}
	return output
}

// FindPassword retrieves password for a user by id
func (c *CommandRepository) FindPasswordByID(ctx *gin.Context, u string) utils.FindPasswordResult {
	var userModel models.User
	userModel.Username = u
	// Use ORM to find user record by ID
	r := c.ORM.DB.First(&userModel, "user_id = ?", u)
	// Prepare the result, including retrieved password, user data, and  database operation result
	output := utils.FindPasswordResult{
		Password: userModel.Password,
		Data:     userModel,
		DB:       r,
	}
	return output
}

// FindOneByID retrieves a user record from database by ID
func (c *CommandRepository) FindProfileByID(ctx *gin.Context, user_id string) utils.FindProfileResult {
	var userModel models.User

	// Use ORM to find a user record by ID
	r := c.ORM.DB.First(&userModel, "user_id = ?", user_id)
	// Prepare the result, including retrieved user data and database operation result
	output := utils.FindProfileResult{
		// PicureLink: userModel.PictureLink,
		// Username:   userModel.Username,
		// Name:       userModel.Name,
		Data: userModel,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) Delete(ctx *gin.Context, userID string) utils.Result {
	// Start a transaction

	// Step 1: Load the user record

	var user models.User
	res := c.ORM.DB.Where("user_id = ?", userID).First(&user)
	if err := res.Error; err != nil {
		c.ORM.DB.Rollback() // Rollback the transaction if there's an error
		return utils.Result{
			Data: nil,
			DB:   res,
		}
	}

	if r := c.ORM.DB.Where("connection_project_id IN (SELECT project_id FROM projects WHERE project_user_id = ?)", userID).
		Or("connection_message_provider_id IN (SELECT message_provider_id FROM message_providers WHERE message_provider_user_id = ?)", userID).
		Delete(&connectionModels.Connection{}); r.Error != nil {
		c.ORM.DB.Rollback() // Rollback the transaction if there's an error
		return utils.Result{
			Data: nil,
			DB:   r,
		}
	}

	// Step 2: Delete related data (projects, message providers, connections)
	if r := c.ORM.DB.Where("project_user_id = ?", userID).Delete(&projectModels.Project{}); r.Error != nil {
		c.ORM.DB.Rollback() // Rollback the transaction if there's an error
		return utils.Result{
			Data: nil,
			DB:   r,
		}
	}

	if r := c.ORM.DB.Where("message_provider_user_id = ?", userID).Delete(&messageProviderModels.MessageProvider{}); r.Error != nil {
		c.ORM.DB.Rollback() // Rollback the transaction if there's an error
		return utils.Result{
			Data: nil,
			DB:   r,
		}
	}

	// Step 3: Delete the user
	res = c.ORM.DB.Delete(&user)
	if res.Error != nil {
		c.ORM.DB.Rollback() // Rollback the transaction if there's an error
		return utils.Result{
			Data: nil,
			DB:   res,
		}
	}

	// Commit the transaction if everything is successful
	c.ORM.DB.Commit()

	output := utils.Result{
		Data: user,
		DB:   res,
	}

	return output
}

func (c *CommandRepository) Updates(ctx *gin.Context, u models.User) utils.Result {

	r := c.ORM.DB.Updates(&u)

	output := utils.Result{
		Data: u,
		DB:   r,
	}
	return output
}

func (c *CommandRepository) UpdatePicture(ctx *gin.Context, userID string, p string) utils.Result {

	r := c.ORM.DB.Update("picture_link", p)

	output := utils.Result{
		Data: p,
		DB:   r,
	}
	return output
}

// resulting in unwanted behavior
// func (c *CommandRepository) UpdatePasswordByID(ctx *gin.Context, userID string, p string) utils.Result {

// 	r := c.ORM.DB.Where("user_id = ?", userID).Update("password", p)

// 	output := utils.Result{
// 		Data: p,
// 		DB:   r,
// 	}
// 	return output
// }

// func (c *CommandRepository) UpdatePasswordByEmail(ctx *gin.Context, email string, p string) utils.Result {

// 	r := c.ORM.DB.Where("email = ?", email).Update("password", p)

// 	output := utils.Result{
// 		Data: p,
// 		DB:   r,
// 	}
// 	return output
// }

func (c *CommandRepository) FindProfileByUsername(ctx *gin.Context, username string) utils.FindProfileResult {
	var userModel models.User

	// Use ORM to find a user record by ID
	r := c.ORM.DB.First(&userModel, "username = ?", username)
	// Prepare the result, including retrieved user data and database operation result
	output := utils.FindProfileResult{
		// PicureLink: userModel.PictureLink,
		// Username:   userModel.Username,
		// Name:       userModel.Name,
		Data: userModel,
		DB:   r,
	}
	return output
}
