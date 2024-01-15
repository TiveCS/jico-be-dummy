package models

type User struct {
	UserID      string `json:"id" gorm:"primaryKey;column:user_id"`
	Email       string `json:"email" form:"email"`
	Password    string `json:"password" form:"password"`
	Username    string `json:"username" form:"username"`
	Name        string `json:"name" form:"name"`
	PictureLink string `json:"picture_link" form:"picture_link"`
}

type UpsertUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

func (u User) UpsertUser() UpsertUser {
	return UpsertUser{
		Name:     u.Name,
		Username: u.Username,
		Email:    u.Email,
	}
}

type LoginRequest struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

type LoginResponse struct {
	UserID      string `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Username    string `json:"username"`
	PictureLink string `json:"picture_link"`
	AccessToken string `json:"accessToken"`
}

type RegisterResponse struct {
	UserID   string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type GetUserResponse struct {
	UserID      string `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	PictureLink string `json:"picture_link"`
}
