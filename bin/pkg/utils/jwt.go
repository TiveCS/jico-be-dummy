package utils

import (
	"fmt"
	"login-api-jwt/bin/modules/user/models"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func GenerateUserJWT(u models.User) (string, error) {
	// Create a new JWT token for user
	token := jwt.New(jwt.SigningMethodHS256) // create new jwt token

	// Initialize claims variable as a map to hold JWT claims
	claims := token.Claims.(jwt.MapClaims)

	// Set claims in JWT token payload
	claims["id"] = u.UserID
	claims["username"] = u.Username
	claims["name"] = u.Name
	claims["email"] = u.Email
	claims["picture_link"] = u.PictureLink
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	t, err := token.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))

	return t, err
}

func ValidateUserJWTToToken(tokenString string) (*jwt.Token, error) {
	// Parse the token with the provided secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET_KEY")), nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func JWTAuthVerifyToken(ctx *gin.Context) {
	var authHeader string = ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, ResultResponse{
			Code:    http.StatusUnauthorized,
			Data:    nil,
			Message: "Token Required",
			Status:  false,
		})
		return
	}
	token := strings.Split(authHeader, " ")[1]
	user := jwt.MapClaims{}
	var secretKey = os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "loutusz"
	}
	_, err := jwt.ParseWithClaims(token, user, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, ResultResponse{
			Code:    http.StatusUnauthorized,
			Data:    nil,
			Message: err.Error(),
			Status:  false,
		})
		return
	}
	ctx.Set("user", user)
	ctx.Next()
}
