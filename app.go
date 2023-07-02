package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yuuLab/cognito-go/auth"
)

type AuthInfo struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func login(c *gin.Context) {
	// dummy
	userName := "test"
	password := "password"
	authOutput, err := auth.InitiateAuth(userName, password)
	if err != nil {
		fmt.Println(err.Error())
		c.IndentedJSON(http.StatusUnauthorized, AuthInfo{})
	}
	// 本来はヘッダに付与するなどする
	c.IndentedJSON(http.StatusOK, AuthInfo{
		AccessToken:  *authOutput.AuthenticationResult.AccessToken,
		IdToken:      *authOutput.AuthenticationResult.IdToken,
		RefreshToken: *authOutput.AuthenticationResult.RefreshToken,
	})
}

func refreshToken(c *gin.Context) {
	token := getHeaderValue(c.Request, "RefreshToken")
	authOutput, err := auth.RefreshTokens(token)
	if err != nil {
		fmt.Println(err.Error())
		c.IndentedJSON(http.StatusUnauthorized, AuthInfo{})
		return
	}
	// 本来はヘッダに付与するなどする
	c.IndentedJSON(http.StatusOK, AuthInfo{
		AccessToken: *authOutput.AuthenticationResult.AccessToken,
		IdToken:     *authOutput.AuthenticationResult.IdToken,
	})
}

func authIdToken(c *gin.Context) {
	token := getHeaderValue(c.Request, "IdToken")
	if err := auth.ValidateIdToken(&token); err != nil {
		fmt.Println(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": "unauthorized"})
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

func getHeaderValue(req *http.Request, header string) string {
	hdr := req.Header.Get(header)
	if hdr == "" {
		return ""
	}
	return hdr
}

func main() {
	router := gin.New()
	router.GET("/login", login)
	router.GET("/refreshToken", refreshToken)
	router.GET("/authIdToken", authIdToken)
	router.Run(":8080")
}
