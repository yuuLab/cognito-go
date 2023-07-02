package auth

import (
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// amazon cognito settings
var (
	cognitoReasion    = os.Getenv("COGNITO_REASION")
	cognitoClientId   = os.Getenv("COGNITO_CLIENT_ID")
	cognitoUserPoolId = os.Getenv("COGNITO_USER_POOL_ID")
	issuer            = "https://cognito-idp." + cognitoReasion + ".amazonaws.com/" + cognitoUserPoolId
	jwksPoint         = issuer + "/.well-known/jwks.json"
)

var (
	cognitoClient *cognitoidentityprovider.CognitoIdentityProvider
	once          sync.Once
)

func init() {
	getCognitoClient()
}

func getCognitoClient() *cognitoidentityprovider.CognitoIdentityProvider {
	once.Do(func() {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(cognitoReasion),
		})

		if err != nil {
			panic(err)
		}
		cognitoClient = cognitoidentityprovider.New(sess)
	})
	return cognitoClient
}

func InitiateAuth(username string, password string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	params := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		ClientId: aws.String(cognitoClientId),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(username),
			"PASSWORD": aws.String(password),
		},
	}

	resp, err := cognitoClient.InitiateAuth(params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func RefreshTokens(refreshToken string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	params := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("REFRESH_TOKEN_AUTH"),
		ClientId: aws.String(cognitoClientId),
		AuthParameters: map[string]*string{
			"REFRESH_TOKEN": aws.String(refreshToken),
		},
	}

	resp, err := cognitoClient.InitiateAuth(params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
