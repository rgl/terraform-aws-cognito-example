package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC Authorization Code Grant handler.
func oidcHandler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	oidcRedirectURL := os.Getenv("EXAMPLE_OIDC_REDIRECT_URL")
	if oidcRedirectURL == "" {
		log.Fatalf("ERROR You MUST set the EXAMPLE_OIDC_REDIRECT_URL environment variable")
	}
	u, err := url.Parse(oidcRedirectURL)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("failed to parse the EXAMPLE_OIDC_REDIRECT_URL environment variable: %w", err)
	}
	oidcRedirectPath := u.Path

	oidcIssuerURL := os.Getenv("EXAMPLE_OIDC_ISSUER_URL")
	if oidcIssuerURL == "" {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("you MUST set the EXAMPLE_OIDC_ISSUER_URL environment variable")
	}

	oidcClientID := os.Getenv("EXAMPLE_OIDC_CLIENT_ID")
	if oidcClientID == "" {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("you MUST set the EXAMPLE_OIDC_CLIENT_ID environment variable")
	}

	oidcClientSecret := os.Getenv("EXAMPLE_OIDC_CLIENT_SECRET")
	if oidcClientSecret == "" {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("you MUST set the EXAMPLE_OIDC_CLIENT_SECRET environment variable")
	}

	var oidcProvider *oidc.Provider
	for n := 0; n < 10; n++ {
		oidcProvider, err = oidc.NewProvider(ctx, oidcIssuerURL)
		if err == nil {
			break
		}
		log.Printf("WARNING Failed to initialize OIDC: %v. Retrying in a bit.", err)
		time.Sleep(3 * time.Second)
	}
	if oidcProvider == nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("failed to load the oidc configuration")
	}

	log.Printf("OIDC provider Authorization URL: %s", oidcProvider.Endpoint().AuthURL)

	oidcConfig := oauth2.Config{
		ClientID:     oidcClientID,
		ClientSecret: oidcClientSecret,
		RedirectURL:  oidcRedirectURL,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{"openid", "email", "profile"},
	}

	// handle oidc error redirect.
	// see https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoint-idp-responses.html
	if errorID, ok := event.QueryStringParameters["error"]; ok {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusBadRequest,
			Body:       fmt.Sprintf("Cognito returned the error %s: %s", errorID, event.QueryStringParameters["error_description"]),
		}, nil
	}

	// handle the oidc redirect
	if _, ok := event.QueryStringParameters["code"]; ok {
		return oidcRedirectHandler(ctx, oidcConfig, oidcRedirectPath, oidcProvider, event)
	}

	// redirect to the cognito oidc authorization url.
	return oidcRedirect(oidcConfig, oidcRedirectPath)
}

func oidcRedirect(oidcConfig oauth2.Config, oidcRedirectPath string) (events.APIGatewayV2HTTPResponse, error) {
	response := events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusFound,
		Headers:    map[string]string{},
	}
	state, err := randString(16)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("failed to generate random string")
	}
	nonce, err := randString(16)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("failed to generate random string")
	}
	// create the pkce code verifier.
	// see https://www.rfc-editor.org/rfc/rfc7636
	// see https://condatis.com/news/blog/oauth-confidential-clients/
	codeVerifier, err := randString(32)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("failed to generate random string")
	}
	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	// save the oidc user authentication state as cookies.
	// TODO ciphertext the cookie values?
	setCookie(&response, oidcRedirectPath, "state", state)
	setCookie(&response, oidcRedirectPath, "nonce", nonce)
	setCookie(&response, oidcRedirectPath, "code_verifier", codeVerifier)
	// start the oidc user authentication dance.
	// NB we are adding pkce code challenge because cognito supports it.
	//    see https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html
	//    see the code_challenge_methods_supported property at, e.g.:
	// 		https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_id/.well-known/openid-configuration
	authCodeURL := oidcConfig.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	response.Headers["Location"] = authCodeURL
	return response, nil
}

func oidcRedirectHandler(ctx context.Context, oidcConfig oauth2.Config, oidcRedirectPath string, oidcProvider *oidc.Provider, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	cookies := parseCookies(event.Cookies)

	response := events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusFound,
		Headers:    map[string]string{},
	}

	// verify the state.
	if cookies["state"] != event.QueryStringParameters["state"] {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusBadRequest,
			Body:       "state did not match",
		}, nil
	}

	// delete the state cookie.
	deleteCookie(&response, oidcRedirectPath, "state")

	// get the code verifier.
	codeVerifier := cookies["code_verifier"]

	// delete the code verifier cookie.
	deleteCookie(&response, oidcRedirectPath, "code_verifier")

	// exchange the authorization code with the access token and
	// identity token.
	token, err := oidcConfig.Exchange(
		ctx,
		event.QueryStringParameters["code"],
		oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusBadRequest,
			Body:       "Failed to exchange the authorization code with the access token: " + err.Error(),
		}, nil
	}

	unverifiedIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       "No id_token field in oauth2 token.",
		}, nil
	}

	// NB in a real program, you should not log these tokens (they should
	// 	  be treated as secrets).
	log.Printf("ID Token: %v", unverifiedIDToken)
	log.Printf("Access Token: %v", token.AccessToken)

	// verify and get the verified id token.
	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID})
	idToken, err := verifier.Verify(ctx, unverifiedIDToken)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       "Failed to verify ID Token: " + err.Error(),
		}, nil
	}

	// verify the id token nonce.
	nonce := cookies["nonce"]
	if idToken.Nonce != nonce {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusBadRequest,
			Body:       "nonce did not match",
		}, nil
	}

	// delete the nonce cookie.
	deleteCookie(&response, oidcRedirectPath, "nonce")

	// extract the user claims from the id token.
	var claims struct {
		Issuer            string `json:"iss"`
		Subject           string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
	}
	err = idToken.Claims(&claims)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       "Failed to get the id token claims: " + err.Error(),
		}, nil
	}

	body, err := json.Marshal(claims)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, err
	}
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(body),
	}, nil
}

func parseCookies(l []string) map[string]string {
	cookies := map[string]string{}
	for _, c := range l {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) > 1 {
			cookies[parts[0]] = parts[1]
		} else if len(parts) > 0 {
			cookies[parts[0]] = ""
		}
	}
	return cookies
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCookie(response *events.APIGatewayV2HTTPResponse, path, name, value string) {
	c := http.Cookie{
		Path:     path,
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   true,
		HttpOnly: true,
	}
	response.Cookies = append(response.Cookies, c.String())
}

func deleteCookie(response *events.APIGatewayV2HTTPResponse, path, name string) {
	c := http.Cookie{
		Path:     path,
		Name:     name,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}
	response.Cookies = append(response.Cookies, c.String())
}
