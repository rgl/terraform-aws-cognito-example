package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func handler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if strings.HasPrefix(event.RawPath, "/oidc") {
		return oidcHandler(ctx, event)
	}
	data := map[string]interface{}{
		"redirectURL": os.Getenv("EXAMPLE_OIDC_REDIRECT_URL"),
		"event":       event,
	}
	// NB when the api-gateway is protecting the request, like our
	//    /jwt-cognito-protected path segment that is configured in
	//    apt-gateway.tf, we can use (and trust) the
	//	  event.RequestContext.Authorizer.JWT.Claims and
	//	  event.RequestContext.Authorizer.JWT.Scopes properties.
	if event.RequestContext.Authorizer != nil && event.RequestContext.Authorizer.JWT != nil {
		data["apiGatewayAuthorizationClaims"] = event.RequestContext.Authorizer.JWT.Claims
	}
	// NB when the api-gateway is protecting the request, like our
	//    /jwt-cognito-protected path segment that is configured in
	//    apt-gateway.tf, we can use (and trust) the
	//	  event.RequestContext.Authorizer.JWT.Claims and
	//	  event.RequestContext.Authorizer.JWT.Scopes properties instead of
	//    parsing the authorization header, bearer token, jwt, and validate
	//    it to extract the claims. this getTokenClaims part is here as an
	//    example and sanity check.
	// and .scopes to authorize the request without the need revalidate the
	if authorization, ok := event.Headers["authorization"]; ok {
		claims, err := getTokenClaims(ctx, authorization)
		if err != nil {
			data["authorizationClaims"] = fmt.Sprintf("ERROR: %v", err)
		} else {
			data["authorizationClaims"] = claims
		}
	}
	body, err := json.Marshal(data)
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

func getTokenClaims(ctx context.Context, authorization string) (map[string]interface{}, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, fmt.Errorf("the Authorization header does is not a Bearer Token")
	}
	bearerToken := authorization[len("Bearer "):]
	unverifiedToken, err := jwt.ParseInsecure([]byte(bearerToken))
	if err != nil {
		return nil, fmt.Errorf("failed to parse the Authorization Bearer Token as a JWT: %v", err)
	}
	// NB in a real application, this issuer would be obtained from a trusted
	//    source (e.g. this service configuration), BUT in this example, we
	//    are blindly trusting the client.
	issuer := unverifiedToken.Issuer()
	jwksURL := fmt.Sprintf("%s/.well-known/jwks.json", issuer)
	keySet, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from %s: %v", jwksURL, err)
	}
	if keySet.Len() < 1 {
		return nil, fmt.Errorf("%s did not return any key", jwksURL)
	}
	token, err := jwt.ParseString(bearerToken, jwt.WithIssuer(issuer), jwt.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("failed to validate the jwt: %v", err)
	}
	claims, err := token.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token claims: %v", err)
	}
	return claims, nil
}

func main() {
	lambda.Start(handler)
}
