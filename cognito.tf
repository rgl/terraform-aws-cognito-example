# see OAuth 2.0, OpenID Connect, and SAML 2.0 federation endpoints reference
#     https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html
locals {
  oidc_issuer_url        = "https://${aws_cognito_user_pool.example.endpoint}"
  oidc_configuration_url = "${local.oidc_issuer_url}/.well-known/openid-configuration"
  oidc_jwks_url          = "${local.oidc_issuer_url}/.well-known/jwks.json"
  oidc_authorization_url = "https://${aws_cognito_user_pool_domain.example.domain}.auth.${var.region}.amazoncognito.com/oauth2/authorize"
  oidc_token_url         = "https://${aws_cognito_user_pool_domain.example.domain}.auth.${var.region}.amazoncognito.com/oauth2/token"
  oidc_userinfo_url      = "https://${aws_cognito_user_pool_domain.example.domain}.auth.${var.region}.amazoncognito.com/oauth2/userInfo"

  example_auth_oauth_scope = "${aws_cognito_resource_server.example.identifier}/auth"

  example_authorization_code_oidc_redirect_url = "${module.api_gateway.apigatewayv2_api_api_endpoint}/oidc"
}

# see https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_domain
resource "aws_cognito_user_pool_domain" "example" {
  domain       = replace(uuidv5("url", "urn:${var.name_prefix}"), "-", "")
  user_pool_id = aws_cognito_user_pool.example.id
}

# see https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool
resource "aws_cognito_user_pool" "example" {
  name = var.name_prefix
}

# see https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user
resource "aws_cognito_user" "alice" {
  user_pool_id   = aws_cognito_user_pool.example.id
  username       = "alice"
  password       = "HeyH0Password!"
  message_action = "SUPPRESS"
  attributes = {
    preferred_username = "alice"
    name               = "Alice Doe"
    given_name         = "Alice"
    family_name        = "Doe"
    email              = "alice@example.com"
    email_verified     = true
  }
}

# see https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_resource_server
resource "aws_cognito_resource_server" "example" {
  identifier   = "example"
  name         = "example"
  user_pool_id = aws_cognito_user_pool.example.id
  scope {
    scope_name        = "auth"
    scope_description = "Authenticate"
  }
}

# see https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_client
resource "aws_cognito_user_pool_client" "example" {
  name                                 = "example"
  user_pool_id                         = aws_cognito_user_pool.example.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = [local.example_auth_oauth_scope]
}

# see https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_client
resource "aws_cognito_user_pool_client" "example_authorization_code" {
  name                                 = "example-authorization-code"
  callback_urls                        = [local.example_authorization_code_oidc_redirect_url]
  user_pool_id                         = aws_cognito_user_pool.example.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile", local.example_auth_oauth_scope]
  supported_identity_providers         = ["COGNITO"]
}
