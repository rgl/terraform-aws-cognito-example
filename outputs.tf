output "oidc_issuer_url" {
  value = local.oidc_issuer_url
}

output "oidc_configuration_url" {
  value = local.oidc_configuration_url
}

output "oidc_authorization_url" {
  value = local.oidc_authorization_url
}

output "oidc_token_url" {
  value = local.oidc_token_url
}

output "oidc_jwks_url" {
  value = local.oidc_jwks_url
}

output "oidc_userinfo_url" {
  value = local.oidc_userinfo_url
}

output "example_client_id" {
  value = aws_cognito_user_pool_client.example.id
}

output "example_client_secret" {
  sensitive = true
  value     = aws_cognito_user_pool_client.example.client_secret
}

output "example_url" {
  value = module.api_gateway.apigatewayv2_api_api_endpoint
}

output "example_authorization_code_oidc_redirect_url" {
  value = local.example_authorization_code_oidc_redirect_url
}
