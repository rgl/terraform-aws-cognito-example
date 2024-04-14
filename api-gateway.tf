// see https://docs.aws.amazon.com/apigateway/latest/developerguide
// see https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html
// see https://registry.terraform.io/modules/terraform-aws-modules/apigateway-v2/aws
// see https://github.com/terraform-aws-modules/terraform-aws-apigateway-v2
module "api_gateway" {
  source  = "terraform-aws-modules/apigateway-v2/aws"
  version = "4.0.0"

  name = var.name_prefix

  protocol_type = "HTTP"

  create_api_domain_name = false

  authorizers = {
    "cognito" = {
      name             = "cognito"
      authorizer_type  = "JWT"
      identity_sources = "$request.header.Authorization"
      issuer           = local.oidc_issuer_url
      # NB this jwt authorizer will use the aud or client_id jwt property as
      #    the audience. and it must match one of the values in this audience
      #    array.
      audience = [
        # TODO is there a way to make cognito return a access token with a
        #      given audience(s)? that way, we only need to add that audience
        #      instead of all the clients ids.
        aws_cognito_user_pool_client.example.id,
      ]
    }
  }

  integrations = {
    "GET /jwt-cognito-protected" = {
      lambda_arn             = module.example_lambda_function.lambda_function_arn
      payload_format_version = "2.0"
      authorization_type     = "JWT"
      authorizer_key         = "cognito"
      authorization_scopes   = local.example_auth_oauth_scope
    }
    "$default" = {
      lambda_arn             = module.example_lambda_function.lambda_function_arn
      payload_format_version = "2.0"
    }
  }
}
