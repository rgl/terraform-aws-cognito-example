terraform {
  required_version = "1.8.0"
  required_providers {
    # see https://registry.terraform.io/providers/hashicorp/aws
    # see https://github.com/hashicorp/terraform-provider-aws
    aws = {
      source  = "hashicorp/aws"
      version = "5.45.0"
    }
    # see https://registry.terraform.io/providers/kreuzwerker/docker
    # see https://github.com/kreuzwerker/terraform-provider-docker
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Owner   = "rgl"
      Project = var.name_prefix
    }
  }
}

provider "docker" {
  registry_auth {
    address  = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.amazonaws.com"
    username = data.aws_ecr_authorization_token.current.user_name
    password = data.aws_ecr_authorization_token.current.password
  }
}
