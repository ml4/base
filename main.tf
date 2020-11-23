## base image unit test
## simple test to start and run rudimentary OS tests to assure working image build
## as a result, this small TF unit suffices atm
#
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3"
    }
  }
  required_version = ">= 0.13"
}

provider "aws" {
  region = "eu-west-1"
}

