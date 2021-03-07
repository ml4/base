variable "email" {
  type = string
}

variable "ubuntu_password" {
  type = string
}

variable "hostname" {
  type = string
}

variable "domain" {
  type = string
}

variable "grubPassword" {
  type = string
}

variable "emailPassword" {
  type = string
}

variable "aws_access_key_id" {
  type = string
}

variable "aws_secret_access_key" {
  type = string
}

variable "aws_session_token" {
  type = string
  default = ""
}

variable "region" {
  type = string
}

variable "s3_bucket" {
  type = string
}

variable "remoteLogHost" {
  type = string
  default = ""
}

variable "ownerTag" {
  type = string
  default = ""
}
