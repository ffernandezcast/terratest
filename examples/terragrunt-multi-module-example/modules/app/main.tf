variable "vpc_id" {
  description = "VPC ID where the app will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the app"
  type        = list(string)
}

variable "database_endpoint" {
  description = "Database endpoint to connect to"
  type        = string
}

variable "database_port" {
  description = "Database port"
  type        = number
}

variable "environment" {
  description = "Environment name"
  type        = string
}

output "app_url" {
  description = "Application URL"
  value       = "https://app-${var.environment}.example.com"
}

output "connection_string" {
  description = "Database connection info"
  value       = "${var.database_endpoint}:${var.database_port}"
}
