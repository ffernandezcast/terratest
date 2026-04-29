variable "vpc_id" {
  description = "VPC ID where the database will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the database"
  type        = list(string)
}

variable "environment" {
  description = "Environment name"
  type        = string
}

output "database_endpoint" {
  description = "Database endpoint"
  value       = "db-${var.environment}.example.com"
}

output "database_port" {
  description = "Database port"
  value       = 5432
}
