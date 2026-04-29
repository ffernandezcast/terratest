variable "environment" {
  description = "Environment name"
  type        = string
}

output "vpc_id" {
  description = "The VPC ID"
  value       = "vpc-${var.environment}-12345"
}

output "subnet_ids" {
  description = "List of subnet IDs"
  value       = ["subnet-${var.environment}-a", "subnet-${var.environment}-b"]
}
