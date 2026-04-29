terraform {
  source = "../../modules//app"
}

dependency "vpc" {
  config_path = "../vpc"
}

dependency "database" {
  config_path = "../database"
}

inputs = {
  environment       = "test"
  vpc_id            = dependency.vpc.outputs.vpc_id
  subnet_ids        = dependency.vpc.outputs.subnet_ids
  database_endpoint = dependency.database.outputs.database_endpoint
  database_port     = dependency.database.outputs.database_port
}
