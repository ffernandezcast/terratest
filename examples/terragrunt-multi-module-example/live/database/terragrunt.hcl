terraform {
  source = "../../modules//database"
}

dependency "vpc" {
  config_path = "../vpc"
}

inputs = {
  environment = "test"
  vpc_id      = dependency.vpc.outputs.vpc_id
  subnet_ids  = dependency.vpc.outputs.subnet_ids
}
