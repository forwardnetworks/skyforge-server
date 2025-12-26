variable "db_url" {
  type = string
}

env "prod" {
  url = var.db_url
  migration {
    dir    = "file://./skyforge/migrations"
    format = golang-migrate
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}
