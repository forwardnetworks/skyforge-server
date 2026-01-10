variable "db_url" {
  type = string
}

env "prod" {
  url = var.db_url
  migration {
    dir    = "file:///app/skyforge/migrations"
    format = golang-migrate
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}
