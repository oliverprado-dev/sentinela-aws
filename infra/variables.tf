variable "aws_region" {
  description = "Região comercial AWS do laboratório."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^(us|af|ap|ca|eu|il|me|mx|sa)-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "Informe uma região AWS comercial, por exemplo us-east-1."
  }
}

variable "project_name" {
  description = "Prefixo para os recursos desta implantação."
  type        = string
  default     = "sentinela-aws"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,21}[a-z0-9]$", var.project_name))
    error_message = "Use de 4 a 23 caracteres minúsculos, números ou hífens."
  }
}

variable "response_mode" {
  description = "observe detecta e alerta. enforce autoriza a remediação no bucket do lab."
  type        = string
  default     = "observe"

  validation {
    condition     = contains(["observe", "enforce"], var.response_mode)
    error_message = "Escolha observe ou enforce."
  }
}

variable "create_cloudtrail" {
  description = "Cria uma trilha regional de escritas de gerenciamento. Desative para reutilizar uma trilha compatível."
  type        = bool
  default     = true
}

variable "create_guardduty_detector" {
  description = "Cria o detector regional em conta sandbox. Deixe false para reutilizar um detector existente."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "E-mail opcional para incidentes e alarmes. Confirme a assinatura do SNS após o apply."
  type        = string
  default     = null
  sensitive   = true

  validation {
    condition     = var.alert_email == null || can(regex("^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$", var.alert_email))
    error_message = "Informe um endereço de e-mail válido ou deixe null."
  }
}

variable "incident_retention_days" {
  description = "Retenção aproximada de incidentes via TTL no DynamoDB."
  type        = number
  default     = 30

  validation {
    condition = (
      floor(var.incident_retention_days) == var.incident_retention_days &&
      var.incident_retention_days >= 14 && var.incident_retention_days <= 365
    )
    error_message = "Use um inteiro entre 14 e 365 dias."
  }
}
