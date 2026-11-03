variable "project" {
  description = "Nom court du projet, utilisé dans le nom des ressources."
  type        = string
  default     = "clinicbooking"

  validation {
    condition     = can(regex("^[a-z0-9]{3,16}$", var.project))
    error_message = "3 à 16 caractères, minuscules et chiffres uniquement (contrainte des noms ACR)."
  }
}

variable "environment" {
  description = "Environnement : staging ou prod."
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment doit valoir staging ou prod."
  }
}

variable "location" {
  description = "Région Azure."
  type        = string
  default     = "francecentral"
}

variable "tags" {
  description = "Tags supplémentaires appliqués à toutes les ressources."
  type        = map(string)
  default     = {}
}
