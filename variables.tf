variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file or jump_hosts."
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}
variable "sshd_port" {
  type        = number
  default     = null
  description = "Port sshd listens on, which the sshd jail bans on. When null, ssh_port. Set it when a port forward or NAT sits between Conn3x and the hosts."

  validation {
    condition     = var.sshd_port == null || (coalesce(var.sshd_port, 1) >= 1 && coalesce(var.sshd_port, 1) <= 65535)
    error_message = "sshd_port must be a port number from 1 to 65535."
  }
}

variable "bantime" {
  type        = number
  default     = 3600
  description = "Seconds an address stays banned. -1 bans it for good."

  validation {
    condition     = var.bantime == -1 || (var.bantime >= 1 && floor(var.bantime) == var.bantime)
    error_message = "bantime must be a whole number of seconds, or -1 for a permanent ban."
  }
}

variable "findtime" {
  type        = number
  default     = 600
  description = "Window in seconds in which maxretry failures lead to a ban."

  validation {
    condition     = var.findtime >= 1 && floor(var.findtime) == var.findtime
    error_message = "findtime must be a whole number of seconds, 1 or more."
  }
}

variable "maxretry" {
  type        = number
  default     = 5
  description = "Failures within findtime that ban an address."

  validation {
    condition     = var.maxretry >= 1 && floor(var.maxretry) == var.maxretry
    error_message = "maxretry must be a whole number, 1 or more."
  }
}

variable "ignoreip" {
  type        = list(string)
  default     = []
  description = "Addresses and networks never banned, such as [\"192.168.1.0/24\"]. Loopback is always on the list."

  validation {
    condition     = alltrue([for ip in var.ignoreip : can(cidrhost(strcontains(ip, "/") ? ip : "${ip}/${strcontains(ip, ":") ? 128 : 32}", 0))])
    error_message = "Each of ignoreip must be an IP address or a CIDR network, such as \"10.0.0.0/8\" or \"2001:db8::/32\"."
  }
}

variable "banaction" {
  type        = string
  default     = "nftables"
  description = "fail2ban action that bans an address, from /etc/fail2ban/action.d, such as \"nftables\", \"firewallcmd-rich-rules\" or \"ufw\"."

  validation {
    condition     = can(regex("^[a-z0-9_-]+$", var.banaction))
    error_message = "banaction must be the name of a file in /etc/fail2ban/action.d without .conf, such as \"nftables\"."
  }
}

variable "jails" {
  type = map(object({
    enabled  = optional(bool, true)
    port     = optional(string)
    filter   = optional(string)
    logpath  = optional(string)
    backend  = optional(string)
    maxretry = optional(number)
  }))
  default     = {}
  description = "Extra jails, by name, such as { nginx-http-auth = { port = \"http,https\", logpath = \"/var/log/nginx/error.log\" } }. filter defaults to the jail's name."

  validation {
    condition     = alltrue([for name in keys(var.jails) : can(regex("^[a-zA-Z0-9][a-zA-Z0-9_-]*$", name)) && !contains(["sshd", "DEFAULT", "INCLUDES"], name)])
    error_message = "Jail names may use letters, digits, - and _, and can't be sshd, DEFAULT or INCLUDES. Use the other inputs for the sshd jail."
  }

  validation {
    condition     = alltrue([for j in values(var.jails) : j.port == null || can(regex("^[a-z0-9]+([,:][a-z0-9]+)*$", coalesce(j.port, "-")))])
    error_message = "A jail's port is a port, a service name, a range or a comma-separated list, such as \"http,https\" or \"6000:6007\"."
  }

  validation {
    condition     = alltrue([for j in values(var.jails) : j.filter == null || can(regex("^[a-zA-Z0-9_.-]+(\\[.*\\])?$", coalesce(j.filter, "-")))])
    error_message = "A jail's filter is the name of a file in /etc/fail2ban/filter.d without .conf, optionally with [options]."
  }

  validation {
    condition     = alltrue([for j in values(var.jails) : j.logpath == null || startswith(coalesce(j.logpath, "-"), "/") && !strcontains(coalesce(j.logpath, "-"), "\n")])
    error_message = "A jail's logpath must be an absolute path."
  }

  validation {
    condition     = alltrue([for j in values(var.jails) : j.backend == null || contains(["auto", "systemd", "polling", "pyinotify"], coalesce(j.backend, "-"))])
    error_message = "A jail's backend is one of auto, systemd, polling or pyinotify."
  }

  validation {
    condition     = alltrue([for j in values(var.jails) : j.maxretry == null || coalesce(j.maxretry, 1) >= 1])
    error_message = "A jail's maxretry must be 1 or more."
  }
}
