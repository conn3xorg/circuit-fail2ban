variable "port" {
  type    = number
  default = 2222
}

module "fail2ban" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  # Podman forwards 127.0.0.1:2222 to sshd's port 22 in the container.
  sshd_port = 22

  bantime  = 7200
  findtime = 900
  maxretry = 4
  ignoreip = ["10.0.0.0/8", "192.168.1.10"]

  jails = {
    recidive = { backend = "systemd" }
  }
}
