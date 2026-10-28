# Facts give each host's distribution. Rocky Linux, AlmaLinux and RHEL get
# fail2ban from EPEL; Fedora, Debian and Ubuntu have it in their own
# repositories.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }
}

locals {
  epel_hosts = { for name, h in var.hosts : name => h if contains(["rocky", "almalinux", "rhel", "centos"], data.conn3x_host.facts[name].os_id) }

  # The Red Hat family splits fail2ban into subpackages. fail2ban-server is
  # the daemon; the fail2ban package would also pull in firewalld and
  # sendmail.
  server_package = { for name, f in data.conn3x_host.facts : name => f.os_family == "redhat" ? "fail2ban-server" : "fail2ban" }

  jail_file = "/etc/fail2ban/jail.d/conn3x.local"

  # Every jail reads the systemd journal unless it names a log file. Debian
  # 13, Fedora and Rocky Linux don't write /var/log/auth.log or
  # /var/log/secure out of the box, and the journal is there on every
  # systemd host.
  jail_config = join("\n", concat(
    [
      <<-EOT
      # Written by Conn3x. Changes here are overwritten on the next apply.
      [DEFAULT]
      bantime = ${var.bantime}
      findtime = ${var.findtime}
      maxretry = ${var.maxretry}
      ignoreip = ${join(" ", concat(["127.0.0.1/8", "::1"], var.ignoreip))}
      backend = systemd
      banaction = ${var.banaction}
      banaction_allports = ${var.banaction}[type=allports]
      EOT
      ,
      <<-EOT
      [sshd]
      enabled = true
      port = ${coalesce(var.sshd_port, var.ssh_port)}
      backend = systemd
      EOT
    ],
    [
      for name, j in var.jails : "${join("\n", compact([
        "[${name}]",
        "enabled = ${j.enabled}",
        j.port == null ? "" : "port = ${j.port}",
        j.filter == null ? "" : "filter = ${j.filter}",
        j.logpath == null ? "" : "logpath = ${j.logpath}",
        "backend = ${coalesce(j.backend, j.logpath != null ? "auto" : "systemd")}",
        j.maxretry == null ? "" : "maxretry = ${j.maxretry}",
      ]))}\n"
    ],
  ))
}

circuit "epel" {
  hosts = local.epel_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "release" {
    package {
      name = "epel-release"
    }
  }
}

circuit "fail2ban" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "server" {
    depends_on = [conn3x_package.epel__release]
    package {
      name = local.server_package[each.key]
    }
  }

  # Reads the journal for the systemd backend.
  step "journal" {
    package {
      name = "python3-systemd"
    }
  }

  # The default banaction adds its rules to an nftables table of its own,
  # which works next to ufw and firewalld.
  step "nftables" {
    package {
      name = "nftables"
    }
  }

  step "config" {
    file {
      path    = local.jail_file
      content = local.jail_config
    }
    notify = [handler.reload]
  }

  step "running" {
    service {
      name    = "fail2ban"
      state   = "started"
      enabled = true
    }
  }

  # fail2ban takes a moment to open its socket after it starts, and a
  # reload before then fails.
  step "ready" {
    wait_for {
      path    = "/run/fail2ban/fail2ban.sock"
      timeout = "1m"
    }
  }

  handler "reload" {
    service {
      name   = "fail2ban"
      action = "reload"
    }
  }
}
