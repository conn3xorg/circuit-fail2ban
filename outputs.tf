output "jail_file" {
  description = "Path of the file the circuit writes on each host."
  value       = local.jail_file
}

output "jails" {
  description = "Names of the jails the circuit turns on, sshd first."
  value       = concat(["sshd"], [for name, j in var.jails : name if j.enabled])
}
