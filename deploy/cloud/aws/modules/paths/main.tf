# The single list of every network path between trust domains (../../paths.json) and the address plan (../../cidrs.json).
# A root asks this module what it must PROVIDE (endpoint services others may use) and what it CONSUMES (endpoints to others).
# The rules at the bottom are the isolation rules of the design; `terraform test` runs them against the real files.

locals {
  raw   = jsondecode(file("${path.module}/../../paths.json"))
  cidrs = jsondecode(file("${path.module}/../../cidrs.json"))

  domains = keys(local.cidrs)

  active = [for p in local.raw.paths : p if !p.optional || contains(var.enabled_optional_paths, p.id)]

  # Services this domain offers to others: one endpoint service per (service), allowed accounts = the domains that have an active path to it.
  provided_keys = distinct([for p in local.active : p.service if p.to == var.domain])
  provides = {
    for s in local.provided_keys : s => {
      ports               = sort(distinct(flatten([for p in local.active : p.ports if p.to == var.domain && p.service == s])))
      allowed_account_ids = sort(distinct([for p in local.active : var.account_ids[p.from] if p.to == var.domain && p.service == s]))
      allowed_domains     = sort(distinct([for p in local.active : p.from if p.to == var.domain && p.service == s]))
    }
  }

  # Endpoints this domain opens towards others, one per path.
  consumes = {
    for p in local.active : p.id => {
      to      = p.to
      service = p.service
      ports   = p.ports
      dns     = p.dns
    } if p.from == var.domain
  }

  # Every range is a /16 whose first address is the network address. Two different /16 blocks never overlap, so distinct ranges are disjoint.
  bad_ranges = [for d, c in local.cidrs : d if !endswith(c, "/16") || cidrhost(c, 0) != split("/", c)[0]]
  overlaps   = length(distinct(values(local.cidrs))) == length(local.cidrs) ? [] : ["duplicate range"]
}

output "domain_cidr" {
  value = local.cidrs[var.domain]
}

output "all_cidrs" {
  value = local.cidrs
}

output "provides" {
  value = local.provides
}

output "consumes" {
  value = local.consumes
}

output "active_paths" {
  value = local.active
}

output "rules_ok" {
  description = "true when every isolation rule holds; the preconditions fail the plan otherwise"
  value       = true

  precondition {
    condition     = contains(local.domains, var.domain)
    error_message = "unknown domain ${var.domain}"
  }
  precondition {
    condition     = length(local.overlaps) == 0 && length(local.bad_ranges) == 0
    error_message = "address ranges must be distinct, aligned /16 blocks (bad: ${join(", ", local.bad_ranges)})"
  }
  precondition {
    condition     = alltrue([for p in local.raw.paths : contains(local.domains, p.from) && contains(local.domains, p.to) && p.from != p.to])
    error_message = "every path needs two different known domains"
  }
  precondition {
    condition     = alltrue([for p in local.raw.paths : p.from != "business"])
    error_message = "no path may start in the business domain: nothing is pushed into a signing domain"
  }
  precondition {
    condition     = alltrue([for p in local.raw.paths : p.to != "party-b" && p.to != "party-c" && p.to != "signing-core" || p.from == "signing-core" || p.from == "party-b"])
    error_message = "only signing domains may open a path into a signing domain"
  }
  precondition {
    condition     = alltrue([for p in local.raw.paths : length(p.ports) > 0 && alltrue([for q in p.ports : q > 0 && q < 65536])])
    error_message = "every path names explicit ports"
  }
  precondition {
    condition     = alltrue([for p in local.active : contains(keys(var.account_ids), p.from) && contains(keys(var.account_ids), p.to)])
    error_message = "account_ids must name every domain that has an active path"
  }
  precondition {
    condition     = length(distinct([for p in local.raw.paths : p.id])) == length(local.raw.paths)
    error_message = "path ids must be unique"
  }
}
