# The isolation rules, run against the real paths.json and cidrs.json. No provider, no account.

variables {
  account_ids = { business = "111111111111", signing-core = "222222222222", party-b = "333333333333", party-c = "444444444444" }
}

run "rules_hold_for_business" {
  variables {
    domain = "business"
  }
  assert {
    condition     = output.rules_ok
    error_message = "isolation rules"
  }
  assert {
    condition     = length(output.consumes) == 0
    error_message = "the business domain opens no path to any other domain"
  }
  assert {
    condition     = jsonencode(sort(keys(output.provides))) == jsonencode(["kafka", "postgres"]) && jsonencode(output.provides["postgres"].allowed_domains) == jsonencode(["signing-core"])
    error_message = "business offers Postgres to the signing core only, and Kafka to the three signing-side domains"
  }
  assert {
    condition     = jsonencode(output.provides["kafka"].allowed_domains) == jsonencode(["party-b", "party-c", "signing-core"])
    error_message = "Kafka is offered to signing-core, party-b and party-c only"
  }
}

run "business_metrics_path_is_off_by_default_and_outward_only" {
  variables {
    domain                 = "business"
    enabled_optional_paths = ["metrics-party-b"]
  }
  assert {
    condition     = jsonencode(output.provides["monitoring"].allowed_domains) == jsonencode(["party-b"]) && join(",", output.provides["monitoring"].ports) == "443"
    error_message = "an optional path opens one endpoint, for one named domain"
  }
}

run "party_b_is_reached_by_the_gateway_and_party_a_only" {
  variables {
    domain = "party-b"
  }
  assert {
    condition     = jsonencode(output.provides["caller"].allowed_domains) == jsonencode(["signing-core"]) && jsonencode(output.provides["peer"].allowed_domains) == jsonencode(["signing-core"])
    error_message = "party B's caller and peer ports are offered to the signing core only"
  }
  assert {
    condition     = jsonencode(sort(keys(output.consumes))) == jsonencode(["b-party-c-peer", "cosigner-b-heads"])
    error_message = "party B calls out to the business Kafka and to party C, nothing else"
  }
}

run "party_c_is_reached_by_signing_core_and_party_b" {
  variables {
    domain = "party-c"
  }
  assert {
    condition     = jsonencode(output.provides["peer"].allowed_domains) == jsonencode(["party-b", "signing-core"]) && jsonencode(output.provides["caller"].allowed_domains) == jsonencode(["signing-core"])
    error_message = "party C's peer port is dialed by A and B; its caller port by the gateway"
  }
  assert {
    condition     = jsonencode(sort(keys(output.consumes))) == jsonencode(["cosigner-c-heads"])
    error_message = "party C dials nobody"
  }
}

run "signing_core_calls_out_only" {
  variables {
    domain = "signing-core"
  }
  assert {
    condition     = length(output.provides) == 0
    error_message = "nothing may be pushed into the signing core: it offers no endpoint service"
  }
  assert {
    condition     = length(output.consumes) == 6
    error_message = "gateway: jobs, heads, B caller, C caller; party A: B peer, C peer; ... (six paths)"
  }
}

run "address_ranges_are_distinct_blocks" {
  variables {
    domain = "business"
  }
  assert {
    condition     = length(distinct(values(output.all_cidrs))) == 4
    error_message = "four distinct ranges"
  }
}

run "unknown_domain_is_refused" {
  variables {
    domain = "party-d"
  }
  command         = plan
  expect_failures = [var.domain]
}
