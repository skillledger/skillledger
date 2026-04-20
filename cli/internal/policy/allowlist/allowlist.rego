package skillledger.policy

import rego.v1

publisher_allowed if {
    count(data.publishers.allowlist) == 0
}

publisher_allowed if {
    some entry in data.publishers.allowlist
    glob.match(entry.cert_identity, ["/"], input.attestation.signed_by)
    entry.issuer == input.attestation.issuer
}

deny contains "publisher not in allowlist" if {
    not publisher_allowed
    count(data.publishers.allowlist) > 0
}
