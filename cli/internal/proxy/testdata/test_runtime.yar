rule runtime_malicious {
    meta:
        severity = "high"
        description = "Malicious runtime pattern"
    strings:
        $a = "exfiltrate_data_now"
    condition:
        $a
}

rule runtime_suspicious {
    strings:
        $a = "suspicious_callback"
    condition:
        $a
}
