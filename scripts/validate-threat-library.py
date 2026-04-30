#!/usr/bin/env python3
"""Validate the SkillLedger community threat library.

Checks:
  - IOC JSON files conform to their JSON Schema definitions
  - No duplicate sha256 hashes or domains
  - YARA rule files have valid structure

Usage:
  python3 scripts/validate-threat-library.py [--dir threat-library/]
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema package required. Install with: pip install jsonschema")
    sys.exit(1)


def validate_ioc_file(data_path: Path, schema_path: Path, key_field: str) -> list[str]:
    """Validate an IOC JSON file against its schema and check for duplicates."""
    errors: list[str] = []

    # Load schema
    try:
        with open(schema_path) as f:
            schema = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        errors.append(f"Schema error ({schema_path}): {e}")
        return errors

    # Load data
    try:
        with open(data_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        errors.append(f"Data error ({data_path}): {e}")
        return errors

    # JSON Schema validation
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        # Find the index if possible
        path_parts = list(e.absolute_path)
        if path_parts:
            errors.append(f"Schema validation failed in {data_path} at entry {path_parts[0]}: {e.message}")
        else:
            errors.append(f"Schema validation failed in {data_path}: {e.message}")

    # Duplicate detection
    seen: set[str] = set()
    for i, entry in enumerate(data):
        value = entry.get(key_field, "")
        if value in seen:
            errors.append(f"Duplicate {key_field} in {data_path} at index {i}: {value}")
        seen.add(value)

    # Explicit severity check (belt and suspenders with schema)
    valid_severities = {"critical", "high", "medium", "low", "info"}
    for i, entry in enumerate(data):
        sev = entry.get("severity", "")
        if sev not in valid_severities:
            errors.append(
                f"Invalid severity in {data_path} at index {i}: "
                f"'{sev}' (must be one of: {', '.join(sorted(valid_severities))})"
            )

    return errors


def validate_yara_rules(rules_dir: Path) -> list[str]:
    """Validate YARA rule files for basic structural correctness."""
    errors: list[str] = []

    yar_files = list(rules_dir.glob("*.yar"))
    if not yar_files:
        return errors  # No YARA rules to validate

    # Try yara-python first
    try:
        import yara

        for yar_file in yar_files:
            try:
                content = yar_file.read_text()
                yara.compile(source=content)
            except yara.SyntaxError as e:
                errors.append(f"YARA syntax error in {yar_file}: {e}")
            except yara.Error as e:
                errors.append(f"YARA error in {yar_file}: {e}")
        return errors
    except ImportError:
        pass  # Fall back to regex validation

    # Regex fallback: check for rule declaration and condition section
    rule_pattern = re.compile(r"^\s*rule\s+\w+", re.MULTILINE)
    condition_pattern = re.compile(r"^\s*condition\s*:", re.MULTILINE)

    for yar_file in yar_files:
        content = yar_file.read_text()
        if not rule_pattern.search(content):
            errors.append(f"YARA file {yar_file} missing 'rule <name>' declaration")
        if not condition_pattern.search(content):
            errors.append(f"YARA file {yar_file} missing 'condition:' section")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SkillLedger threat library")
    parser.add_argument(
        "--dir",
        default="threat-library",
        help="Path to the threat-library directory (default: threat-library/)",
    )
    args = parser.parse_args()

    base = Path(args.dir)
    if not base.is_dir():
        print(f"ERROR: Directory not found: {base}")
        return 1

    all_errors: list[str] = []
    hash_count = 0
    domain_count = 0
    yara_count = 0

    # Validate IOC hashes
    hashes_path = base / "ioc" / "hashes.json"
    hash_schema = base / "schema" / "ioc-hash.schema.json"
    if hashes_path.exists():
        errs = validate_ioc_file(hashes_path, hash_schema, "sha256")
        all_errors.extend(errs)
        with open(hashes_path) as f:
            hash_count = len(json.load(f))

    # Validate IOC domains
    domains_path = base / "ioc" / "domains.json"
    domain_schema = base / "schema" / "ioc-domain.schema.json"
    if domains_path.exists():
        errs = validate_ioc_file(domains_path, domain_schema, "domain")
        all_errors.extend(errs)
        with open(domains_path) as f:
            domain_count = len(json.load(f))

    # Validate YARA rules
    rules_dir = base / "yara" / "rules"
    if rules_dir.is_dir():
        errs = validate_yara_rules(rules_dir)
        all_errors.extend(errs)
        yara_count = len(list(rules_dir.glob("*.yar")))

    # Report
    if all_errors:
        print(f"FAILED: {len(all_errors)} error(s) found:\n")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print(
        f"Validated {hash_count} hashes, {domain_count} domains, "
        f"{yara_count} YARA rules. All checks passed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
