#!/usr/bin/env python3
"""Main entrypoint for vps-fixer security remediation tool.

This script reads JSON input from stdin (FixInput model), processes fix requests,
and outputs a FixResponse as JSON to stdout.
"""

import json
import sys

# Add src directory to path for imports
sys.path.insert(0, "src")

from vps_fixer.models import (
    FixAction,
    FixInput,
    FixResponse,
    FixResult,
    FixType,
)

# Import fix modules
from vps_fixer.fixes.fail2ban import get_fail2ban_fix_actions, apply_fail2ban_fix
from vps_fixer.fixes.firewall import get_firewall_fix_actions, apply_firewall_fix
from vps_fixer.fixes.ssh import (
    get_ssh_password_auth_fix_actions,
    apply_ssh_password_auth_fix,
    get_ssh_root_login_fix_actions,
    apply_ssh_root_login_fix,
)
from vps_fixer.fixes.updates import get_auto_updates_fix_actions, apply_auto_updates_fix


# Map FixType enum to action and apply functions
FIX_TYPE_TO_ACTIONS = {
    FixType.FAIL2BAN: get_fail2ban_fix_actions,
    FixType.FIREWALL: get_firewall_fix_actions,
    FixType.SSH_PASSWORD_AUTH: get_ssh_password_auth_fix_actions,
    FixType.SSH_ROOT_LOGIN: get_ssh_root_login_fix_actions,
    FixType.AUTO_UPDATES: get_auto_updates_fix_actions,
}

FIX_TYPE_TO_APPLY = {
    FixType.FAIL2BAN: apply_fail2ban_fix,
    FixType.FIREWALL: apply_firewall_fix,
    FixType.SSH_PASSWORD_AUTH: apply_ssh_password_auth_fix,
    FixType.SSH_ROOT_LOGIN: apply_ssh_root_login_fix,
    FixType.AUTO_UPDATES: apply_auto_updates_fix,
}


def get_available_fixes_message() -> str:
    """Return a message listing all available fix types.

    Returns:
        Human-readable string describing available fixes.
    """
    fix_descriptions = {
        FixType.FAIL2BAN: "Install and configure fail2ban for brute-force protection",
        FixType.FIREWALL: "Enable and configure UFW firewall",
        FixType.SSH_PASSWORD_AUTH: "Disable SSH password authentication",
        FixType.SSH_ROOT_LOGIN: "Restrict SSH root login",
        FixType.AUTO_UPDATES: "Enable automatic security updates",
    }
    lines = ["Available fixes:"]
    for fix_type in FixType:
        lines.append(f"  - {fix_type.value}: {fix_descriptions.get(fix_type, 'No description')}")
    return "\n".join(lines)


def main() -> int:
    """Main entry point for the VPS fixer.

    Reads FixInput from stdin, processes fix requests, and outputs FixResponse to stdout.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Read input from stdin
    try:
        input_data = sys.stdin.read()
        if input_data.strip():
            fix_input = FixInput.model_validate_json(input_data)
        else:
            # No input provided - return error with available fixes
            error_result = {
                "error": "No input provided",
                "message": get_available_fixes_message(),
                "expected_format": {
                    "fixes": ["fail2ban", "firewall", "ssh_password_auth", "ssh_root_login", "auto_updates"],
                    "dry_run": True,
                    "confirm": False,
                },
            }
            print(json.dumps(error_result, indent=2), file=sys.stdout)
            return 1
    except Exception as e:
        error_result = {
            "error": f"Failed to parse input: {str(e)}",
            "expected_format": {
                "fixes": ["fail2ban", "firewall"],
                "dry_run": True,
                "confirm": False,
            },
        }
        print(json.dumps(error_result, indent=2), file=sys.stdout)
        return 1

    # Validate input: If no fixes specified, return error with available fixes
    if not fix_input.fixes:
        error_result = {
            "error": "No fixes specified",
            "message": get_available_fixes_message(),
            "expected_format": {
                "fixes": ["fail2ban", "firewall", "ssh_password_auth", "ssh_root_login", "auto_updates"],
                "dry_run": True,
                "confirm": False,
            },
        }
        print(json.dumps(error_result, indent=2), file=sys.stdout)
        return 1

    # Validate input: If dry_run is False and confirm is False, return error
    if not fix_input.dry_run and not fix_input.confirm:
        error_result = {
            "error": "Must set confirm=True to apply changes when dry_run=False",
            "message": "For safety, you must explicitly confirm when applying changes. "
                       "Set 'confirm': true in your input to proceed.",
        }
        print(json.dumps(error_result, indent=2), file=sys.stdout)
        return 1

    # Process fixes based on mode
    if fix_input.dry_run:
        # Dry-run mode: collect planned actions
        return handle_dry_run(fix_input)
    else:
        # Apply mode: apply fixes and collect results
        return handle_apply(fix_input)


def handle_dry_run(fix_input: FixInput) -> int:
    """Handle dry-run mode by collecting planned actions.

    Args:
        fix_input: Validated input with fixes to preview.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    all_actions: list[FixAction] = []

    for fix_type in fix_input.fixes:
        try:
            get_actions_func = FIX_TYPE_TO_ACTIONS.get(fix_type)
            if get_actions_func is None:
                # Unknown fix type - shouldn't happen with enum validation
                continue
            actions = get_actions_func()
            all_actions.extend(actions)
        except Exception as e:
            # Return error result for this fix type
            error_result = {
                "error": f"Failed to get actions for {fix_type.value}: {str(e)}",
            }
            print(json.dumps(error_result, indent=2), file=sys.stdout)
            return 1

    # Build summary
    fix_names = [f.value for f in fix_input.fixes]
    summary = f"Dry-run complete. Planned {len(all_actions)} action(s) for fixes: {', '.join(fix_names)}"

    response = FixResponse(
        dry_run=True,
        actions=all_actions,
        results=[],
        summary=summary,
    )

    print(response.model_dump_json(indent=2))
    return 0


def handle_apply(fix_input: FixInput) -> int:
    """Handle apply mode by executing fixes and collecting results.

    Args:
        fix_input: Validated input with fixes to apply.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    all_results: list[FixResult] = []
    success_count = 0
    failure_count = 0

    for fix_type in fix_input.fixes:
        try:
            apply_func = FIX_TYPE_TO_APPLY.get(fix_type)
            if apply_func is None:
                # Unknown fix type - shouldn't happen with enum validation
                all_results.append(
                    FixResult(
                        fix_type=fix_type,
                        success=False,
                        message=f"Unknown fix type: {fix_type.value}",
                        output="",
                        applied=False,
                        backup_path=None,
                    )
                )
                failure_count += 1
                continue

            result = apply_func()
            all_results.append(result)

            if result.success:
                success_count += 1
            else:
                failure_count += 1
        except Exception as e:
            # Handle unexpected errors gracefully
            all_results.append(
                FixResult(
                    fix_type=fix_type,
                    success=False,
                    message=f"Unexpected error applying {fix_type.value}: {str(e)}",
                    output=str(e),
                    applied=False,
                    backup_path=None,
                )
            )
            failure_count += 1

    # Build summary
    total = len(fix_input.fixes)
    if failure_count == 0:
        summary = f"Successfully applied {success_count}/{total} fix(es)"
    else:
        summary = f"Applied {success_count}/{total} fix(es), {failure_count} failed"

    response = FixResponse(
        dry_run=False,
        actions=[],
        results=all_results,
        summary=summary,
    )

    print(response.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
