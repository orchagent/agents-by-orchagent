"""Pydantic models for VPS security fixer."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FixType(str, Enum):
    """Types of security fixes that can be applied."""

    FAIL2BAN = "fail2ban"
    FIREWALL = "firewall"
    SSH_PASSWORD_AUTH = "ssh_password_auth"
    SSH_ROOT_LOGIN = "ssh_root_login"
    AUTO_UPDATES = "auto_updates"
    AUTO_REBOOT = "auto_reboot"
    SSH_TAILSCALE = "ssh_tailscale"


class FixInput(BaseModel):
    """Input parameters for applying security fixes."""

    fixes: list[FixType] = Field(description="List of fixes to apply")
    dry_run: bool = Field(default=True, description="Preview without applying changes")
    confirm: bool = Field(
        default=False,
        description="Must be True to apply changes (when dry_run is False)",
    )


class FixAction(BaseModel):
    """Describes a single action to be taken."""

    fix_type: FixType = Field(description="Type of fix being applied")
    description: str = Field(description="Human-readable description of what will be done")
    commands: list[str] = Field(
        default_factory=list, description="Commands that will be run"
    )
    backup_files: list[str] = Field(
        default_factory=list, description="Files that will be backed up before changes"
    )
    rollback_commands: list[str] = Field(
        default_factory=list, description="Commands to undo this fix"
    )


class FixResult(BaseModel):
    """Result of applying a single fix."""

    fix_type: FixType = Field(description="Type of fix that was applied")
    success: bool = Field(description="Whether the fix succeeded")
    message: str = Field(description="Human-readable result message")
    output: str = Field(default="", description="Command output from applying the fix")
    applied: bool = Field(
        default=False, description="Whether the fix was actually applied (vs dry-run)"
    )
    backup_path: Optional[str] = Field(
        default=None, description="Path to backup file if one was created"
    )


class FixResponse(BaseModel):
    """Overall response from the fixer."""

    dry_run: bool = Field(description="Whether this was a dry-run")
    actions: list[FixAction] = Field(
        default_factory=list, description="Planned actions (shown in dry-run mode)"
    )
    results: list[FixResult] = Field(
        default_factory=list, description="Results of applied fixes"
    )
    summary: str = Field(default="", description="Summary of what was done or planned")
