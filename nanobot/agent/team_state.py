"""Persistent team state for subagent groups."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger


class TeamState:
    """Manages persistent team state stored as JSON."""

    def __init__(self, workspace: Path) -> None:
        self._path = workspace / "team_state.json"
        self._teams: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except Exception:
                logger.warning("Failed to load team state, starting fresh")
        return {}

    def _save(self) -> None:
        self._path.write_text(json.dumps(self._teams, indent=2))

    def create_team(self, name: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        if name in self._teams:
            raise ValueError(f"Team '{name}' already exists")
        team = {
            "name": name,
            "created_at": datetime.now().isoformat(),
            "status": "active",
            "members": [],
            "config": config or {},
        }
        self._teams[name] = team
        self._save()
        return team

    def get_team(self, name: str) -> dict[str, Any] | None:
        return self._teams.get(name)

    def list_teams(self) -> list[dict[str, Any]]:
        return list(self._teams.values())

    def archive_team(self, name: str) -> None:
        if name not in self._teams:
            raise ValueError(f"Team '{name}' not found")
        self._teams[name]["status"] = "archived"
        self._save()

    def add_member(self, team_name: str, member_config: dict[str, Any]) -> None:
        if team_name not in self._teams:
            raise ValueError(f"Team '{team_name}' not found")
        self._teams[team_name]["members"].append(member_config)
        self._save()
