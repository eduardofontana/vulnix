"""
VULNIX - Scan State Management
Save and resume scan progress
"""

import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from core.error_collector import ModuleErrorCollector


class ScanState:
    """Manage scan state for resume functionality."""

    def __init__(self, state_file: str = "vulnix_state.json"):
        self.state_file = state_file
        self.state: Dict[str, Any] = {}
        self.error_collector = ModuleErrorCollector("scan_state")

    def start_new_scan(self, target: str, config: Dict[str, Any]) -> None:
        """Start a new scan and initialize state."""
        self.state = {
            "target": target,
            "config": config,
            "start_time": datetime.now().isoformat(),
            "phase": "init",
            "completed_phases": [],
            "endpoints_discovered": [],
            "findings": [],
            "errors": [],
            "progress": 0,
        }
        self.save()

    def update_phase(self, phase: str, data: Dict[str, Any]) -> None:
        """Update current phase."""
        self.state["phase"] = phase
        self.state["last_update"] = datetime.now().isoformat()

        if "phase_data" not in self.state:
            self.state["phase_data"] = {}

        self.state["phase_data"][phase] = data
        self.save()

    def complete_phase(self, phase: str) -> None:
        """Mark a phase as completed."""
        if phase not in self.state.get("completed_phases", []):
            if "completed_phases" not in self.state:
                self.state["completed_phases"] = []
            self.state["completed_phases"].append(phase)

        progress_map = {
            "init": 5,
            "crawl": 20,
            "sqli": 35,
            "xss": 50,
            "headers": 65,
            "dirscan": 75,
            "csrf": 80,
            "idor": 85,
            "auth": 90,
            "report": 100,
        }
        self.state["progress"] = progress_map.get(phase, 0)
        self.save()

    def add_endpoint(self, endpoint: str) -> None:
        """Add discovered endpoint."""
        if "endpoints_discovered" not in self.state:
            self.state["endpoints_discovered"] = []

        if endpoint not in self.state["endpoints_discovered"]:
            self.state["endpoints_discovered"].append(endpoint)
            self.save()

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding."""
        if "findings" not in self.state:
            self.state["findings"] = []
        self.state["findings"].append(finding)
        self.save()

    def add_error(self, error: str) -> None:
        """Add an error."""
        if "errors" not in self.state:
            self.state["errors"] = []
        self.state["errors"].append({
            "module": "scan_state",
            "phase": "add_error",
            "url": self.state.get("target", self.state_file),
            "error": error,
            "time": datetime.now().isoformat(),
        })
        self.save()

    def save(self) -> None:
        """Save state to file."""
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.error_collector.add(self.state_file, e, "save")

    def load(self) -> Optional[Dict[str, Any]]:
        """Load state from file."""
        if not os.path.exists(self.state_file):
            return None

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                self.state = json.load(f)
            return self.state
        except Exception as e:
            self.error_collector.add(self.state_file, e, "load")
            return None

    def can_resume(self) -> bool:
        """Check if there's a scan to resume."""
        if not os.path.exists(self.state_file):
            return False

        state = self.load()
        if not state:
            return False

        completed = state.get("completed_phases", [])
        return "report" not in completed

    def get_resume_info(self) -> Optional[Dict[str, Any]]:
        """Get info about resumable scan."""
        if not self.can_resume():
            return None

        return {
            "target": self.state.get("target"),
            "phase": self.state.get("phase"),
            "progress": self.state.get("progress", 0),
            "findings_count": len(self.state.get("findings", [])),
            "endpoints_count": len(self.state.get("endpoints_discovered", [])),
        }

    def clear(self) -> None:
        """Clear saved state."""
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
            except Exception as e:
                self.error_collector.add(self.state_file, e, "clear")
        self.state = {}

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured state management errors."""
        return self.error_collector.all()

    def complete_scan(self) -> None:
        """Mark scan as completed."""
        self.state["end_time"] = datetime.now().isoformat()
        self.state["phase"] = "complete"
        self.state["progress"] = 100
        self.save()


class ScanCheckpoint:
    """Periodic checkpoint for long scans."""

    def __init__(self, checkpoint_dir: str = "checkpoints"):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)
        self.error_collector = ModuleErrorCollector("scan_checkpoint")

    def save_checkpoint(
        self,
        scan_id: str,
        data: Dict[str, Any]
    ) -> str:
        """Save a checkpoint."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{scan_id}_{timestamp}.json"
        filepath = self.checkpoint_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return str(filepath)

    def list_checkpoints(self, scan_id: str) -> List[str]:
        """List all checkpoints for a scan."""
        pattern = f"{scan_id}_*.json"
        return sorted([
            str(f) for f in self.checkpoint_dir.glob(pattern)
        ], reverse=True)

    def load_checkpoint(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Load a checkpoint."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.error_collector.add(filepath, e, "load_checkpoint")
            return None

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured checkpoint errors."""
        return self.error_collector.all()
