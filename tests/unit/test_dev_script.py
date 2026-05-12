# -*- coding: utf-8 -*-

"""
Unit tests for the dev.sh development server helper.

These tests validate command-line behavior without starting the server.
"""

import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEV_SCRIPT = PROJECT_ROOT / "dev.sh"


class TestDevScript:
    """Tests for dev.sh syntax and safe command validation."""

    def test_dev_script_exists(self):
        """
        What it does: Verifies dev.sh exists in the project root.
        Purpose: Ensure contributors have the requested development helper.
        """
        print(f"Checking script path: {DEV_SCRIPT}")
        assert DEV_SCRIPT.exists()
        assert DEV_SCRIPT.is_file()

    def test_dev_script_has_valid_bash_syntax(self):
        """
        What it does: Runs bash syntax validation for dev.sh.
        Purpose: Catch shell syntax errors without starting the server.
        """
        print("Action: Running bash -n dev.sh...")
        result = subprocess.run(
            ["bash", "-n", str(DEV_SCRIPT)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        assert result.returncode == 0

    def test_dev_script_help_documents_reload_behavior(self):
        """
        What it does: Checks help text for default no-reload behavior.
        Purpose: Ensure users can discover how to enable or avoid hot reload.
        """
        print("Action: Running dev.sh --help...")
        result = subprocess.run(
            ["bash", str(DEV_SCRIPT), "--help"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        print(f"stdout: {result.stdout}")
        assert result.returncode == 0
        assert "./dev.sh start [reload]" in result.stdout
        assert "Start without hot reload" in result.stdout
        assert "start reload" in result.stdout
        assert "uvicorn --reload" in result.stdout

    def test_dev_script_help_works_outside_project_directory(self):
        """
        What it does: Runs dev.sh from the user's home directory.
        Purpose: Ensure shell aliases can call the script without being in the repo root.
        """
        outside_directory = Path.home()
        print(f"Action: Running dev.sh --help from {outside_directory}...")
        result = subprocess.run(
            ["bash", str(DEV_SCRIPT), "--help"],
            cwd=outside_directory,
            capture_output=True,
            text=True,
            check=False,
        )

        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        assert result.returncode == 0
        assert "./dev.sh start [reload]" in result.stdout

    def test_dev_script_changes_to_project_root_before_using_relative_paths(self):
        """
        What it does: Inspects script initialization for project-root resolution.
        Purpose: Prevent imports like ``from kiro import config`` from failing outside the repo.
        """
        print("Action: Reading dev.sh content...")
        content = DEV_SCRIPT.read_text(encoding="utf-8")

        assert 'PROJECT_ROOT="$(cd -P "$(dirname "${SCRIPT_SOURCE}")"' in content
        assert 'cd "${PROJECT_ROOT}"' in content

    def test_dev_script_rejects_unknown_command_without_starting_server(self):
        """
        What it does: Calls an invalid command and checks for a usage error.
        Purpose: Ensure typos do not accidentally start a server.
        """
        print("Action: Running dev.sh with an invalid command...")
        result = subprocess.run(
            ["bash", str(DEV_SCRIPT), "invalid-command"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        assert result.returncode == 2
        assert "Unknown command: invalid-command" in result.stderr
        assert "Usage:" in result.stderr

    def test_dev_script_rejects_invalid_start_mode_without_starting_server(self):
        """
        What it does: Calls start with an unsupported mode.
        Purpose: Ensure only the explicit reload mode can enable hot reload.
        """
        print("Action: Running dev.sh start with invalid mode...")
        result = subprocess.run(
            ["bash", str(DEV_SCRIPT), "start", "hot"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        assert result.returncode == 2
        assert "Invalid start mode: hot" in result.stderr
        assert "Usage:" in result.stderr

    def test_dev_script_only_adds_reload_flag_for_reload_mode(self):
        """
        What it does: Inspects the script for conditional reload flag handling.
        Purpose: Guard the default start path from accidentally enabling hot reload.
        """
        print("Action: Reading dev.sh content...")
        content = DEV_SCRIPT.read_text(encoding="utf-8")

        assert 'if [[ "${mode}" == "reload" ]]' in content
        assert "command+=(--reload)" in content
        assert "start reload" in content
