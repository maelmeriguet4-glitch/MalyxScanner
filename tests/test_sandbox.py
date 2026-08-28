"""
Unit tests for the Windows Sandbox integration module (core/sandbox.py).
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.sandbox import (
    generate_wsb_content,
    is_windows_sandbox_available,
    launch_in_windows_sandbox,
)


class TestWindowsSandboxModule(unittest.TestCase):
    def test_generate_wsb_content_read_only(self):
        folder = Path("C:/TestThreats")
        wsb = generate_wsb_content(folder, read_only=True, auto_open_folder=True)

        self.assertIn("<Configuration>", wsb)
        self.assertIn("</Configuration>", wsb)
        self.assertIn("<ReadOnly>true</ReadOnly>", wsb)
        self.assertIn("<MappedFolder>", wsb)
        self.assertIn("<LogonCommand>", wsb)
        self.assertIn("explorer.exe", wsb)

    def test_generate_wsb_content_read_write(self):
        folder = Path("C:/TestThreats")
        wsb = generate_wsb_content(folder, read_only=False, auto_open_folder=False)

        self.assertIn("<ReadOnly>false</ReadOnly>", wsb)
        self.assertNotIn("<LogonCommand>", wsb)

    @patch("core.sandbox.is_windows_sandbox_available")
    def test_launch_sandbox_when_unavailable(self, mock_available):
        mock_available.return_value = (False, "Sandbox disabled")

        success, msg = launch_in_windows_sandbox("C:/some_file.exe")
        self.assertFalse(success)
        self.assertEqual(msg, "Sandbox disabled")

    @patch("core.sandbox.is_windows_sandbox_available")
    def test_launch_sandbox_missing_file(self, mock_available):
        mock_available.return_value = (True, "C:/Windows/System32/WindowsSandbox.exe")

        success, msg = launch_in_windows_sandbox("C:/nonexistent_threat_file_xyz.exe")
        self.assertFalse(success)
        self.assertIn("introuvable", msg)


if __name__ == "__main__":
    unittest.main()
