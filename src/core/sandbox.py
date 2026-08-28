"""
MalyxScanner — Windows Sandbox Integration Module
Generates ephemeral .wsb configurations with read-only folder mounts
and launches isolated testing environments with zero host exposure.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import xml.sax.saxutils
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("MalyxSandbox")


def is_windows_sandbox_available() -> Tuple[bool, str]:
    """
    Checks if Windows Sandbox is supported and enabled on the current system.
    Returns (is_available, reason_or_path).
    """
    if sys.platform != "win32":
        return False, "Windows Sandbox est uniquement disponible sous Windows 10/11 Pro, Entreprise ou Éducation."

    # Check for WindowsSandbox.exe executable
    system_root = os.getenv("SystemRoot", "C:\\Windows")
    sandbox_exe = Path(system_root) / "System32" / "WindowsSandbox.exe"

    if sandbox_exe.exists() and sandbox_exe.is_file():
        return True, str(sandbox_exe)

    # Fallback search on PATH
    which_sandbox = shutil.which("WindowsSandbox.exe")
    if which_sandbox:
        return True, which_sandbox

    return False, (
        "Windows Sandbox n'est pas activé sur cet ordinateur.\n\n"
        "Pour l'activer :\n"
        "1. Ouvrez le menu Démarrer et cherchez « Activer ou désactiver des fonctionnalités Windows ».\n"
        "2. Cochez la case « Bac à sable Windows » (Windows Sandbox).\n"
        "3. Cliquez sur OK et redémarrez votre ordinateur.\n\n"
        "(Note : Nécessite Windows 10/11 Pro/Entreprise et la virtualisation activée dans le BIOS/UEFI)."
    )


def generate_wsb_content(
    host_folder_path: str | Path,
    read_only: bool = True,
    auto_open_folder: bool = True,
) -> str:
    """
    Generates XML configuration content for a .wsb (Windows Sandbox) file.
    Mounts the specified host folder inside the sandbox.
    """
    host_folder = str(Path(host_folder_path).resolve())
    escaped_host_folder = xml.sax.saxutils.escape(host_folder)
    read_only_str = "true" if read_only else "false"

    sandbox_folder = r"C:\Users\WDAGUtilityAccount\Desktop\MalyxShared"
    escaped_sandbox_folder = xml.sax.saxutils.escape(sandbox_folder)

    logon_command_xml = ""
    if auto_open_folder:
        logon_command_xml = f"""
  <LogonCommand>
    <Command>explorer.exe "{escaped_sandbox_folder}"</Command>
  </LogonCommand>"""

    wsb_xml = f"""<Configuration>
  <VGpu>Default</VGpu>
  <Networking>Default</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{escaped_host_folder}</HostFolder>
      <SandboxFolder>{escaped_sandbox_folder}</SandboxFolder>
      <ReadOnly>{read_only_str}</ReadOnly>
    </MappedFolder>
  </MappedFolders>{logon_command_xml}
</Configuration>
"""
    return wsb_xml


def launch_in_windows_sandbox(file_path: str | Path) -> Tuple[bool, str]:
    """
    Creates an ephemeral .wsb file mounting the file's parent directory in read-only mode,
    and launches Windows Sandbox.
    """
    available, msg = is_windows_sandbox_available()
    if not available:
        return False, msg

    target_file = Path(file_path).resolve()
    if not target_file.exists():
        return False, f"Le fichier spécifié est introuvable : {target_file}"

    parent_dir = target_file.parent

    try:
        wsb_content = generate_wsb_content(
            host_folder_path=parent_dir,
            read_only=True,
            auto_open_folder=True,
        )

        # Write ephemeral .wsb configuration file to %TEMP%
        temp_dir = Path(tempfile.gettempdir())
        wsb_path = temp_dir / f"malyx_sandbox_{target_file.stem[:20]}.wsb"

        with open(wsb_path, "w", encoding="utf-8") as f:
            f.write(wsb_content)

        # Launch Windows Sandbox via OS file association or binary
        if sys.platform == "win32":
            os.startfile(str(wsb_path))
        else:
            subprocess.Popen(["WindowsSandbox.exe", str(wsb_path)])

        logger.info("Launched Windows Sandbox with configuration: %s", wsb_path)
        return True, "Windows Sandbox démarré avec succès en environnement isolé (Lecture seule)."

    except Exception as exc:
        logger.error("Failed to launch Windows Sandbox: %s", exc, exc_info=True)
        return False, f"Erreur lors du lancement de Windows Sandbox : {exc}"
