from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass

# Optional imports for remote collection
try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    from smbclient import shutil as smb_shutil
    from smbclient import open_file as smb_open
    import smbclient
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False


# Default artifact paths on Windows systems
ARTIFACT_PATHS = {
    "evtx": {
        "Security": r"C:\Windows\System32\winevt\Logs\Security.evtx",
        "System": r"C:\Windows\System32\winevt\Logs\System.evtx",
        "Application": r"C:\Windows\System32\winevt\Logs\Application.evtx",
        "PowerShell-Operational": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
        "Sysmon": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
        "WinRM": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx",
        "TaskScheduler": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "TerminalServices": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    },
    "registry": {
        "SAM": r"C:\Windows\System32\config\SAM",
        "SYSTEM": r"C:\Windows\System32\config\SYSTEM",
        "SOFTWARE": r"C:\Windows\System32\config\SOFTWARE",
        "SECURITY": r"C:\Windows\System32\config\SECURITY",
        "DEFAULT": r"C:\Windows\System32\config\DEFAULT",
    },
    "other": {
        "Prefetch": r"C:\Windows\Prefetch",
        "Amcache": r"C:\Windows\AppCompat\Programs\Amcache.hve",
        "SRUM": r"C:\Windows\System32\sru\SRUDB.dat",
    },
}


@dataclass
class CollectionResult:
    success: bool
    artifact_name: str
    local_path: Optional[Path] = None
    remote_path: Optional[str] = None
    size_bytes: Optional[int] = None
    error: Optional[str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class WinRMCollector:
    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        port: int = 5985,
        use_ssl: bool = False,
        transport: str = "ntlm",
    ):
        if not WINRM_AVAILABLE:
            raise ImportError("pywinrm not installed. Install with: pip install pywinrm")

        if not password and not ntlm_hash:
            raise ValueError("Either password or ntlm_hash must be provided")

        if password and ntlm_hash:
            raise ValueError("Cannot use both password and ntlm_hash - choose one")

        self.host = host
        self.username = username
        self.port = port
        self.use_ssl = use_ssl

        if ntlm_hash:
            if ":" in ntlm_hash:
                auth_password = ntlm_hash
            else:
                auth_password = f"00000000000000000000000000000000:{ntlm_hash}"
            self.password = auth_password
            self.using_pth = True
        else:
            self.password = password
            self.using_pth = False

        protocol = "https" if use_ssl else "http"
        self.url = f"{protocol}://{host}:{port}/wsman"

        self.session = winrm.Session(
            self.url,
            auth=(username, self.password),
            transport=transport,
            server_cert_validation="ignore" if use_ssl else None,
        )
    
    def run_command(self, command: str) -> tuple[str, str, int]:
        result = self.session.run_ps(command)
        return (
            result.std_out.decode("utf-8", errors="replace"),
            result.std_err.decode("utf-8", errors="replace"),
            result.status_code,
        )
    
    def collect_file(
        self,
        remote_path: str,
        local_path: Path,
        use_shadow_copy: bool = True,
    ) -> CollectionResult:
        artifact_name = Path(remote_path).name
        
        try:
            if use_shadow_copy:
                ps_script = f'''
                $shadowPath = "{remote_path}"
                
                # Check if file exists
                if (-not (Test-Path $shadowPath)) {{
                    Write-Error "File not found: $shadowPath"
                    exit 1
                }}
                
                # Try to read directly first
                try {{
                    $content = [System.IO.File]::ReadAllBytes($shadowPath)
                    [Convert]::ToBase64String($content)
                }} catch {{
                    # If locked, try VSS
                    $vss = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\\", "ClientAccessible")
                    $shadow = Get-WmiObject Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1
                    $shadowRoot = $shadow.DeviceObject + "\\"
                    
                    $relativePath = $shadowPath -replace "^C:\\\\", ""
                    $vssPath = $shadowRoot + $relativePath
                    
                    $content = [System.IO.File]::ReadAllBytes($vssPath)
                    
                    # Clean up shadow copy
                    $shadow.Delete()
                    
                    [Convert]::ToBase64String($content)
                }}
                '''
            else:
                ps_script = f'''
                $path = "{remote_path}"
                if (-not (Test-Path $path)) {{
                    Write-Error "File not found: $path"
                    exit 1
                }}
                $content = [System.IO.File]::ReadAllBytes($path)
                [Convert]::ToBase64String($content)
                '''
            
            stdout, stderr, exit_code = self.run_command(ps_script)
            
            if exit_code != 0:
                return CollectionResult(
                    success=False,
                    artifact_name=artifact_name,
                    remote_path=remote_path,
                    error=stderr or f"Exit code: {exit_code}",
                )
            
            content = base64.b64decode(stdout.strip())

            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(content)
            
            return CollectionResult(
                success=True,
                artifact_name=artifact_name,
                local_path=local_path,
                remote_path=remote_path,
                size_bytes=len(content),
            )
            
        except Exception as e:
            return CollectionResult(
                success=False,
                artifact_name=artifact_name,
                remote_path=remote_path,
                error=str(e),
            )
    
    def list_evtx_files(self) -> list[dict[str, Any]]:
        ps_script = '''
        Get-ChildItem -Path "C:\\Windows\\System32\\winevt\\Logs" -Filter "*.evtx" | 
        Select-Object Name, FullName, Length, LastWriteTime |
        ConvertTo-Json
        '''
        stdout, stderr, exit_code = self.run_command(ps_script)
        
        if exit_code != 0:
            raise RuntimeError(f"Failed to list EVTX files: {stderr}")

        files = json.loads(stdout)
        if isinstance(files, dict):
            files = [files]
        
        return [{
            "name": f["Name"],
            "path": f["FullName"],
            "size_bytes": f["Length"],
            "modified": f["LastWriteTime"],
        } for f in files]
    
    def get_system_info(self) -> dict[str, Any]:
        ps_script = '''
        @{
            ComputerName = $env:COMPUTERNAME
            Domain = (Get-WmiObject Win32_ComputerSystem).Domain
            OS = (Get-WmiObject Win32_OperatingSystem).Caption
            Version = (Get-WmiObject Win32_OperatingSystem).Version
            Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
            LastBoot = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
            Users = (Get-WmiObject Win32_UserAccount | Select-Object Name, SID, Disabled)
        } | ConvertTo-Json
        '''
        stdout, stderr, exit_code = self.run_command(ps_script)
        
        if exit_code != 0:
            raise RuntimeError(f"Failed to get system info: {stderr}")

        return json.loads(stdout)


class SSHCollector:
    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
    ):
        if not PARAMIKO_AVAILABLE:
            raise ImportError("paramiko not installed. Install with: pip install paramiko")
        
        self.host = host
        self.username = username
        self.port = port
        
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": username,
        }
        
        if key_path:
            connect_kwargs["key_filename"] = key_path
        elif password:
            connect_kwargs["password"] = password
        
        self.client.connect(**connect_kwargs)
        self.sftp = self.client.open_sftp()

    def run_command(self, command: str) -> tuple[str, str, int]:
        stdin, stdout, stderr = self.client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        return (
            stdout.read().decode("utf-8", errors="replace"),
            stderr.read().decode("utf-8", errors="replace"),
            exit_code,
        )
    
    def collect_file(
        self,
        remote_path: str,
        local_path: Path,
    ) -> CollectionResult:
        artifact_name = Path(remote_path).name
        
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            self.sftp.get(remote_path, str(local_path))
            
            size = local_path.stat().st_size
            
            return CollectionResult(
                success=True,
                artifact_name=artifact_name,
                local_path=local_path,
                remote_path=remote_path,
                size_bytes=size,
            )
        except Exception as e:
            return CollectionResult(
                success=False,
                artifact_name=artifact_name,
                remote_path=remote_path,
                error=str(e),
            )
    
    def close(self):
        self.sftp.close()
        self.client.close()


class SMBCollector:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "",
    ):
        if not SMB_AVAILABLE:
            raise ImportError("smbprotocol not installed. Install with: pip install smbprotocol")
        
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        
        # Register the session
        smbclient.register_session(
            host,
            username=username,
            password=password,
            domain=domain,
        )
    
    def collect_file(
        self,
        remote_path: str,
        local_path: Path,
        share: str = "C$",
    ) -> CollectionResult:
        artifact_name = Path(remote_path).name

        if remote_path.startswith("C:\\"):
            remote_path = remote_path[3:]
        
        smb_path = f"\\\\{self.host}\\{share}\\{remote_path}"
        
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            smb_shutil.copy(smb_path, str(local_path))
            
            size = local_path.stat().st_size
            
            return CollectionResult(
                success=True,
                artifact_name=artifact_name,
                local_path=local_path,
                remote_path=smb_path,
                size_bytes=size,
            )
        except Exception as e:
            return CollectionResult(
                success=False,
                artifact_name=artifact_name,
                remote_path=smb_path,
                error=str(e),
            )


def collect_triage_package(
    collector: WinRMCollector | SSHCollector | SMBCollector,
    output_dir: Path,
    include_evtx: bool = True,
    include_registry: bool = True,
    include_prefetch: bool = False,
) -> list[CollectionResult]:
    results = []
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if include_evtx:
        evtx_dir = output_dir / "evtx"
        evtx_dir.mkdir(exist_ok=True)
        
        for name, path in ARTIFACT_PATHS["evtx"].items():
            local_path = evtx_dir / f"{name}.evtx"
            
            if isinstance(collector, WinRMCollector):
                result = collector.collect_file(path, local_path, use_shadow_copy=True)
            else:
                result = collector.collect_file(path, local_path)
            
            results.append(result)

    if include_registry:
        reg_dir = output_dir / "registry"
        reg_dir.mkdir(exist_ok=True)
        
        for name, path in ARTIFACT_PATHS["registry"].items():
            local_path = reg_dir / name
            
            if isinstance(collector, WinRMCollector):
                result = collector.collect_file(path, local_path, use_shadow_copy=True)
            else:
                result = collector.collect_file(path, local_path)
            
            results.append(result)
    
    return results
