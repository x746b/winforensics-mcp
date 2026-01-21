from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# Limits for query results to avoid overwhelming LLM context
MAX_EVTX_RESULTS = 50
MAX_REGISTRY_RESULTS = 50
MAX_SCAN_EVENTS = 10000  # Max events to scan in a single file
MAX_PREFETCH_RESULTS = 20
MAX_AMCACHE_RESULTS = 30
MAX_TIMELINE_RESULTS = 50
MAX_MFT_RESULTS = 30
MAX_USN_RESULTS = 30

# Default paths for Windows artifacts (when analyzing mounted images or remote shares)
WINDOWS_ARTIFACT_PATHS = {
    "evtx": [
        r"Windows\System32\winevt\Logs",
        r"Windows\System32\config",
    ],
    "registry": {
        "SAM": r"Windows\System32\config\SAM",
        "SYSTEM": r"Windows\System32\config\SYSTEM",
        "SOFTWARE": r"Windows\System32\config\SOFTWARE",
        "SECURITY": r"Windows\System32\config\SECURITY",
        "DEFAULT": r"Windows\System32\config\DEFAULT",
        "NTUSER": r"Users\{user}\NTUSER.DAT",
        "USRCLASS": r"Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat",
    },
    "prefetch": r"Windows\Prefetch",
    "amcache": r"Windows\AppCompat\Programs\Amcache.hve",
}

# Common forensically-relevant Event IDs
IMPORTANT_EVENT_IDS = {
    "Security": {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4634: "Logoff",
        4648: "Explicit Credential Logon",
        4672: "Special Privileges Assigned",
        4688: "Process Creation",
        4689: "Process Termination",
        4697: "Service Installed",
        4698: "Scheduled Task Created",
        4699: "Scheduled Task Deleted",
        4700: "Scheduled Task Enabled",
        4701: "Scheduled Task Disabled",
        4702: "Scheduled Task Updated",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4723: "Password Change Attempted",
        4724: "Password Reset Attempted",
        4725: "User Account Disabled",
        4726: "User Account Deleted",
        4732: "Member Added to Local Group",
        4733: "Member Removed from Local Group",
        4738: "User Account Changed",
        4756: "Member Added to Universal Group",
        4768: "Kerberos TGT Requested",
        4769: "Kerberos Service Ticket Requested",
        4770: "Kerberos Service Ticket Renewed",
        4771: "Kerberos Pre-Auth Failed",
        4776: "NTLM Authentication",
        4778: "Session Reconnected",
        4779: "Session Disconnected",
        1102: "Audit Log Cleared",
    },
    "System": {
        7034: "Service Crashed",
        7035: "Service Control Manager",
        7036: "Service Started/Stopped",
        7040: "Service Start Type Changed",
        7045: "New Service Installed",
        104: "Event Log Cleared",
    },
    "PowerShell": {
        4103: "Module Logging",
        4104: "Script Block Logging",
        4105: "Script Start",
        4106: "Script Stop",
    },
    "Sysmon": {
        1: "Process Creation",
        2: "File Creation Time Changed",
        3: "Network Connection",
        5: "Process Terminated",
        6: "Driver Loaded",
        7: "Image Loaded",
        8: "CreateRemoteThread",
        9: "RawAccessRead",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "Registry Event (Create/Delete)",
        13: "Registry Value Set",
        14: "Registry Key/Value Rename",
        15: "FileCreateStreamHash",
        17: "Pipe Created",
        18: "Pipe Connected",
        19: "WmiEventFilter",
        20: "WmiEventConsumer",
        21: "WmiEventConsumerToFilter",
        22: "DNS Query",
        23: "FileDelete",
        25: "ProcessTampering",
        26: "FileDeleteDetected",
    },
}

# Registry keys of forensic interest
FORENSIC_REGISTRY_KEYS = {
    "persistence": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ],
    "services": [
        r"SYSTEM\CurrentControlSet\Services",
    ],
    "network": [
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
    ],
    "usb": [
        r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        r"SYSTEM\CurrentControlSet\Enum\USB",
    ],
    "user_activity": [
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    ],
    "system_info": [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
        r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
    ],
    "shimcache": [
        r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
    ],
    "amcache": [
        r"Amcache.hve\Root\File",
        r"Amcache.hve\Root\InventoryApplicationFile",
    ],
}


@dataclass
class ForensicsConfig:
    """Configuration for forensics analysis"""
    
    # Base path for artifacts (mounted image, share, or local path)
    artifacts_base: Optional[Path] = None
    
    # Output directory for reports
    output_dir: Path = field(default_factory=lambda: Path("./forensics_output"))
    
    # Limits
    max_evtx_results: int = MAX_EVTX_RESULTS
    max_registry_results: int = MAX_REGISTRY_RESULTS
    max_scan_events: int = MAX_SCAN_EVENTS
    
    # Time zone for timestamp normalization (e.g., "UTC", "America/New_York")
    timezone: str = "UTC"
    
    # YARA rules directory
    yara_rules_dir: Optional[Path] = None
    
    # Remote connection settings
    remote_host: Optional[str] = None
    remote_user: Optional[str] = None
    remote_password: Optional[str] = None
    remote_method: str = "winrm"  # winrm, ssh, smb
    
    def __post_init__(self):
        if self.artifacts_base:
            self.artifacts_base = Path(self.artifacts_base)
        self.output_dir = Path(self.output_dir)
        if self.yara_rules_dir:
            self.yara_rules_dir = Path(self.yara_rules_dir)


# Global config instance
_config: Optional[ForensicsConfig] = None


def get_config() -> ForensicsConfig:
    """Get or create the global configuration"""
    global _config
    if _config is None:
        _config = ForensicsConfig()
    return _config


def set_config(config: ForensicsConfig) -> None:
    """Set the global configuration"""
    global _config
    _config = config
