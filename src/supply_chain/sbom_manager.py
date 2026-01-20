"""
SBOM Manager - Software Bill of Materials

Manages the software inventory across the fleet to enable:
- Vulnerability tracking and alerting
- License compliance
- Supply chain attack detection (e.g., Shai-Hulud)

SBOM Formats Supported:
- CycloneDX (preferred)
- SPDX
- Custom JSON format

The SBOM is critical for answering:
"Which devices are affected by vulnerability CVE-XXXX-YYYY?"
"""

import json
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class PackageType(Enum):
    """Types of software packages."""
    SYSTEM = "system"           # OS-level packages
    APPLICATION = "application"  # Installed applications
    LIBRARY = "library"         # Shared libraries
    BREW = "brew"              # Homebrew packages (macOS)
    NPM = "npm"                # Node.js packages
    PIP = "pip"                # Python packages


@dataclass
class Package:
    """
    Represents a software package in the SBOM.
    """
    name: str
    version: str
    package_type: PackageType
    
    # Package identifiers
    purl: Optional[str] = None  # Package URL (standard identifier)
    cpe: Optional[str] = None   # Common Platform Enumeration
    
    # Source information
    vendor: Optional[str] = None
    license: Optional[str] = None
    
    # Integrity
    checksum_sha256: Optional[str] = None
    
    # Metadata
    install_path: Optional[str] = None
    install_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "type": self.package_type.value,
            "purl": self.purl,
            "cpe": self.cpe,
            "vendor": self.vendor,
            "license": self.license,
            "checksum_sha256": self.checksum_sha256,
            "install_path": self.install_path,
            "install_date": self.install_date.isoformat() if self.install_date else None,
        }


@dataclass
class DeviceSBOM:
    """
    Software Bill of Materials for a device.
    
    Contains the complete inventory of software installed
    on a device, used for vulnerability correlation.
    """
    device_id: str
    serial_number: str
    platform: str
    os_version: str
    
    # Package inventory
    packages: List[Package] = field(default_factory=list)
    
    # SBOM metadata
    generated_at: datetime = field(default_factory=datetime.now)
    generator: str = "zero-trust-platform"
    format_version: str = "1.0"
    
    def to_cyclonedx(self) -> Dict:
        """Export as CycloneDX format."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{self.device_id}",
            "version": 1,
            "metadata": {
                "timestamp": self.generated_at.isoformat(),
                "tools": [{"name": self.generator, "version": self.format_version}],
                "component": {
                    "type": "device",
                    "name": self.serial_number,
                    "version": self.os_version,
                },
            },
            "components": [
                {
                    "type": pkg.package_type.value,
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": pkg.purl,
                    "hashes": [{"alg": "SHA-256", "content": pkg.checksum_sha256}]
                    if pkg.checksum_sha256 else [],
                }
                for pkg in self.packages
            ],
        }
    
    def get_package_names(self) -> Set[str]:
        """Get set of all package names."""
        return {pkg.name for pkg in self.packages}
    
    def has_package(self, name: str, version: Optional[str] = None) -> bool:
        """Check if device has a specific package."""
        for pkg in self.packages:
            if pkg.name.lower() == name.lower():
                if version is None or pkg.version == version:
                    return True
        return False


class SBOMManager:
    """
    Manages SBOM collection, storage, and querying.
    
    Key capabilities:
    - Collect SBOMs from devices (via MDM or agent)
    - Store and version SBOMs
    - Query for vulnerable packages across fleet
    - Track package changes over time
    
    Example:
        manager = SBOMManager()
        
        # Import SBOM from device
        sbom = manager.import_from_kandji("device-123")
        
        # Find devices with vulnerable package
        affected = manager.find_devices_with_package("log4j", "2.14.1")
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize SBOM manager.
        
        Args:
            storage_path: Directory for SBOM storage
        """
        self.storage_path = storage_path or Path("./sbom_data")
        self._sbom_cache: Dict[str, DeviceSBOM] = {}
    
    def generate_sbom(self, device_id: str, packages: List[Dict]) -> DeviceSBOM:
        """
        Generate SBOM from package list.
        
        Args:
            device_id: Device identifier
            packages: List of package dictionaries
            
        Returns:
            DeviceSBOM object
        """
        pkg_objects = []
        for pkg in packages:
            pkg_objects.append(Package(
                name=pkg.get("name", "unknown"),
                version=pkg.get("version", "0.0.0"),
                package_type=PackageType(pkg.get("type", "application")),
                purl=pkg.get("purl"),
                vendor=pkg.get("vendor"),
                license=pkg.get("license"),
                checksum_sha256=pkg.get("checksum"),
            ))
        
        sbom = DeviceSBOM(
            device_id=device_id,
            serial_number=f"SN-{device_id}",
            platform="macos",
            os_version="14.2.1",
            packages=pkg_objects,
        )
        
        self._sbom_cache[device_id] = sbom
        logger.info(f"Generated SBOM for {device_id} with {len(pkg_objects)} packages")
        
        return sbom
    
    def get_sbom(self, device_id: str) -> Optional[DeviceSBOM]:
        """Get SBOM for a device."""
        return self._sbom_cache.get(device_id)
    
    def find_devices_with_package(
        self,
        package_name: str,
        version: Optional[str] = None,
    ) -> List[str]:
        """
        Find all devices with a specific package.
        
        Critical for incident response - when a vulnerability
        is disclosed, quickly identify affected devices.
        """
        affected = []
        for device_id, sbom in self._sbom_cache.items():
            if sbom.has_package(package_name, version):
                affected.append(device_id)
        
        logger.info(
            f"Found {len(affected)} devices with {package_name}"
            f"{f' {version}' if version else ''}"
        )
        return affected
    
    def get_fleet_packages(self) -> Dict[str, int]:
        """
        Get aggregate package counts across fleet.
        
        Returns:
            Dict of package_name -> device_count
        """
        package_counts: Dict[str, int] = {}
        
        for sbom in self._sbom_cache.values():
            for pkg in sbom.packages:
                key = f"{pkg.name}@{pkg.version}"
                package_counts[key] = package_counts.get(key, 0) + 1
        
        return package_counts
    
    def export_fleet_sbom(self) -> Dict:
        """
        Export aggregate SBOM for entire fleet.
        
        Useful for compliance reporting and vendor security assessments.
        """
        all_packages = set()
        
        for sbom in self._sbom_cache.values():
            for pkg in sbom.packages:
                all_packages.add((pkg.name, pkg.version, pkg.vendor or "unknown"))
        
        return {
            "format": "fleet-sbom",
            "generated_at": datetime.now().isoformat(),
            "device_count": len(self._sbom_cache),
            "unique_packages": len(all_packages),
            "packages": [
                {"name": name, "version": ver, "vendor": vendor}
                for name, ver, vendor in sorted(all_packages)
            ],
        }
    
    def import_mock_data(self) -> None:
        """Load mock SBOM data for demonstration."""
        mock_packages = [
            {"name": "macOS", "version": "14.2.1", "type": "system", "vendor": "Apple"},
            {"name": "Google Chrome", "version": "120.0.6099.199", "type": "application", "vendor": "Google"},
            {"name": "Slack", "version": "4.35.126", "type": "application", "vendor": "Slack"},
            {"name": "1Password", "version": "8.10.22", "type": "application", "vendor": "AgileBits"},
            {"name": "CrowdStrike Falcon", "version": "7.10.17106", "type": "application", "vendor": "CrowdStrike"},
            {"name": "python", "version": "3.11.6", "type": "brew", "vendor": "Python Software Foundation"},
            {"name": "node", "version": "20.10.0", "type": "brew", "vendor": "Node.js Foundation"},
            {"name": "openssl", "version": "3.2.0", "type": "library", "vendor": "OpenSSL"},
            {"name": "zlib", "version": "1.3", "type": "library", "vendor": "zlib"},
        ]
        
        # Generate SBOMs for mock devices
        for i in range(5):
            device_id = f"device-{i+1:03d}"
            self.generate_sbom(device_id, mock_packages)


# Demo entry point
if __name__ == "__main__":
    manager = SBOMManager()
    manager.import_mock_data()
    
    print(f"\n{'='*60}")
    print("SBOM Manager Demo")
    print(f"{'='*60}")
    
    # Show fleet summary
    fleet = manager.export_fleet_sbom()
    print(f"\nFleet Summary:")
    print(f"  Devices: {fleet['device_count']}")
    print(f"  Unique Packages: {fleet['unique_packages']}")
    
    # Find devices with a specific package
    chrome_devices = manager.find_devices_with_package("Google Chrome")
    print(f"\nDevices with Chrome: {len(chrome_devices)}")
    
    # Export single device SBOM
    sbom = manager.get_sbom("device-001")
    if sbom:
        print(f"\nDevice 001 SBOM:")
        print(f"  Platform: {sbom.platform} {sbom.os_version}")
        print(f"  Packages: {len(sbom.packages)}")
    
    print(f"{'='*60}\n")
