#!/usr/bin/env python3
"""Verification script: Check all imports and module structure"""

import sys
import importlib
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

MODULES_TO_TEST = [
    # Core infrastructure
    "core",
    "core.config",
    "core.logger",
    "core.base_classes",

    # Collection
    "collection",
    "collection.models",

    # Detection
    "detection",
    "detection.ip_analysis",
    "detection.ip_analysis.models",
    "detection.yara",
    "detection.yara.models",
    "detection.sigma_lite",
    "detection.sigma_lite.models",
    "detection.correlation",
    "detection.correlation.threat_correlator",
    "detection.crash_detection",
    "detection.crash_detection.detector",

    # Integrations (CORE)
    "integrations",
    "integrations.braincell",
    "integrations.amalia",

    # Application
    "application",
    "application.implant_agent",
    "application.services",

    # Examples
    "examples",
]


def test_imports():
    """Test all module imports"""
    print("=" * 60)
    print("IMPORT VERIFICATION TEST")
    print("=" * 60)
    
    passed = 0
    failed = 0
    errors = []
    
    for module_name in MODULES_TO_TEST:
        try:
            importlib.import_module(module_name)
            print(f"[✓] {module_name}")
            passed += 1
        except ImportError as e:
            print(f"[✗] {module_name}: {e}")
            failed += 1
            errors.append((module_name, str(e)))
        except Exception as e:
            print(f"[!] {module_name}: {type(e).__name__}: {e}")
            failed += 1
            errors.append((module_name, f"{type(e).__name__}: {e}"))
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if errors:
        print("\nFailed modules:")
        for module_name, error in errors:
            print(f"  - {module_name}: {error}")
        return False
    
    return True


def test_key_classes():
    """Test instantiation of key classes (CORE framework only)"""
    print("\n" + "=" * 60)
    print("KEY CLASS INSTANTIATION TEST")
    print("=" * 60)

    tests = [
        ("ConfigManager", lambda: __import__("core").config.ConfigManager()),
        ("ImplantLogger", lambda: __import__("core").logger.ImplantLogger()),
        ("ThreatCorrelator", lambda: __import__("detection").correlation.ThreatCorrelator()),
        ("IPAnalyzer", lambda: __import__("detection").ip_analysis.IPAnalyzer()),
        ("YARADetector", lambda: __import__("detection").yara.YARADetector()),
        ("SigmaLiteDetector", lambda: __import__("detection").sigma_lite.SigmaLiteDetector()),
        ("ApplicationServices", lambda: __import__("application").services.ApplicationServices(__import__("core").config.ConfigManager())),
    ]
    
    passed = 0
    failed = 0
    
    for class_name, test_func in tests:
        try:
            instance = test_func()
            print(f"[✓] {class_name}")
            passed += 1
        except Exception as e:
            print(f"[✗] {class_name}: {e}")
            failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all verification tests"""
    print("\nStarting verification tests...\n")
    
    imports_ok = test_imports()
    classes_ok = test_key_classes()
    
    print("\n" + "=" * 60)
    if imports_ok and classes_ok:
        print("✓ ALL VERIFICATION TESTS PASSED")
        print("=" * 60)
        return 0
    else:
        print("✗ SOME VERIFICATION TESTS FAILED")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
