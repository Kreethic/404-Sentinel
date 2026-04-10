#!/usr/bin/env python3
"""
debug_modules.py - Diagnose module import issues
Run on Kali: python3 debug_modules.py
"""

import os
import sys

print("=" * 60)
print("MODULE IMPORT DIAGNOSTIC")
print("=" * 60 + "\n")

print(f"Python executable: {sys.executable}")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}\n")

# Check current directory
print("📁 Files in current directory:")
try:
    files = os.listdir(".")
    for f in sorted(files):
        if not f.startswith("__"):
            print(f"  - {f}")
except Exception as e:
    print(f"  ERROR: {e}")

print("\n📁 Looking for modules folder:")
if os.path.isdir("modules"):
    print("  ✓ modules/ folder FOUND")
    print("\n  Contents of modules/:")
    try:
        module_files = os.listdir("modules")
        for f in sorted(module_files):
            print(f"    - {f}")
    except Exception as e:
        print(f"    ERROR: {e}")
else:
    print("  ✗ modules/ folder NOT FOUND")
    print(f"  Expected at: {os.path.abspath('modules')}")

print("\n🔍 Python path:")
for i, path in enumerate(sys.path):
    print(f"  {i}: {path}")

print("\n" + "=" * 60)
print("ATTEMPTING IMPORT:")
print("=" * 60 + "\n")

try:
    from modules.ip_reputation import IPReputationChecker
    print("✓ SUCCESS: from modules.ip_reputation import IPReputationChecker")
except ModuleNotFoundError as e:
    print(f"✗ FAILED: {e}")
    print("\nTROUBLESHOOTING:")
    print("1. Run: ls -la modules/")
    print("2. Run: ls -la modules/__init__.py")
    print("3. Verify all 5 .py files exist in modules/")
