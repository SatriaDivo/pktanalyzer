#!/usr/bin/env python3
"""
Test build script for PktAnalyzer

This script tests if the package can be built and installed locally
before publishing to PyPI.
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"\n🔄 {description}...")
    print(f"   Command: {cmd}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} successful")
            if result.stdout.strip():
                print(f"   Output: {result.stdout.strip()}")
        else:
            print(f"❌ {description} failed")
            print(f"   Error: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"❌ {description} failed with exception: {e}")
        return False
    
    return True

def main():
    """Main test function."""
    print("🔍 PktAnalyzer Build Test")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("setup.py"):
        print("❌ setup.py not found. Please run from project root.")
        return False
    
    # List of commands to test
    commands = [
        ("python -m pip install --upgrade pip build twine", "Upgrade build tools"),
        ("python -m build", "Build package"),
        ("python -m twine check dist/*", "Check package"),
        ("python -c \"import pktanalyzer; print('Version:', pktanalyzer.__version__)\"", "Test import"),
    ]
    
    # Run each command
    for cmd, desc in commands:
        if not run_command(cmd, desc):
            print(f"\n💥 Build test failed at: {desc}")
            return False
    
    # List built files
    print(f"\n📦 Built files:")
    if os.path.exists("dist"):
        for file in os.listdir("dist"):
            print(f"   - dist/{file}")
    
    print(f"\n✅ All build tests passed!")
    print(f"\n📋 Next steps:")
    print(f"   1. Check GitHub Actions: https://github.com/SatriaDivo/pktanalyzer/actions")
    print(f"   2. Verify PyPI upload: https://pypi.org/project/pktanalyzer/")
    print(f"   3. Test install: pip install pktanalyzer")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)