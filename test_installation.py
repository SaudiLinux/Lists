#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Installation Test Script for Cybersecurity Tool Manager
Author: SayerLinux (SaudiLinux1@gmail.com)
"""

import sys
import subprocess
import importlib

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        if package_name:
            importlib.import_module(package_name)
        else:
            importlib.import_module(module_name)
        print(f"✅ {module_name} - OK")
        return True
    except ImportError as e:
        print(f"❌ {module_name} - FAILED: {e}")
        return False

def test_system_command(command):
    """Test if a system command is available"""
    try:
        subprocess.run([command, '--version'], capture_output=True, check=True)
        print(f"✅ {command} - OK")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"❌ {command} - NOT FOUND")
        return False

def main():
    """Main test function"""
    print("🔍 Cybersecurity Tool Manager - Installation Test")
    print("=" * 50)
    
    # Test Python version
    print(f"Python Version: {sys.version}")
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher required!")
        return False
    else:
        print("✅ Python version - OK")
    
    print("\n📦 Testing Python Dependencies:")
    print("-" * 30)
    
    # Test Python packages
    dependencies = [
        ('python-nmap', 'nmap'),
        ('requests', 'requests'),
        ('urllib3', 'urllib3'),
        ('colorama', 'colorama'),
    ]
    
    all_passed = True
    for display_name, import_name in dependencies:
        if not test_import(display_name, import_name):
            all_passed = False
    
    print("\n🔧 Testing System Dependencies:")
    print("-" * 30)
    
    # Test system commands
    system_deps = ['nmap', 'ping']
    for dep in system_deps:
        if not test_system_command(dep):
            all_passed = False
    
    print("\n📋 Test Results:")
    print("-" * 30)
    
    if all_passed:
        print("✅ All tests passed! Installation is ready.")
        print("\n🚀 You can now run: python cybersecurity_tool_manager.py")
        return True
    else:
        print("❌ Some tests failed. Please check the installation.")
        print("\n🔧 To fix issues, run: install.bat")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)