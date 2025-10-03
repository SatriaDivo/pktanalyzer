#!/usr/bin/env python3
"""
GitHub Actions Status Monitor

Script untuk monitor status GitHub Actions dan memberikan info tentang build.
"""

import subprocess
import sys
import webbrowser

def open_github_actions():
    """Open GitHub Actions page in browser."""
    repo_url = "https://github.com/SatriaDivo/pktanalyzer"
    actions_url = f"{repo_url}/actions"
    
    print(f"🔗 Opening GitHub Actions: {actions_url}")
    webbrowser.open(actions_url)

def check_git_status():
    """Check local git status."""
    try:
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print("📝 Local changes detected:")
            print(result.stdout)
        else:
            print("✅ Working directory clean")
            
        # Check current branch and last commit
        branch_result = subprocess.run(['git', 'branch', '--show-current'], 
                                     capture_output=True, text=True)
        print(f"🌿 Current branch: {branch_result.stdout.strip()}")
        
        # Last commit
        commit_result = subprocess.run(['git', 'log', '--oneline', '-1'], 
                                     capture_output=True, text=True)
        print(f"📝 Last commit: {commit_result.stdout.strip()}")
        
    except Exception as e:
        print(f"❌ Error checking git status: {e}")

def show_build_info():
    """Show build and deployment information."""
    print("\n📊 PktAnalyzer Build Status")
    print("=" * 50)
    
    print("\n🔄 GitHub Actions Workflows:")
    print("  CI: Tests on every push to main")
    print("  Publish: Deploys to PyPI on tags")
    
    print("\n🎯 PyPI Deployment:")
    print("  Project: https://pypi.org/project/pktanalyzer/")
    print("  Test: https://test.pypi.org/project/pktanalyzer/")
    
    print("\n📋 To trigger PyPI deployment:")
    print("  1. Create new tag: git tag v1.0.1")
    print("  2. Push tag: git push origin v1.0.1")
    print("  3. Or create GitHub Release")
    
    print("\n🔍 Monitoring URLs:")
    print("  Actions: https://github.com/SatriaDivo/pktanalyzer/actions")
    print("  Repository: https://github.com/SatriaDivo/pktanalyzer")

def main():
    """Main function."""
    print("🔍 PktAnalyzer GitHub Actions Monitor")
    print("=" * 50)
    
    check_git_status()
    show_build_info()
    
    choice = input("\n🌐 Open GitHub Actions in browser? (y/N): ").strip().lower()
    if choice == 'y':
        open_github_actions()
    
    print("\n✅ Done! Check GitHub Actions for build status.")

if __name__ == "__main__":
    main()