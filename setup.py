#!/usr/bin/env python3
"""
PktAnalyzer Setup Script

Installation script for PktAnalyzer packet analysis library.
"""

from setuptools import setup, find_packages
import sys

# Check Python version
if sys.version_info < (3, 8):
    sys.exit("PktAnalyzer requires Python 3.8 or higher")

# Read README for long description
def read_readme():
    """Read README.md for long description."""
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "A comprehensive packet capture and analysis library"

# Read version from __init__.py
def get_version():
    """Get version from package __init__.py"""
    try:
        with open("pktanalyzer/__init__.py", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"\'')
    except FileNotFoundError:
        pass
    return "1.0.0"

# Package metadata
NAME = "pktanalyzer"
VERSION = get_version()
DESCRIPTION = "A comprehensive packet capture and analysis library"
LONG_DESCRIPTION = read_readme()
AUTHOR = "SatriaDivo"
AUTHOR_EMAIL = "satriadivop354@gmail.com"
URL = "https://github.com/SatriaDivo/pktanalyzer"
LICENSE = "MIT"

# Core requirements
INSTALL_REQUIRES = [
    "scapy>=2.4.5",
    "matplotlib>=3.3.0",
    "numpy>=1.19.0",
]

# Optional dependencies
EXTRAS_REQUIRE = {
    "full": [
        "seaborn>=0.11.0",
        "pandas>=1.3.0",
        "plotly>=5.0.0",
    ],
    "visualization": [
        "seaborn>=0.11.0", 
        "plotly>=5.0.0",
    ],
    "analysis": [
        "pandas>=1.3.0",
    ],
    "dev": [
        "pytest>=6.0.0",
        "pytest-cov>=2.10.0",
        "black>=21.0.0",
        "flake8>=3.8.0",
    ]
}

# Classifiers for PyPI
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: Education",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License", 
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Networking",
    "Topic :: System :: Networking :: Monitoring",
    "Topic :: Security",
    "Topic :: Education",
]

# Keywords for PyPI
KEYWORDS = [
    "packet", "analysis", "network", "security", "scapy",
    "monitoring", "traffic", "capture", "visualization"
]

# Entry points for CLI commands
ENTRY_POINTS = {
    "console_scripts": [
        "pktanalyzer=pktanalyzer.cli:main",
    ]
}

# Setup configuration
setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    url=URL,
    license=LICENSE,
    
    # Package discovery
    packages=find_packages(),
    include_package_data=True,
    
    # Requirements
    python_requires=">=3.8",
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    
    # Entry points
    entry_points=ENTRY_POINTS,
    
    # Metadata
    classifiers=CLASSIFIERS,
    keywords=KEYWORDS,
    platforms=["any"],
    
    # Options
    zip_safe=False,
)

# Post-installation message
print("\n" + "="*50)
print("PktAnalyzer Installation Complete!")
print("="*50)
print("\nQuick Start:")
print("1. Install dependencies:")
print("   pip install scapy matplotlib numpy")
print("\n2. Run examples:")
print("   python examples/basic_sniff.py")
print("   python examples/analyze_pcap.py")
print("   python examples/live_monitor.py")
print("\nNote: Packet capture requires admin privileges")
print("="*50)