"""
NetSentinel - Setup Configuration
Network Log Analyzer & Intrusion Detection System
"""

from setuptools import setup, find_packages
from pathlib import Path

README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="netsentinel", 
    version="1.0.0",
    description="Network Log Analyzer & Intrususion Detection System (NIDS)",
    long_description=README,
    author="Security Team",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "PyYAML>=6.0.1",
        "numpy>=1.24.0",
    ],
    entry_points={
        "console_scripts": [
            "netsentinel=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 -Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",        
    ],
)