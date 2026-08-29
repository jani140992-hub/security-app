from setuptools import setup, find_packages

setup(
    name="aegisguard",
    version="1.0.0",
    description="Enterprise Cyber Defense, SIEM Correlation & Threat Intelligence Platform",
    author="jani140992-hub",
    author_email="jani140992-hub@users.noreply.github.com",
    packages=find_packages(include=["aegisguard", "aegisguard.*"]),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "aegis=aegisguard.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
