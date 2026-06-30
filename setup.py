from setuptools import setup, find_packages

setup(
    name="scamshield-ai",
    version="0.1.0",
    description="Multi-agent scam protection system with MCP tools, Google ADK integration, and a CLI",
    author="ScamShield Team",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*", "demo*", "docs*"]),
    install_requires=[
        "anthropic>=0.40.0",
        "mcp>=1.0.0",
        "google-adk>=0.3.0",
        "python-dotenv>=1.0.0",
        "click>=8.1.0",
        "httpx>=0.27.0",
        "pydantic>=2.0.0",
        "uvicorn>=0.29.0",
        "fastapi>=0.110.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0.0", "pytest-asyncio>=0.23.0"],
    },
    entry_points={
        "console_scripts": [
            "scamshield=cli.scamshield_cli:main",
        ],
    },
    package_data={
        "mcp_server": ["resources/*.json"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
