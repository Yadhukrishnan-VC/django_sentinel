from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="django-sentinel",
    version="1.0.0",
    author="DjangoSentinel",
    description="Enterprise AI Security Assistant for Python/Django — Finds and Fixes Vulnerabilities Before Production",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/django-sentinel",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "packaging>=21.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "sentinel=djangosentinel.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: Django",
    ],
    keywords="django security vulnerability scanner SAST",
)
