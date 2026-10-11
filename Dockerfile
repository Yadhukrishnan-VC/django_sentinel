FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install DjangoSentinel from PyPI or use the source
# Option 1: Install from PyPI (recommended for production)
RUN pip install --no-cache-dir django-sentinel

# Option 2: Use source code (development)
# COPY . /app
# RUN pip install -e .

# Environment variables (set at runtime or via docker-compose/.env)
#   ANTHROPIC_API_KEY - for Anthropic Claude AI features
#   OPENAI_API_KEY - for OpenAI GPT-4/3.5 AI features
#   GOOGLE_API_KEY - for Google Gemini AI features
#   GITHUB_TOKEN - for GitHub PR integration (comments, check runs, inline annotations)
#   GITHUB_REPOSITORY - owner/repo format (e.g., "owner/repo")
#   GITHUB_SHA - commit SHA (for check runs)
#   GITHUB_REF - refs/pull/N/merge (for PR-aware scanning)

# Default command: run sentinel scan on the project directory
# The scanner will use the working directory or accept a path argument
CMD ["sentinel", "scan", "."]

# Show help by default
# ENTRYPOINT ["sentinel"]
