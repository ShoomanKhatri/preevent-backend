# Use official Python image
FROM python:3.11-slim

# Don't write .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Print logs directly
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies (optional but good for debugging or building dependencies)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev netcat && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project files
COPY . .

# Default run command (for development)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
