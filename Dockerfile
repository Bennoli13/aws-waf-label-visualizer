FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Expose port
EXPOSE 5001

# Start the app
CMD ["python", "app.py"]
