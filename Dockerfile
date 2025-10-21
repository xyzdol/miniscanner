# Minimal Dockerfile placeholder
FROM python:3.11-slim
WORKDIR /app
COPY . /app
# RUN pip install -r requirements.txt
CMD ["python", "src/app.py"]
