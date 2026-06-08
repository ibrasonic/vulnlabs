FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY email_service.py ./
ENV PORT=5002 HOST=0.0.0.0
EXPOSE 5002
CMD ["python", "email_service.py"]
