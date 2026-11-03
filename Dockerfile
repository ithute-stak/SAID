FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY said ./said
RUN useradd -r -u 10001 said
USER said
EXPOSE 8000
CMD ["uvicorn","said.main:app","--host","0.0.0.0","--port","8000"]
