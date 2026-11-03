FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
COPY said ./said
COPY alembic.ini .
COPY migrations ./migrations
RUN pip install --no-cache-dir .
RUN useradd -r -u 10001 said
USER said
EXPOSE 8000
CMD ["uvicorn","said.main:app","--host","0.0.0.0","--port","8000"]
