FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

WORKDIR /app

COPY . .

RUN python -m pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "-m", "mcp_defender.server"]