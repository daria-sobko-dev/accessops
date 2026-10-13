# accessops-api: the AccessOps code plus a tiny HTTP API for n8n.
# No secrets in the image: the Ansible key arrives at runtime as a compose secret,
# passwords and the API token as environment variables.
FROM python:3.12-slim

# ssh client: Ansible reaches linux-target over SSH.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin accessops

WORKDIR /app

# Dependencies first (cached layer): read them from pyproject.toml, no second list to keep.
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" > /tmp/requirements.txt \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY accessops/ accessops/
COPY ansible/ ansible/
COPY ansible.cfg roles.yaml ./
COPY docker/accessops-api/entrypoint.sh /usr/local/bin/accessops-api-entrypoint

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER accessops
EXPOSE 8000
ENTRYPOINT ["accessops-api-entrypoint"]
CMD ["python", "-m", "accessops.api"]
