# Digest-pinned so a rebuild of the same commit resolves the same base
# image. Dependabot (docker ecosystem) bumps the digest.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

COPY requirements-all.lock /tmp/requirements-all.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-all.lock

COPY . /action
RUN pip install --no-cache-dir --no-deps "/action[all]"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Hardening: run as non-root user (CTRL-14)
RUN useradd --create-home --shell /bin/bash verifier
USER verifier

ENTRYPOINT ["/entrypoint.sh"]
