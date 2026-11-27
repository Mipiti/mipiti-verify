# Digest-pinned so a rebuild of the same commit resolves the same base
# image. Dependabot (docker ecosystem) bumps the digest.
FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b

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
