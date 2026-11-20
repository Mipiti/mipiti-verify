# Digest-pinned so a rebuild of the same commit resolves the same base
# image. Dependabot (docker ecosystem) bumps the digest.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

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
