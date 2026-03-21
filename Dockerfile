FROM python:3.12-slim

COPY . /action
RUN pip install --no-cache-dir "/action[all]"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
