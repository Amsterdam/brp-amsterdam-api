FROM ghcr.io/brp-api/personen-mock:2.6.0-202502261446

ARG JSON_URL

USER root
RUN sed -i 's+http://deb+https://deb+g' /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources || true
RUN apt-get update && apt-get install -y curl
RUN curl -L ${JSON_URL} -o /app/Data/test-data.json
USER brp-api-user
