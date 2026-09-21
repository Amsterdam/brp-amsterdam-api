FROM ghcr.io/brp-api/personen-mock:2.7.0-202609171305

USER root
RUN apk update && apk add --no-cache curl

ARG JSON_URL
RUN curl -L ${JSON_URL} -o /app/Data/test-data.json

USER brp-api-user
