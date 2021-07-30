# syntax=docker/dockerfile:1
FROM python:3.8-slim-buster

COPY . /app
WORKDIR /app
RUN pip3 install .
CMD [ "python3", "-m", "bitsserver", "80"]
