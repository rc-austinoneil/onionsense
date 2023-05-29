FROM ubuntu:22.04

# Make code directory where the code will live
RUN mkdir /code

ARG DEBIAN_FRONTEND=noninteractive

# Install all required dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    cron \
    tzdata \
    dnsutils \
    ntp

# Set timezone
ENV TZ=America/New_York
RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime
RUN dpkg-reconfigure -f noninteractive tzdata
RUN service ntp start
RUN date

# Copy project to docker image
COPY ./src /code

# Set env file location
ENV ENVLOCATION="/code/.env"

# Setup Python Venv
COPY ./requirements.txt /code/requirements.txt
RUN python3 -m venv /code/venv
RUN /code/venv/bin/python3 -m pip install --no-cache-dir -r /code/requirements.txt

# Make everything executable
RUN chmod +x /code/main.py

# Register cron jobs to start the applications and redirects their stdout/stderr
# to the stdout/stderr of the entry process by adding lines to /etc/crontab
RUN echo "SHELL=/bin/bash" >> /etc/crontab
RUN echo "*/15 * * * * root /code/venv/bin/python3 /code/main.py > /proc/1/fd/1 2>/proc/1/fd/2" >> /etc/crontab

# Start cron in foreground (don't fork)
ENTRYPOINT [ "cron", "-f" ]

