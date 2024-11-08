FROM ubuntu:24.04

WORKDIR /opt/loboguara
COPY . .
RUN mkdir -p /opt/loboguara/bin /opt/loboguara/app

# Installing all the necessary APT packages
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y python3 python3-pip python3-venv libpq-dev python3-dev redis-server build-essential zip wget curl sudo postgresql postgresql-contrib 

# Install the chrome and chromedriver
RUN wget -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN dpkg -i /tmp/google-chrome.deb || apt-get install -f -y
RUN ln -sf /usr/bin/google-chrome /opt/loboguara/bin/google-chrome

RUN wget -O /tmp/chromedriver.zip https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/129.0.6668.89/linux64/chromedriver-linux64.zip
RUN unzip /tmp/chromedriver.zip -d /tmp/
RUN mv /tmp/chromedriver-linux64/ /opt/loboguara/bin/chromedriver_dir
RUN chmod +x /opt/loboguara/bin/chromedriver_dir/chromedriver
RUN ln -sf /opt/loboguara/bin/chromedriver_dir/chromedriver /opt/loboguara/bin/chromedriver

# Install subfinder
RUN wget -O /tmp/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip
RUN unzip /tmp/subfinder.zip -d /tmp/
RUN mv /tmp/subfinder /opt/loboguara/bin/
RUN chmod +x /opt/loboguara/bin/subfinder

# Install FFUF
RUN wget -O /tmp/ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_linux_amd64.tar.gz
RUN tar -xvzf /tmp/ffuf.tar.gz -C /tmp/
RUN mv /tmp/ffuf /opt/loboguara/bin/
RUN chmod +x /opt/loboguara/bin/ffuf

# Install the application

RUN chmod +x ./run_via_docker.sh

RUN adduser --disabled-password --gecos '' guarauser
RUN adduser guarauser sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN chown guarauser:guarauser -R /opt/loboguara

EXPOSE 7405
USER guarauser

CMD [ "/opt/loboguara/run_via_docker.sh" ]