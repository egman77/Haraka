# NOTICE: This is user-contributed and not officially supported by the Haraka team. Use at your own risk.
#
# This file describes how to build Haraka into a runnable linux container with all dependencies installed
# To build:
# 1.) Install docker (http://docker.io)
# 2.) Clone Haraka repo if you haven't already: git clone https://github.com/haraka/Haraka.git
# 3.) Modify config/host_list with the domain(s) that you'd like to receive mail to
# 4.) Build: cd Haraka && docker build .
# 5.) Run:
# docker run -d <imageid>
#
# VERSION           0.1
# DOCKER-VERSION    0.5.3

# See http://phusion.github.io/baseimage-docker/
FROM phusion/baseimage:focal-1.2.0

MAINTAINER Justin Plock <jplock@gmail.com>

ENV HOME /root

RUN /etc/my_init.d/00_regen_ssh_host_keys.sh

RUN sed 's/main$/main universe/' -i /etc/apt/sources.list
RUN sed -i 's|http://.*archive.ubuntu.com|https://mirrors.aliyun.com|g' /etc/apt/sources.list && \
    sed -i 's|http://.*security.ubuntu.com|https://mirrors.aliyun.com|g' /etc/apt/sources.list && \
    sed 's/main$/main universe/' -i /etc/apt/sources.list
RUN DEBIAN_FRONTEND=noninteractive apt-get -y -q update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y -q install software-properties-common g++ make git curl
RUN curl -sL https://deb.nodesource.com/setup_18.x | setuser root bash -
RUN DEBIAN_FRONTEND=noninteractive apt-get -y -q install nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Optional, useful for development
# See https://github.com/phusion/baseimage-docker#login_ssh
#RUN rm -f /etc/service/sshd/down
#RUN /usr/sbin/enable_insecure_key

# Install Haraka
# RUN npm install -g Haraka --unsafe
# RUN haraka -i /usr/local/haraka
# ADD ./config/host_list /usr/local/haraka/config/host_list
# ADD ./config/plugins /usr/local/haraka/config/plugins
# ADD ./config/log.ini /usr/local/haraka/config/log.ini
# RUN cd /usr/local/haraka && npm install

# 将当前项目代码复制到镜象目录中
COPY . /usr/local/haraka

# 进入项目目录并安装依赖
WORKDIR /usr/local/haraka
RUN DEBIAN_FRONTEND=noninteractive npm install

#初始化 Harak

# Create haraka runit service
RUN mkdir /etc/service/haraka
ADD haraka.sh /etc/service/haraka/run

EXPOSE 25

# Start the init daemon - runit will launch the Haraka process
CMD ["/sbin/my_init"]
