FROM ubuntu:latest
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo 'Europe/Berlin' > /etc/timezone
RUN apt update && apt install -y build-essential make libpam0g-dev net-tools python3 netcat wget lighttpd
ADD firmware_check_yml.sh /
RUN wget https://ftp.osuosl.org/pub/blfs/conglomeration/vsftpd/vsftpd-2.3.4.tar.gz && tar -xzvf vsftpd-2.3.4.tar.gz
WORKDIR /vsftpd-2.3.4
ENV LDFLAGS="-lpam"
RUN make
RUN install -v -m 755 vsftpd /usr/sbin/vsftpd && install -v -m 644 vsftpd.conf   /etc
WORKDIR /
ENTRYPOINT service lighttpd start && bash
