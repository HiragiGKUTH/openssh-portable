FROM alpine as sshd-linux

WORKDIR /root
RUN apk update && apk add --no-cache openssh openrc gcc g++ make openssl-dev zlib-dev bash rsyslog
#user
RUN echo 'root:root' |chpasswd
RUN adduser -S koba \
    && echo "koba ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && echo 'koba:koba' | chpasswd

#rsyslog enable
RUN rsyslogd

ENTRYPOINT ["/bin/bash"]
