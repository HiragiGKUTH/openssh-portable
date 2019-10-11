FROM alpine as sshd-linux

WORKDIR /root
RUN apk update && apk add --no-cache openssh openrc gcc g++ make openssl-dev zlib-dev bash
ENTRYPOINT ["/bin/bash"]
