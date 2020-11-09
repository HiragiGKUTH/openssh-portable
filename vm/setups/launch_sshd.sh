#!/bin/bash

cd ../../src
# ./configure --with-authtime
make clean
make sshd
mv ./sshd /usr/sbin/sshd3
/usr/sbin/rsyslogd
ssh-keygen -A
/usr/sbin/sshd3 -f /etc/ssh/sshd_config -h /etc/ssh/ssh_host_rsa_key

ssh localhost

tail -n 10 /var/log/messages