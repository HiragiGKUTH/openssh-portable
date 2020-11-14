#!/bin/bash

cd /root/openssh-portable/src

pkill sshd3
pkill rsyslog

rm -rf /usr/sbin/sshd3

make sshd

# install
mv sshd /usr/sbin/sshd3
# relaunch
/usr/sbin/rsyslogd
/usr/sbin/sshd3 -f /etc/ssh/sshd_config -h /etc/ssh/ssh_host_rsa_key
