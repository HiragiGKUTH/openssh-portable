#!/bin/bash

cd /root/openssh-portable/src

echo "clean start..."
# cleaning...
make veryclean > /dev/null
pkill sshd3 > /dev/null
pkill rsyslogd
rm -rf /usr/sbin/sshd3

echo "done, rebuild start..."

# rebuild
autoconf && autoheader > /dev/null
echo "autotools done."
./configure --with-authtime > /dev/null
echo "configure done."
make sshd > /dev/null
echo "make sshd done."

echo "sshd install start..."
# install
mv sshd /usr/sbin/sshd3

# launch
/usr/sbin/rsyslogd
/usr/sbin/sshd3 -f /etc/ssh/sshd_config -h /etc/ssh/ssh_host_rsa_key

echo "all done"
