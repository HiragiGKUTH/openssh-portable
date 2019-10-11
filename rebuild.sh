#!/bin/bash

# this action for refresh softlevel timestamp to launch sshd.
rc-status > /dev/null
touch /run/openrc/softlevel

# rebuild and reinstall
cd src/
make && make install

# restart sshd
rc-service sshd restart
