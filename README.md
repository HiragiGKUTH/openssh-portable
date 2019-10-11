# Portable OpenSSH

## purpose

This application is forked from openssh-portable.

Modify this program for measure authorication duration time on sshd using password.

## how to develop

### first time

1. clone this repository
2. install docker and docker-compose
3. run `docker-compose build` and `docker-compose up -d`

### on development

1. modify source code
2. vm/login.sh to login container
3. in container, run rebuild.sh
4. sshd server is now runnning!
5. return to 1.

