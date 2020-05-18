#!/bin/sh

set -e

sshpass -p 'root' ssh root@192.168.44.121 'pkill geomesh; rm -rf ~/geomesh;'
sshpass -p 'root' ssh root@192.168.44.122 'pkill geomesh; rm -rf ~/geomesh;'
sshpass -p 'root' scp -r ../geomesh root@192.168.44.121:~/
sshpass -p 'root' scp -r ../geomesh root@192.168.44.122:~/
sshpass -p 'root' ssh root@192.168.44.121 'cd ~/geomesh; make;'
sshpass -p 'root' ssh root@192.168.44.122 'cd ~/geomesh; make'
