#!/bin/sh

set -e

a=123
b=124

sshpass -p 'root' ssh root@192.168.44.${a} 'pkill geomesh; rm -rf ~/geomesh;'
sshpass -p 'root' ssh root@192.168.44.${b} 'pkill geomesh; rm -rf ~/geomesh;'
sshpass -p 'root' scp -r ../geomesh root@192.168.44.${a}:~/
sshpass -p 'root' scp -r ../geomesh root@192.168.44.${b}:~/
sshpass -p 'root' ssh root@192.168.44.${a} 'cd ~/geomesh; make;'
sshpass -p 'root' ssh root@192.168.44.${b} 'cd ~/geomesh; make'
