#!/bin/bash

echo "NEW BOX, TYPE THIS AFTER LOGIN TO VAGRANT DEV/TEST BOX:"
echo
echo "sudo chown -R ubuntu:ubuntu ~/.ssh/* && exit"
ssh -p 2222 ubuntu@localhost
ssh -p 2222 ubuntu@localhost "echo $(cat ~/.ssh/id_rsa.pub) > .ssh/authorized_keys"
scp -P 2222 Assessor-CLI-v4.0.21.zip ubuntu@localhost:
scp -P 2222 jre-8u261-linux-x64.tar.gz ubuntu@localhost:
ssh -p 2222 ubuntu@localhost "unzip Assessor-CLI-v4.0.21.zip"
ssh -p 2222 ubuntu@localhost "tar -zxvf jre-8u261-linux-x64.tar.gz"
ssh -p 2222 ubuntu@localhost "chmod 755 ~/Assessor-CLI/Assessor-CLI.sh"
clear
echo "cd ~/Assessor-CLI && sudo bash"
echo "export PATH=\$PATH:/home/ubuntu/jre1.8.0_261/bin && ./Assessor-CLI.sh -vvvvvv -b benchmarks/CIS_Ubuntu_Linux_18.04_LTS_Benchmark_v2.0.1-xccdf.xml && sudo chmod -R 755 reports && exit"
ssh -p 2222 ubuntu@localhost
scp -P 2222 ubuntu@localhost:~/Assessor-CLI/reports/* .
