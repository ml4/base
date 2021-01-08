#!/bin/bash
curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key | tee -a ~ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu ~ubuntu/.ssh/authorized_keys
BBCPKTS=$(ping -c1 bbc.co.uk | grep transmitted | awk '{print $6}' | cut -d% -f1)
if [[ -n ${BBCPKTS} && ${BBCPKTS} == 0 ]]
then
  echo "PASS" | tee -a /var/tmp/baseUnitTest
else
  echo "FAIL" | tee -a /var/tmp/baseUnitTest
fi

