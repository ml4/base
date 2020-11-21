#!/bin/bash

if [ -z "$(command -v packer)" ]
then
  echo "Install Packer first"
  exit 1
fi

if  [ -n "${S3_BUCKET}" ]
then
  aws s3api list-buckets --query "Buckets[].Name" | tr '\t' '\012' | grep ^${S3_BUCKET}$
  rCode=${?}
  if [ ${rCode} -gt 0 ]
  then
    echo "ERROR: S3 bucket ${S3_BUCKET} does not exist - create it first"
    exit 1
  fi
  aws iam get-role --role-name vmimport >/dev/null 2>&1
  rCode=${?}
  if [ ${rCode} -gt 0 ]
  then
    cat role-policy.src | sed "s/%%S3_BUCKET%%/${S3_BUCKET}/g" > role-policy.json
    aws iam create-role --role-name vmimport --assume-role-policy-document file://trust-policy.json
    aws iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document file://role-policy.json
  fi
else
  echo "ERROR: S3_BUCKET is not set"
  exit 1
fi

if [ -n "${GRUB_PASSWORD}" -a -n "${GMAIL}" -a -n "${GMAILPASSWORD}" -a -n "${HOST}" -a -n "${DOMAIN}" -a -n "${AWS_ACCESS_KEY_ID}" -a -n "${AWS_SECRET_ACCESS_KEY}" -a -n "${S3_BUCKET}" -a -n "${UBUNTUPASSWORD}" -a -n "${REGION}" ]
then
  cat preseed.src | sed "s/%%UBUNTUPASSWORD%%/${UBUNTUPASSWORD}/g" > preseed.cfg
  packer build -var=email=${GRUB_PASSWORD} -var=email=${GMAIL} -var=emailPassword=${GMAILPASSWORD} \
               -var=remoteLogHost=${HOST}.${DOMAIN} -var=hostname=${HOST} \
               -var=domain=${DOMAIN} -var=aws_access_key_id=${AWS_ACCESS_KEY_ID} \
               -var=aws_secret_access_key=${AWS_SECRET_ACCESS_KEY} \
               -var=s3_bucket=${S3_BUCKET} -var=region=${REGION} -var=ubuntu_password=${UBUNTUPASSWORD} base.json && rm preseed.cfg role-policy.json
else
  echo "Error: Please ensure all required environment variables are set."
fi
