#!/bin/bash

echo "Creating temporary SSH key pair"
ssh-keygen -t rsa -b 4096 -N "" -C "base_unit_test_key" -f base_unit_test_key
rCode=${?}
if [ ${rCode} -gt 0 ]
then
  echo "ERROR creating temporary SSH key pair"
  exit 1
fi

if [ -z "$(command -v packer)" ]
then
  echo "Install Packer first"
  exit 1
fi

if [ -z "$(command -v terraform)" ]
then
  echo "Install Terraform first"
  exit 1
fi

if  [ -n "${S3_BUCKET}" ]
then
  aws s3 ls | awk '{print $NF}' | grep ^${S3_BUCKET}$
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
               -var=aws_session_token=${AWS_SESSION_TOKEN} \
               -var=s3_bucket=${S3_BUCKET} -var=region=${REGION} -var=ubuntu_password=${UBUNTUPASSWORD} base.json && rm preseed.cfg role-policy.json 2>/dev/null
else
  echo "Error: Please ensure all required environment variables are set."
fi

if [ -f preseed.cfg ]
then
  echo "preseed.cfg still present so Packer build must have failed."
  exit 1
fi

LATESTBASE=$(aws ec2 describe-images --owners self --region ${REGION} --query "sort_by(Images, &CreationDate)[-1].[ImageId]" --filters "Name=name,Values=base" --output text)
echo
echo "ABOUT TO TEST AMI: ${LATESTBASE}"
echo
sed "s/%%LATESTBASE%%/${LATESTBASE}/; s/%%REGION%%/${REGION}/" main.src > main.tf

## terraform unit test
#
terraform init -upgrade
rCode=${?}
if [ ${rCode} -gt 0 ]
then
  echo "ERROR running terraform init"
  exit 1
fi

terraform apply -auto-approve -compact-warnings
rCode=${?}
if [ ${rCode} -gt 0 ]
then
  echo "ERROR running terraform apply"
  exit 1
fi

## sleep for instance OK
## aws ec2 wait instance-status-ok --instance-ids appears to timeout
#
echo -n "Waiting for instance."
INSTANCEID=$(terraform output | grep base_unit_test_instance_id | awk '{print $NF}' | tr -d '"')
if [[ -n ${INSTANCEID} ]]
then
  while [[ $(aws ec2 describe-instance-status --instance-id ${INSTANCEID} --region ${REGION} --output text | grep -v INSTANCESTATUSES | grep INSTANCESTATUS | awk '{print $NF}') != "ok" ]]
  do
    echo -n "."
    sleep 10
  done
fi

INSTANCEIP=$(aws ec2 describe-instances --instance-id ${INSTANCEID} --region ${REGION} --output json | grep PublicIpAddress | awk -F '"' '{print $4}')
if [[ -z ${INSTANCEIP} ]]
then
  echo "ERROR: return status greater than zero for command ."
  exit 1
fi

ssh-keyscan -H ${INSTANCEIP} >> ~/.ssh/known_hosts
rCode=${?}
if [[ ${rCode} > 0 ]]
then
  echo "ERROR: return status greater than zero for command ssh-keyscan."
  exit 1
fi

RESULT=$(ssh -i base_unit_test_key ubuntu@${INSTANCEIP} "cat /var/tmp/base_unit_test" 2>/dev/null)

terraform destroy -auto-approve -compact-warnings
rCode=${?}
if [ ${rCode} -gt 0 ]
then
  echo "ERROR running terraform destroy"
  exit 1
fi

## remove all older AMIs *and their corresponding snapshots* leaving only the latest behind. Do nothing if only one exists
#
IMAGENUM=$(aws ec2 describe-images --owners self --region ${REGION} --query "sort_by(Images, &CreationDate)" --filters "Name=name,Values=base" --output json | grep ImageId | wc -l | awk '{print $1}')
if [[ ${IMAGENUM} > 1 ]]
then
  for AMI in $(aws ec2 describe-images --owners self --region ${REGION} --query "sort_by(Images, &CreationDate)" --filters "Name=name,Values=base" --output json | grep ImageId | head -$(( IMAGENUM -= 1 )) | awk -F '"' '{print $4}')
  do
    SNAP=$(aws ec2 describe-snapshots --owner-ids self --region eu-west-1 --output text | grep ${AMI} | awk -F'\t' '{print $6}')
    echo "aws ec2 deregister-image --image-id ${AMI} --region ${REGION} && aws ec2 delete-snapshot --snapshot-id ${SNAP} --region ${REGION}"
    aws ec2 deregister-image --image-id ${AMI} --region ${REGION} && aws ec2 delete-snapshot --snapshot-id ${SNAP} --region ${REGION}
  done
fi

## tidy up, leave packer_cache
#
rm -rf main.tf base_unit_test_key base_unit_test_key.pub terraform.tfstate terraform.tfstate.backup .terraform

## output result
#
echo
echo "base unit test: ${RESULT}"
echo
