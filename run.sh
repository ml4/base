#!/bin/bash
#
## run.sh - orchestrate the running of the base build pipeline
## 2020-12-24 11:15::ml4
#
## This scripture is run by the init.sh script. Please see the README.md
#
################################################################################

#####    ##    ####  ######    #####  #    # #    #
#    #  #  #  #      #         #    # #    # ##   #
#####  #    #  ####  #####     #    # #    # # #  #
#    # ######      # #         #####  #    # #  # #
#    # #    # #    # #         #   #  #    # #   ##
#####  #    #  ####  ######    #    #  ####  #    #

RED='\033[0;31m'

function log {
  bldred='\033[0;31m' # Red
  bldgrn='\033[1;32m' # Green
  bldylw='\033[1;33m' # Yellow
  bldblu='\033[1;34m' # Blue
  bldpur='\033[1;35m' # Purple
  bldcyn='\033[1;36m' # Cyan
  bldwht='\033[1;37m' # White
  txtrst='\033[0m'    # Text Reset

  local -r level="$1"
  if [ "${level}" == "INFO" ]
  then
    COL=${bldgrn}
  elif [ "${level}" == "ERROR" ]
  then
    COL=${bldred}
  elif [ "${level}" == "WARN" ]
  then
    COL=${bldylw}
  fi
  local -r message="$2"
  >&2 echo -e "${bldwht}[${COL}${level}${bldwht}] ${message}"
}

if [[ -z "${GRUB_PASSWORD}" ]]
then
  log "ERROR" "GRUB_PASSWORD is not set"
  exit 1
fi

if [[ -z "${GMAIL}" ]]
then
  log "ERROR" "GMAIL is not set"
  exit 1
fi

if [[ -z "${GMAILPASSWORD}" ]]
then
  log "ERROR" "GMAILPASSWORD is not set"
  exit 1
fi

if [[ -z "${HOST}" ]]
then
  log "ERROR" "HOST is not set"
  exit 1
fi

if [[ -z "${DOMAIN}" ]]
then
  log "ERROR" "DOMAIN is not set"
  exit 1
fi

if [[ -z "${AWS_ACCESS_KEY_ID}" ]]
then
  log "ERROR" "AWS_ACCESS_KEY_ID is not set"
  exit 1
fi

if [[ -z "${AWS_SECRET_ACCESS_KEY}" ]]
then
  log "ERROR" "AWS_SECRET_ACCESS_KEY is not set"
  exit 1
fi

if [[ -z "${UBUNTUPASSWORD}" ]]
then
  log "ERROR" "UBUNTUPASSWORD is not set"
  exit 1
fi

if [[ -z "${REGION}" ]]
then
  log "ERROR" "REGION is not set"
  exit 1
fi

log "INFO" "Creating temporary SSH key pair"
if [[ -r "./base_unit_test_key" && "./base_unit_test_key.pub" ]]
then
  log "INFO" "Found base_unit_test_key pair - using"
else
    ssh-keygen -t rsa -b 4096 -N "" -C "base_unit_test_key" -f base_unit_test_key
fi
rCode=${?}
if [ ${rCode} -gt 0 ]
then
  log "ERROR" "Problem creating temporary SSH key pair"
  exit 1
fi

if [[ -z "$(command -v packer)" ]]
then
  log "ERROR" "Install Packer first"
  exit 1
fi

if [[ -z "$(command -v terraform)" ]]
then
  log "ERROR" "Install Terraform first"
  exit 1
fi

if [[ -n "${S3_BUCKET}" ]]
then
  aws s3 ls | awk '{print $NF}' | grep ^${S3_BUCKET}$
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "S3 bucket ${S3_BUCKET} does not exist - create it first"
    exit 1
  fi
  aws iam get-role --role-name vmimport >/dev/null 2>&1
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    cat role-policy.src | sed "s/%%S3_BUCKET%%/${S3_BUCKET}/g" > role-policy.json
    aws iam create-role --role-name vmimport --assume-role-policy-document file://trust-policy.json
    aws iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document file://role-policy.json
  fi
else
  log "ERROR" "S3_BUCKET is not set"
  exit 1
fi

## MAIN CALL
#
cat preseed.src | sed "s/%%UBUNTUPASSWORD%%/${UBUNTUPASSWORD}/g" > preseed.cfg
packer build -var=email=${GRUB_PASSWORD} -var=email=${GMAIL} -var=emailPassword=${GMAILPASSWORD} \
              -var=remoteLogHost=${HOST}.${DOMAIN} -var=hostname=${HOST} \
              -var=domain=${DOMAIN} -var=aws_access_key_id=${AWS_ACCESS_KEY_ID} \
              -var=aws_secret_access_key=${AWS_SECRET_ACCESS_KEY} \
              -var=aws_session_token=${AWS_SESSION_TOKEN} \
              -var=s3_bucket=${S3_BUCKET} -var=region=${REGION} -var=ubuntu_password=${UBUNTUPASSWORD} base.json && role-policy.json 2>/dev/null
              # -var=s3_bucket=${S3_BUCKET} -var=region=${REGION} -var=ubuntu_password=${UBUNTUPASSWORD} base.json && rm preseed.cfg role-policy.json 2>/dev/null


if [[ -f preseed.cfg ]]
then
  log "ERROR" "preseed.cfg still present so Packer build must have failed."
  exit 1
else
  log "INFO" "Completed initial build. Proceeding to unit test."
fi

LATESTBASE=$(aws ec2 describe-images --owners self --region ${REGION} --query "sort_by(Images, &CreationDate)[-1].[ImageId]" --filters "Name=name,Values=base" --output text)
echo
log "INFO" "ABOUT TO TEST AMI: ${LATESTBASE}"
echo
sed "s/%%LATESTBASE%%/${LATESTBASE}/; s/%%REGION%%/${REGION}/" main.src > main.tf

## terraform unit test
#
terraform init -upgrade
rCode=${?}
if [[ ${rCode} -gt 0 ]]
then
  log "ERROR" "Problem running terraform init"
  exit 1
fi

terraform apply -auto-approve -compact-warnings
rCode=${?}
if [[ ${rCode} -gt 0 ]]
then
  log "ERROR" "Problem running terraform apply"
  exit 1
fi

## sleep for instance OK
## aws ec2 wait instance-status-ok --instance-ids appears to timeout
#
INSTANCEID=$(terraform output | grep base_unit_test_instance_id | awk '{print $NF}' | tr -d '"')
log "INFO" "Unit test instance ID harvested as: ${INSTANCEID}; Polling:"
echo -n "Waiting for instance to come up"
if [[ -n ${INSTANCEID} ]]
then
  while [[ $(aws ec2 describe-instance-status --instance-id ${INSTANCEID} --region ${REGION} --output text | grep -v INSTANCESTATUSES | grep INSTANCESTATUS | awk '{print $NF}') != "ok" ]]
  do
    echo -n "."
    sleep 10
  done
else
  log "ERROR" "Instance ID not found. Running Terraform destroy to tidy up"
  terraform destroy -auto-approve -compact-warnings
  rCode=${?}
  if [[ ${rCode} > 0 ]]
  then
    log "ERROR" "Return status greater than zero for command terraform destroy -auto-approve -compact-warnings"
  fi
  exit 1
fi

log "INFO" "Getting unit test instance ID with: aws ec2 describe-instances --instance-id |${INSTANCEID}| --region |${REGION}| --output json | grep PublicIpAddress"
INSTANCEIP=$(aws ec2 describe-instances --instance-id ${INSTANCEID} --region ${REGION} --output json | grep PublicIpAddress | awk -F '"' '{print $4}')
if [[ -z ${INSTANCEIP} ]]
then
  log "ERROR" "aws ec2 describe-instances --instance-id returned an empty string. Running Terraform destroy to tidy up"
  terraform destroy -auto-approve -compact-warnings
  rCode=${?}
  if [[ ${rCode} > 0 ]]
  then
    log "ERROR" "Return status greater than zero for command terraform destroy -auto-approve -compact-warnings"
  fi
  exit 1
fi

log "INFO" "Adding non-interactive SSH capability with: ssh-keyscan -H |${INSTANCEIP}| | tee -a ~/.ssh/known_hosts"
ssh-keyscan -H ${INSTANCEIP} | tee -a ~/.ssh/known_hosts
rCode=${?}
if [[ ${rCode} > 0 ]]
then
  echo "ERROR: return status greater than zero for command ssh-keyscan. Running Terraform destroy to tidy up"
  terraform destroy -auto-approve -compact-warnings
  rCode=${?}
  if [[ ${rCode} > 0 ]]
  then
    log "ERROR" "Return status greater than zero for command terraform destroy -auto-approve -compact-warnings"
  fi
  exit 1
fi

log "INFO" "Getting test result with: ssh -i base_unit_test_key ubuntu@${INSTANCEIP} 'cat /var/tmp/base_unit_test'"
RESULT=$(ssh -i base_unit_test_key ubuntu@${INSTANCEIP} "cat /var/tmp/base_unit_test" 2>/dev/null)
if [[ -z ${RESULT} ]]
then
  log "ERROR" "Return status greater than zero for command ssh -i base_unit_test_key ubuntu@${INSTANCEIP} 'cat /var/tmp/base_unit_test'"
  exit 1
fi

log "INFO" "Running Terraform destroy to complete test"
terraform destroy -auto-approve -compact-warnings
rCode=${?}
if [ ${rCode} -gt 0 ]
then
  echo "ERROR running terraform destroy"
  exit 1
fi

## remove all older AMIs *and their corresponding snapshots* leaving only the latest behind. Do nothing if only one exists
#
log "INFO" "Removing older AMIs and corresponding snapshots with aws ec2 describe-images pipeline"
IMAGENUM=$(aws ec2 describe-images --owners self --region ${REGION} --query "sort_by(Images, &CreationDate)" --filters "Name=name,Values=base" --output json | grep ImageId | wc -l | awk '{print $1}')
if [[ ${IMAGENUM} > 1 ]]
then
  for AMI in $(aws ec2 describe-images --owners self --region ${REGION} --query "sort_by(Images, &CreationDate)" --filters "Name=name,Values=base" --output json | grep ImageId | head -$(( IMAGENUM -= 1 )) | awk -F '"' '{print $4}')
  do
    SNAP=$(aws ec2 describe-snapshots --owner-ids self --region eu-west-1 --output text | grep ${AMI} | awk -F'\t' '{print $6}')
    log "INFO" "Running aws ec2 deregister-image --image-id ${AMI} --region ${REGION} && aws ec2 delete-snapshot --snapshot-id ${SNAP} --region ${REGION}"
    aws ec2 deregister-image --image-id ${AMI} --region ${REGION} && aws ec2 delete-snapshot --snapshot-id ${SNAP} --region ${REGION}
    rCode=${?}
    if [[ ${rCode} > 0 ]]
    then
      log "WARNING" "return status greater than zero for command aws ec2 deregister-image --image-id |${AMI}| --region |${REGION}|"
      exit 1
    fi
  done
fi

## tidy up, leave packer_cache
#
rm -rf main.tf base_unit_test_key base_unit_test_key.pub terraform.tfstate terraform.tfstate.backup .terraform

## output result
#
echo
log "INFO" "base unit test: ${RESULT}"
echo
