## This script automates the initiation of the packer build environment to ensure all env vars are instantiated
#

#####    ##    ####  ######    # #    # # #####
#    #  #  #  #      #         # ##   # #   #
#####  #    #  ####  #####     # # #  # #   #
#    # ######      # #         # #  # # #   #
#    # #    # #    # #         # #   ## #   #
#####  #    #  ####  ######    # #    # #   #

if [ -z $(echo ${GRUB_PASSWORD}) ]
then
  read -sp "Enter value for GRUB_PASSWORD: " GRUB_PASSWORD
  export GRUB_PASSWORD=${GRUB_PASSWORD}
  echo
fi

if [ -z $(echo ${GMAIL}) ]
then
  read -p "Enter value for GMAIL account: " GMAIL
  export GMAIL=${GMAIL}
fi

if [ -z $(echo ${HOST}) ]
then
  read -p "Enter value for HOST: " HOST
  export HOST=${HOST}
fi

if [ -z $(echo ${DOMAIN}) ]
then
  read -p "Enter value for DOMAIN: " DOMAIN
  export DOMAIN=${DOMAIN}
fi

if [ -z $(echo ${REGION}) ]
then
  read -p "Enter value for AWS REGION: " REGION
  export REGION=${REGION}
fi

if [ -z $(echo ${S3_BUCKET}) ]
then
  read -p "Enter value for S3_BUCKET: " S3_BUCKET
  export S3_BUCKET=${S3_BUCKET}
fi

if [ -z $(echo ${AWS_ACCESS_KEY_ID}) ]
then
  read -p "Enter value for AWS_ACCESS_KEY_ID: " AWS_ACCESS_KEY_ID
  export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
fi

if [ -z $(echo ${AWS_SECRET_ACCESS_KEY}) ]
then
  read -sp "Enter value for AWS_SECRET_ACCESS_KEY: " AWS_SECRET_ACCESS_KEY
  export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
  echo
fi

if [ -z $(echo ${AWS_SESSION_TOKEN}) ]
then
  read -p "Enter value for AWS_SESSION_TOKEN (enter for none): " AWS_SESSION_TOKEN
  export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}
fi

if [ -z $(echo ${GMAILPASSWORD}) ]
then
  read -sp "Enter value for GMAILPASSWORD: " GMAILPASSWORD
  export GMAILPASSWORD=${GMAILPASSWORD}
  echo
fi

if [ -z $(echo ${UBUNTUPASSWORD}) ]
then
  read -sp "Enter value for UBUNTUPASSWORD: " UBUNTUPASSWORD
  export UBUNTUPASSWORD=${UBUNTUPASSWORD}
  echo
fi

if [ -z $(echo ${OTHER_REGIONS}) ]
then
  read -p "Space-separated list of OTHER_REGIONS to copy the base image to (do not include main REGION): " OTHER_REGIONS
  export OTHER_REGIONS="${OTHER_REGIONS}"
  echo
fi
