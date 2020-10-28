![Development status](https://img.shields.io/badge/status-uat-F90.svg?style=for-the-badge)
![MIT license](https://img.shields.io/badge/licence-MIT-blue.svg?style=for-the-badge)
![CIS version](https://img.shields.io/badge/CIS_benchmark-2.0.1-blue.svg?style=for-the-badge)
![CIS CAT](https://img.shields.io/badge/CIS_CAT_Lite-4.0.21-blue.svg?style=for-the-badge)
![CIS Compliance](https://img.shields.io/badge/CIS_Compliance-100%25-green.svg?style=for-the-badge)
![Packer version](https://img.shields.io/badge/packer-1.6.4-blue.svg?style=for-the-badge)
![Vagrant version](https://img.shields.io/badge/vagrant-2.2.9-1563ff.svg?style=for-the-badge)
![Ubuntu version](https://img.shields.io/badge/ubuntu-18.05LTS-blue.svg?style=for-the-badge)
![Packer language](https://img.shields.io/badge/packer-JSON-blueviolet.svg?style=for-the-badge)
![Provisioning language](https://img.shields.io/badge/provisioning-bash-blueviolet.svg?style=for-the-badge)
![Written with](https://img.shields.io/badge/written_with-macOS-333.svg?style=for-the-badge)

# base

* MacOS: Packer + virtualbox-iso + Ubuntu OVA = single EBS volume AWS AMI + Vagrant dev box
* Partitioned, single-volume images.
* CIS benchmark compliance.
* Free to create and free to analyse/confirm compliance.
* Scored Level 1 CIS benchmarks, not unscored or Level 2 requirements.

## Current Picture
* Parameterised Vagrant, Packer & Bash.  That's it.

## Prerequisites
* An AWS account, with locally configured credentials (by which I mean AWS AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY).
* A working [AWS cli tool](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-mac.html).
* Permissions to create EC2 instances, volumes, S3 buckets, s3 objects, user roles, role policies.

## Setup
* The first thing to do is to configure the AWS S3 bucket.  Reproducing [this](https://rzn.id.au/tech/converting-an-ova-to-an-amazon-ami/) post:
  * Run this:
```
read -p s3_bucket: S3_BUCKET             # AWS s3 bucket for OVA ingress
```

  * Next, find a Linux machine somewhere and generate yourself a Linux boot password with [grub-mkpasswd-pbkdf2](https://www.gnu.org/software/grub/manual/grub/html_node/Invoking-grub_002dmkpasswd_002dpbkdf2.html) - save for below.
  * Next:
    * Create the S3 bucket either through the UI/CLI, ensure it is not public.
    * The file `role-policy.json` should be then generated from the `role-policy.src` file as per the below.
    * Run the following to create the role _vmimport_ in your AWS account and enable the policy for importing via the bucket named in `${S3_BUCKET}`:
```shell
if  [ -n "${S3_BUCKET} ]
then
  cat role-policy.src | sed "s/%%S3_BUCKET%%/${S3_BUCKET}/g" > role-policy.json
  aws iam create-role --role-name vmimport --assume-role-policy-document file://trust-policy.json
  aws iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document file://role-policy.json
else
  echo "ERROR: S3_BUCKET is not set"
  exit 1
fi
```
  * Packer will deposit the image in OVA format in this bucket, and then creates the AMI from it using the standard [AWS process](https://docs.aws.amazon.com/vm-import/latest/userguide/vmie_prereqs.html).
  * Packer will also output a `u18.box` vbox Vagrant image type if you want to have a look locally prior to running your build. Optional.
  * Running the build below means the Ubuntu default user password used will be on your file system only during the build.
  * Next, run these commands to set up your shell and run the Packer build.  These proffer a personalised/differentiated build easily:
```
brew install packer                                    # or the equivalent for Linux
read -sp grubPassword: GRUB_PASSWORD                    # grub password from the grub-mkpasswd-pbkdf2 output above
read -p remoteLogHost: REMOTELOGHOST                   # log service - does not have to exist for the build to work
read -p email: EMAIL                                   # gmail address for sSMTP
read -sp password: EMAILPASSWORD                       # gmail password for sSMTP
read -p hostname: HOSTNAME                             # hostname for your base image
read -p domain: DOMAIN                                 # domain for your base image
read -p region: REGION                                 # regions for your base image
read -p aws_access_key_id: AWS_ACCESS_KEY_ID           # AWS access key
read -sp aws_secret_access_key: AWS_SECRET_ACCESS_KEY  # AWS secret key
read -sp ubuntu_password: UBUNTUPASSWORD               # Used to sed out %%UBUNTUPASSWORD%% *.src below

## run with something like this:
#
if [ -n "${GRUB_PASSWORD}" -a -n "${EMAIL}" -a -n "${EMAILPASSWORD}" -a -n "${HOSTNAME}" -a -n "${DOMAIN}" -a -n "${AWS_ACCESS_KEY_ID}" -a -n "${AWS_SECRET_ACCESS_KEY}" -a -n "${S3_BUCKET}" -a -n "${UBUNTUPASSWORD}" -a -n "${REGION}" ]
then
  cat preseed.src | sed "s/%%UBUNTUPASSWORD%%/${UBUNTUPASSWORD}/g" > preseed.cfg
  packer build -var=email=${GRUB_PASSWORD} -var=email=${EMAIL} -var=emailPassword=${EMAILPASSWORD} \
               -var=remoteLogHost=${HOSTNAME}.${DOMAIN} -var=hostname=${HOSTNAME} \
               -var=domain=${DOMAIN} -var=aws_access_key_id=${AWS_ACCESS_KEY_ID} \
               -var=aws_secret_access_key=${AWS_SECRET_ACCESS_KEY} \
               -var=s3_bucket=${S3_BUCKET} -var=region=${REGION} -var=ubuntu_password=${UBUNTUPASSWORD} base.json && rm preseed.cfg role-policy.json
else
  echo "Error: Please ensure all required environment variables are set."
fi

## Once you have your base, differentiate it with equivalent Packer build pipelines to create AMIs for all your favourite toys and stacks and make them trigger when this one succeeds.
## Bear in mind the %%PHOENIX%% replacement in the Phoenix builds (see below)
```

## Notes
* Default locale is GB in `preseed.src` and may need editing.
* I build a root disk with 60Gb - update `preseed.src` if needed.
* This build is currently designed to operate one-way on a new default distribution of Ubuntu, and is not idempotent due to CIS implementation conveniences.
* The `preseed.src` file includes `gawk` which supercedes `mawk` as it has `strftime`, and is required by the `cis.sh` script.
* Other notes pertaining to the CIS v2.0.1 Ubuntu CIS benchmarking document:
  * 1.3.1: This config sets up `sSMTP` in order for aide to be able to send email requires a hostname which defaults to `${HOSTNAME}.vm`.
  * 1.5.2: Generate your own grub password as this repo has one only the author knows. See above.
  * 3.4.3: It is recommended to populate the `hosts.deny` once you have an idea of the networking from which you will attach to your machines. Optionally look at [HashiCorp Boundary](https://www.boundaryproject.io/) when you get there.
  * 3.6: For now, I'm leaving network manager switched on to check to see whether or not this is required in order to turn the radio module off.
  * 3.7/4.1.1.4 IPv6 is disabled but firewall rules are included and commented out in case use is required.
  * 4.1.2.3 auditd.conf has a %%PHOENIX%% parameter added intending for this to be replaced as part of your [phoenix build](https://martinfowler.com/bliki/PhoenixServer.html) which consumes this repo.
  * 5.2.14: SSHD is configured to `AllowUsers ubuntu` so only this user will be able to login unless the `cis.sh` script is amended.
* Note the terms of use for CIS-CAT Lite: https://learn.cisecurity.org/cis-cat-trial-terms
* Note that this software is provided as-is, and hardens an Ubuntu image built with Packer.  The recommendation is to comply with the above terms of use as they apply in your use case.

