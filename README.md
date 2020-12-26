![Development status](https://img.shields.io/badge/status-uat-F90.svg?style=for-the-badge)
![MIT license](https://img.shields.io/badge/licence-MIT-ff69b4.svg?style=for-the-badge)
![CIS version](https://img.shields.io/badge/CIS_benchmark-2.0.1-003b5b.svg?style=for-the-badge)
![CIS CAT](https://img.shields.io/badge/CIS_CAT_Lite-4.0.21-003b5b.svg?style=for-the-badge)
![CIS Compliance](https://img.shields.io/badge/CIS_Compliance-100%25-green.svg?style=for-the-badge)
![Packer version](https://img.shields.io/badge/packer-1.6.5-00ACFF.svg?style=for-the-badge)
![Vagrant version](https://img.shields.io/badge/vagrant-2.2.13-1563ff.svg?style=for-the-badge)
![Terraform version](https://img.shields.io/badge/terraform-0.14.3-623CE4.svg?style=for-the-badge)
![Ubuntu version](https://img.shields.io/badge/ubuntu-18.05LTS-blue.svg?style=for-the-badge)
![Written with](https://img.shields.io/badge/written_with-macOS-333.svg?style=for-the-badge)

# base

* MacOS: Packer + virtualbox-iso + Ubuntu OVA = single EBS volume AWS AMI + Vagrant dev box
* Partitioned, single-volume images.
* CIS benchmark compliance.
* Free to create and free to analyse/confirm compliance.
* Scored Level 1 CIS benchmarks, not unscored or Level 2 requirements.
* GCP/Azure builds to follow in due course, but `!breath(hold)`.

## Current Picture
* Parameterised Packer & Bash, with a little bit of Terraform & Vagrant.  That's it.

## Prerequisites
* Packer and Terraform.
* An AWS account, with locally configured credentials (by which I mean AWS AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY and if you require it, AWS_SESSION_TOKEN).
* A working [AWS cli tool](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-mac.html).
* Permissions to create EC2 instances, volumes, S3 buckets, s3 objects, user roles, role policies.
* A _privately_ accessible AWS S3 bucket.  Packer will deposit the image in OVA format in this bucket, and then create the AMI from it using the standard [AWS process](https://docs.aws.amazon.com/vm-import/latest/userguide/vmie_prereqs.html) leaving the bucket empty.
* A separate Ubuntu machine for Grub password generation.
* Gmail account for system sSMTP configuration - the box will email this account during the build.

## Initialisation
* Use a Linux machine somewhere and generate yourself a Linux boot password with [grub-mkpasswd-pbkdf2](https://www.gnu.org/software/grub/manual/grub/html_node/Invoking-grub_002dmkpasswd_002dpbkdf2.html) - save this for later.
* The `run.sh` script in this repo is triggered by the `init.sh` and configures IAM in your account so that the build process works - Check [this](https://rzn.id.au/tech/converting-an-ova-to-an-amazon-ami/) post, credence to Jake.
* Run the build using `make` as below. This will ask for any outstanding variable values in order for it to trigger the `run.sh` which itself runs the `packer build` and nominal Terraform unit test:
```shell
make
```
* The `run.sh` will list all AMIs with a tag Name = `base` and delete all but the latest and their corresponding snapshots.  Read the code.
* The build should take ~40 mminutes mostly due to the import process to AWS and copying the AMI into the chosen region.  Multi-region copies are not currently supported, but are penned for dev.
* For abortive builds use the below, ensuring to destroy an errored Packer-created VMs and SSH public keys on the cloud:
```shell
make clean
```


## Notes
* Running the build below means the Ubuntu default user password used will be on your file system only during the build.
* Once you have your base, differentiate it with equivalent Packer build pipelines to create AMIs for all your favourite toys and stacks and make them trigger when this one succeeds.
* Bear in mind the `%%PHOENIX%%` replacement in the Phoenix builds (see below)
* Default locale is GB in `preseed.src` and may need editing.
* I build a root disk with 60Gb - update `preseed.src` if needed.
* This build is currently designed to operate one-way on a new default distribution of Ubuntu, and is not idempotent due to CIS implementation conveniences.
* The `preseed.src` file includes `gawk` which supercedes `mawk` as it has `strftime`, and is required by the `cis.sh` script.
* The default user on board is `ubuntu`, not `vagrant` which means a `vagrant up` will fail the login step and will have to be interrupted. A normal `ssh` will succeed on the command line specifying the correct user.
* Other notes pertaining to the CIS v2.0.1 Ubuntu CIS benchmarking document:
  * 1.3.1: This config sets up `sSMTP` in order for `aide` to be able to send email requires a hostname which defaults to `${HOST}.vm` and a _gmail account_.
  * 1.5.2: Generate your own grub password as this repo has one only the author knows. See above.
  * 3.4.3: It is recommended to populate the `hosts.deny` once you have an idea of the networking from which you will attach to your machines. Optionally look at [HashiCorp Boundary](https://www.boundaryproject.io/) when you get there.
  * 3.6: For now, I'm leaving network manager switched on to check to see whether or not this is required in order to turn the radio module off.
  * 3.7/4.1.1.4 IPv6 is disabled but firewall rules are included and commented out in case use is required.
  * 4.1.2.3 auditd.conf has a `%%PHOENIX%%` parameter added intending for this to be replaced as part of your [phoenix build](https://martinfowler.com/bliki/PhoenixServer.html) which consumes this repo.
  * 5.2.14: SSHD is configured to `AllowUsers ubuntu` so only this user will be able to login unless the `cis.sh` script is amended.
* Packer will also output a `u18.box` vbox Vagrant image type if you want to have a look locally prior to running your build. Optional.
* Note the terms of use for CIS-CAT Lite: https://learn.cisecurity.org/cis-cat-trial-terms
* Note that this software is provided as-is, and hardens an Ubuntu image built with Packer.  The recommendation is to comply with the above terms of use as they apply in your use case.
* Running
```shell
echo -e "GRUB_PASSWORD: ${GRUB_PASSWORD}\nGMAIL: $GMAIL\nHOST: $HOST\nDOMAIN: $DOMAIN\nREGION: $REGION\nREMOTELOGHOST: $REMOTELOGHOST\nS3_BUCKET: ${S3_BUCKET}\nAWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\nAWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\nGMAILPASSWORD: $GMAILPASSWORD\nUBUNTUPASSWORD: $UBUNTUPASSWORD\n"
```
might be convenient during development.
* Certain environments require AWS_SESSION_TOKEN to be set such as your place of work, but although this needs to be set correctly for those environments to work, it is not specifically tested during the Packer run.
* Put your site-specific base image unit test content in the `base_unit_test.sh` script which distributes as a nominal Internet connectivity test.

## TODO
* Rerun with REMOTELOGHOST instantiated and test logging works with Elastic cloud.

