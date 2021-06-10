![Development status](https://img.shields.io/badge/status-uat-F81.svg?style=for-the-badge)
![MIT license](https://img.shields.io/badge/licence-MIT-ff69b4.svg?style=for-the-badge)
![CIS version](https://img.shields.io/badge/CIS_benchmark-2.0.1-003b5b.svg?style=for-the-badge)
![CIS CAT](https://img.shields.io/badge/CIS_CAT_Lite-4.0.21-003b5b.svg?style=for-the-badge)
![CIS Compliance](https://img.shields.io/badge/CIS_Compliance-100%25-green.svg?style=for-the-badge)
![Packer version](https://img.shields.io/badge/packer-1.7.2-02A8EF.svg?style=for-the-badge)
![Vagrant version](https://img.shields.io/badge/vagrant-2.2.16-1868F2.svg?style=for-the-badge)
![Terraform version](https://img.shields.io/badge/terraform-1.0.0-7B42BC.svg?style=for-the-badge)
![VirtualBox version](https://img.shields.io/badge/virtualbox-6.1.18-red.svg?style=for-the-badge)
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
* Vagrant, VirtualBox, Packer and Terraform (tested at the versions above).
* An AWS account, with locally configured credentials (by which I mean AWS AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY and if you require it, AWS_SESSION_TOKEN).
* A working [AWS cli tool](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-mac.html).
* Permissions to create EC2 instances, volumes, S3 buckets, s3 objects, user roles, role policies.
* A _privately_ accessible AWS S3 bucket.  Packer will deposit the image in OVA format in this bucket, and then create the AMI from it using the standard [AWS process](https://docs.aws.amazon.com/vm-import/latest/userguide/vmie_prereqs.html) leaving the bucket empty.
* A separate, temporary Ubuntu machine for Grub password generation. This can be destroyed once you have the crypt which looks something like this: `grub.pbkdf2.sha512.10000.AF3blahXXX` (see [here for more](https://sleeplessbeastie.eu/2015/01/06/how-to-password-protect-grub-entries/)).
* Gmail account for system sSMTP configuration - the box will email this account during the build and on boot.

## Initialisation
* Use a Linux machine somewhere and generate yourself a Linux boot password with [grub-mkpasswd-pbkdf2](https://www.gnu.org/software/grub/manual/grub/html_node/Invoking-grub_002dmkpasswd_002dpbkdf2.html) - save this for later.
* Use this to configure your environment variables; read the file before sourcing it.  Check [this](https://rzn.id.au/tech/converting-an-ova-to-an-amazon-ami/) post, credence to Jake.  Note that a space-separated list of regions instantiated into the ${OTHER_REGIONS} variable will result in the base image being copied to those regions once successfully ingressed into the target region.
```shell
. init.sh
```
* Run the build using `make` as below. This will ask for any outstanding variable values in order for it to trigger the `run.sh` which itself runs the `packer build` and nominal Terraform unit test:
```shell
make
```
* The `run.sh` will delete all but the latest AMI in your account with the tag name `base` and their corresponding snapshots.  Read the code.

## Notes
* The build should take ~40 minutes mostly due to the import process to AWS and copying the AMI into the chosen region.  Multi-region copies are not currently supported, but are penned for dev.
* For abortive builds use the below, ensuring to destroy an errored Packer-created VMs and SSH public keys on the cloud:
```shell
make clean
```
* Running the above build means the Ubuntu default user password used will be on your file system only during the build.
* Once you have your base, differentiate it with equivalent Packer build pipelines to create AMIs for all your favourite toys and stacks and make them trigger when this one succeeds.  Bear in mind the `%%PHOENIX%%` replacement in the Phoenix builds (see below).
* Default locale is GB in `preseed.src`.
* I build a 60Gb root disk - update `preseed.src` if needed.
* This build is currently designed to operate one-way on a new default distribution of Ubuntu 18, and is not idempotent due to CIS implementation conveniences.
* The `preseed.src` file includes `gawk` which supercedes `mawk` as it has `strftime`, and is required by the `cis.sh` script.
* The default user on board is `ubuntu`, not `vagrant` which means a `vagrant up` will fail the login step and will have to be interrupted. Running `ssh -p 2222 ubuntu@localhost` should succeed after `vagrant up`.
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
echo -e "GRUB_PASSWORD: ${GRUB_PASSWORD}\nGMAIL: ${GMAIL}\nHOST: ${HOST}\nDOMAIN: ${DOMAIN}\nREGION: ${REGION}\nREMOTELOGHOST: ${REMOTELOGHOST}\nS3_BUCKET: ${S3_BUCKET}\nAWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID}\nAWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}\nAWS_SESSION_TOKEN: ${AWS_SESSION_TOKEN}\nGMAILPASSWORD: ${GMAILPASSWORD}\nUBUNTUPASSWORD: ${UBUNTUPASSWORD}\nOTHER_REGIONS: ${OTHER_REGIONS}\n"
```
might be convenient during development.
* Certain environments require `AWS_SESSION_TOKEN` to be set such as your place of work, but although this needs to be set correctly for those environments to work, it is not specifically tested during the Packer run.
* Put your site-specific base image unit test content in the `baseUnitTest.sh` script which distributes as a nominal Internet connectivity test.

## Troubleshooting
* Post-processor failed: Import task import-ami-0467547a09916b17a failed with status message: ClientError: Disk validation failed [We do not have access to the given resource. Reason 403 Forbidden], error: ResourceNotReady: failed waiting for successful resource state
  * Have you changed the name of the S3 bucket?  If so, you'll need to remove the role from IAM which refers to the previously instantiated bucket name
