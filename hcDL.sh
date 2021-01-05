#!/bin/bash
#
## hcDL HashiCorp Download
## 2020-07-10 ml4
## Automate the secure downloading of a tool from releases.hashicorp.com to the current working directory
#
#############################################################################################################################

set -Eo pipefail

function log {
  bldred="\033[0;31m" # Red
  bldgrn="\033[0;32m" # Green
  bldylw="\033[0;33m" # Yellow
  bldblu="\033[0;34m" # Blue
  bldpur="\033[0;35m" # Purple
  bldcyn="\033[0;36m" # Cyan
  bldwht="\033[0;37m" # White
  txtrst="\033[0m"    # Text Reset

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
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "${bldcyn}${timestamp}${txtrst} [${COL}${level}${txtrst}] ${message}"
}

args=("$@")

if [[ -z ${args[1]} ]]
then
  echo
  echo "Usage: hcDL <tool> <version> <platform>"
  echo
  echo "Where"
  echo "tool = is from https://releases.hashicorp.com/ e.g. packer"
  echo -e "platform = something like ${bldcyn}linux_amd64${txtrst}"
  echo
  echo "If <platform> is omitted, it is calculated from the current platform"
  echo "NOTE: currently only tested on macOS and Linux"
  exit 1
fi

TOOL="${args[0]}"
VERSION="${args[1]}"
PLATFORM="${args[2]}"
OSNAME=$(uname -s | tr 'A-Z' 'a-z')
HWNAME=$(uname -m)

## now assess platform if not specified
#
if [[ -z "${PLATFORM}" ]]
then
  if [ "${HWNAME}" == "x86_64" ]
  then
    PLATFORM="${OSNAME}_amd64"
  fi
fi

log "INFO" "Tool: ${TOOL}"
log "INFO" "Version: ${VERSION}"
log "INFO" "Platform: ${PLATFORM}"

## handle keys first
#
if [[ -z $(gpg --list-keys | grep 51852D87348FFC4C) ]]
then
  log "INFO" "Getting HashiCorp public GPG key"
  cat <<EOF >/tmp/hashicorp.asc
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFMORM0BCADBRyKO1MhCirazOSVwcfTr1xUxjPvfxD3hjUwHtjsOy/bT6p9f
W2mRPfwnq2JB5As+paL3UGDsSRDnK9KAxQb0NNF4+eVhr/EJ18s3wwXXDMjpIifq
fIm2WyH3G+aRLTLPIpscUNKDyxFOUbsmgXAmJ46Re1fn8uKxKRHbfa39aeuEYWFA
3drdL1WoUngvED7f+RnKBK2G6ZEpO+LDovQk19xGjiMTtPJrjMjZJ3QXqPvx5wca
KSZLr4lMTuoTI/ZXyZy5bD4tShiZz6KcyX27cD70q2iRcEZ0poLKHyEIDAi3TM5k
SwbbWBFd5RNPOR0qzrb/0p9ksKK48IIfH2FvABEBAAG0K0hhc2hpQ29ycCBTZWN1
cml0eSA8c2VjdXJpdHlAaGFzaGljb3JwLmNvbT6JAU4EEwEKADgWIQSRpuf4XQXG
VjC+8YlRhS2HNI/8TAUCXn0BIQIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAK
CRBRhS2HNI/8TJITCACT2Zu2l8Jo/YLQMs+iYsC3gn5qJE/qf60VWpOnP0LG24rj
k3j4ET5P2ow/o9lQNCM/fJrEB2CwhnlvbrLbNBbt2e35QVWvvxwFZwVcoBQXTXdT
+G2cKS2Snc0bhNF7jcPX1zau8gxLurxQBaRdoL38XQ41aKfdOjEico4ZxQYSrOoC
RbF6FODXj+ZL8CzJFa2Sd0rHAROHoF7WhKOvTrg1u8JvHrSgvLYGBHQZUV23cmXH
yvzITl5jFzORf9TUdSv8tnuAnNsOV4vOA6lj61Z3/0Vgor+ZByfiznonPHQtKYtY
kac1M/Dq2xZYiSf0tDFywgUDIF/IyS348wKmnDGjuQENBFMORM0BCADWj1GNOP4O
wJmJDjI2gmeok6fYQeUbI/+Hnv5Z/cAK80Tvft3noy1oedxaDdazvrLu7YlyQOWA
M1curbqJa6ozPAwc7T8XSwWxIuFfo9rStHQE3QUARxIdziQKTtlAbXI2mQU99c6x
vSueQ/gq3ICFRBwCmPAm+JCwZG+cDLJJ/g6wEilNATSFdakbMX4lHUB2X0qradNO
J66pdZWxTCxRLomPBWa5JEPanbosaJk0+n9+P6ImPiWpt8wiu0Qzfzo7loXiDxo/
0G8fSbjYsIF+skY+zhNbY1MenfIPctB9X5iyW291mWW7rhhZyuqqxN2xnmPPgFmi
QGd+8KVodadHABEBAAGJATwEGAECACYCGwwWIQSRpuf4XQXGVjC+8YlRhS2HNI/8
TAUCXn0BRAUJEvOKdwAKCRBRhS2HNI/8TEzUB/9pEHVwtTxL8+VRq559Q0tPOIOb
h3b+GroZRQGq/tcQDVbYOO6cyRMR9IohVJk0b9wnnUHoZpoA4H79UUfIB4sZngma
enL/9magP1uAHxPxEa5i/yYqR0MYfz4+PGdvqyj91NrkZm3WIpwzqW/KZp8YnD77
VzGVodT8xqAoHW+bHiza9Jmm9Rkf5/0i0JY7GXoJgk4QBG/Fcp0OR5NUWxN3PEM0
dpeiU4GI5wOz5RAIOvSv7u1h0ZxMnJG4B4MKniIAr4yD7WYYZh/VxEPeiS/E1CVx
qHV5VVCoEIoYVHIuFIyFu1lIcei53VD6V690rmn0bp4A5hs+kErhThvkok3c
=+mCN
-----END PGP PUBLIC KEY BLOCK-----
EOF
  gpg --import /tmp/hashicorp.asc
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Importing of HashiCorp GPG key failed. stopping here."
    exit ${rCode}
  fi
  rm -f /tmp/hashicorp.asc
else
  log "INFO" "Already got HashiCorp key in your keyring"
fi

## get media
#
# remove existing as unzip -o varies platform-platform
rm -f ${TOOL}_${VERSION}_${PLATFORM}.zip 2>/dev/null
log "INFO" "Getting https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_${PLATFORM}.zip"
curl -#Ok https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_${PLATFORM}.zip
rCode=${?}
if [[ $rCode -gt 0 ]]
then
  log "ERROR" "Failed to download https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_${PLATFORM}.zip"
  exit ${rCode}
fi
rm -f ${TOOL}_${VERSION}_SHA256SUMS 2>/dev/null
log "INFO" "Getting https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_SHA256SUMS"
curl -#Ok https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_SHA256SUMS
rCode=${?}
if [[ $rCode -gt 0 ]]
then
  log "ERROR" "Failed to download https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_SHA256SUMS"
  exit ${rCode}
fi

rm -f ${TOOL}_${VERSION}_SHA256SUMS.sig 2>/dev/null
log "INFO" "Getting https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_SHA256SUMS.sig"
curl -#Ok https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_SHA256SUMS.sig
rCode=${?}
if [[ $rCode -gt 0 ]]
then
  log "ERROR" "Failed to download https://releases.hashicorp.com/${TOOL}/${VERSION}/${TOOL}_${VERSION}_SHA256SUMS.sig"
  exit ${rCode}
fi

log "INFO" "Verifying SHA256SUMS file"
gpg --verify ${TOOL}_${VERSION}_SHA256SUMS.sig ${TOOL}_${VERSION}_SHA256SUMS >/dev/null 2>&1
rCode=${?}
if [[ ${rCode} -gt 0 ]]
then
  log "ERROR" "Failed to verify ${TOOL}_${VERSION}_SHA256SUMS"
  exit ${rCode}
else
  log "INFO" "OK signature for SHA256SUMS file checks out"
fi

log "INFO" "Grepping ${TOOL}_${VERSION}_${PLATFORM}.zip from ${TOOL}_${VERSION}_SHA256SUMS and comparing sums"
PUTATIVESUM=$(grep ${TOOL}_${VERSION}_${PLATFORM}.zip ${TOOL}_${VERSION}_SHA256SUMS  | awk '{print $1}')
rCode=${?}
if [[ ${rCode} -gt 0 ]]
then
  log "ERROR" "Failed to get PUTATIVESUM |${PUTATIVESUM}|"
  exit ${rCode}
else
  log "INFO" "OK putative SHA256SUM checks out: ${PUTATIVESUM}"
fi

FOUNDSUM=$(sha256sum ${TOOL}_${VERSION}_${PLATFORM}.zip | awk '{print $1}')
rCode=${?}
if [[ ${rCode} -gt 0 ]]
then
  log "ERROR" "Failed to get FOUNDSUM |${FOUNDSUM}|"
  exit ${rCode}
else
  log "INFO" "OK found SHA256SUM checks out: ${FOUNDSUM}"
fi

if [ "${PUTATIVESUM}" != "${FOUNDSUM}" ]
then
  log "ERROR" "Sum of zip ${TOOL}_${VERSION}_${PLATFORM}.zip is not what is in the SHA256SUMS file.  Possible tampering!"
  exit 1
else
  log "INFO" "Sum of ${TOOL}_${VERSION}_${PLATFORM}.zip checks out.  Unzipping into local directory..."
  unzip -o ${TOOL}_${VERSION}_${PLATFORM}.zip >/dev/null 2>/dev/null
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Unzip operation failed.  Stopping here"
  fi
  log "INFO" "Tidying away download files"
  rm ${TOOL}_${VERSION}_${PLATFORM}.zip
  rm ${TOOL}_${VERSION}_SHA256SUMS
  rm ${TOOL}_${VERSION}_SHA256SUMS.sig
fi

log "INFO" "All done.  File is:"
ls -la ./${TOOL}
if [[ $(echo ${PLATFORM} | grep ${OSNAME}) ]]
then
  ./${TOOL} --version
else
  log "WARN" "Downloaded version is for ${PLATFORM} so will not run on this OS (${OSNAME})"
fi
#
## done


