#!/bin/bash
#
## base-clean.sh
## (c) 2020:05:30::ml4
## Clean up the base image.
#
###########################################################################################

set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

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


## Process stdout/err handling
## https://intoli.com/blog/exit-on-errors-in-bash-scripts/
## https://stackoverflow.com/questions/3684212/using-strftime-function-in-mawk
## https://stackoverflow.com/a/25548995/259453
#
LASTCOMM=
CURRCOMM=
LOGFILE=/root/base.log
exec > >(stdbuf -i0 -oL -eL awk '{print strftime("%Y-%m-%d %H:%M:%S"), $0 }' | stdbuf -i0 -oL -eL tee "$LOGFILE") 2>&1
trap 'LASTCOMM=${CURRCOMM}; CURRCOMM=${BASH_COMMAND}' DEBUG
trap 'log "ERROR" "Command \"${LASTCOMM}\" exited with exit code $?."' EXIT

## convenience function to reduce lines of code while handling exit codes
#
function handleExit {
  local -r cmdOrMessage="${1}"
  local -r rCode="${2}"
  echo ' '
  log "ERROR" "FAILED:    ${cmdOrMessage}"
  log "ERROR" "EXIT CODE: ${rCode}"
  exit ${rCode}
}

## convenience function to test return code. Some commands don't work (sed or pipelines) due to quoting reasons so
## have separate treatments below
#
function checkOrRun {
  local -r cmd="${1}"
  log "INFO" "${cmd}"
  ${cmd}
}

echo "##################################################################################################"
echo
banner "BASE CLEAN"
echo "##################################################################################################"

## Add cloud-init ready for cloud building
#
checkOrRun "sudo apt-get --quiet --assume-yes install dialog apt-utils"   # these before iptables-persistent
checkOrRun "sudo apt-get --quiet --assume-yes install cloud-init iptables-persistent curl unzip jq net-tools git telnet"
# checkOrRun "sudo cloud-init init"

## Install aws cli v2
#
log "INFO" "Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# Apt cleanup.
## Remove other packages not covered by CIS benchmarking.
#
checkOrRun "sudo apt-get --quiet --assume-yes purge --auto-remove nano ntfs-3g"
checkOrRun "sudo apt-get --quiet --assume-yes autoremove"
checkOrRun "sudo apt-get --quiet --assume-yes update"

## additional kernel tuning
log "INFO" "RUNNING additional kernel tweaks"
# https://russ.garrett.co.uk/2009/01/01/linux-kernel-tuning/
# https://community.mellanox.com/s/article/linux-sysctl-tuning
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_timestamps = 0
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

sync
echo "##################################################################################################"
echo
banner "ALL DONE"
echo "##################################################################################################"
trap 'echo' EXIT
exit 0
#
## Jah Brendan
## https://archive.org/stream/Crash_No._41_1987-06_Newsfield_GB/Crash_No._41_1987-06_Newsfield_GB_djvu.txt
