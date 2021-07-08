#!/bin/bash
#
## base-init.sh
## (c) 2020:05:16::ml4
## Initialise the base image, call the CIS benchmarking scripts and clean up.
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
## https://intoli.com/blog/exit-on-errors-in-bash-scripts/
## https://stackoverflow.com/questions/3684212/using-strftime-function-in-mawk
## https://stackoverflow.com/a/25548995/259453
#
LASTCOMM=
CURRCOMM=
LOGFILE=/root/base.log
exec > >(stdbuf -i0 -oL -eL awk '{print strftime("%Y-%m-%d %H:%M:%S"), $0 }' | stdbuf -i0 -oL -eL tee "$LOGFILE") 2>&1
trap 'LASTCOMM=${CURRCOMM}; CURRCOMM=${BASH_COMMAND}' DEBUG
trap 'log "ERROR" "Command \"${LASTCOMM}\" exited with exit code $?."' EXIT

## convenience function to reduce lines of code while handling exit codes
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
banner "BASE INIT"
echo "##################################################################################################"

# Disable daily apt unattended updates.
echo 'APT::Periodic::Enable "0";' | tee -a /etc/apt/apt.conf.d/10periodic

## handle initial updates from origin - full distribution upgrade to include kernel upgrades etc.
#
checkOrRun "sudo apt-get --quiet --assume-yes update"
checkOrRun "sudo apt-get --quiet --assume-yes dist-upgrade"

## deposit phoenix file which can be edited by phoenix build to enable contextual relevance in the auditd
#
checkOrRun "sudo touch /etc/phoenix"
checkOrRun "echo "undifferentiated" | sudo tee /etc/phoenix"

## ensure that the ubuntu home directory is locked
#
checkOrRun "sudo chmod 700 /home/ubuntu"

## set up a systemd service unit in to which any boot additions are required (e.g. cis 2.0.1 4.2.3)
#
checkOrRun "sudo mkdir -pm 0755 /usr/local/bin"
cat << 'EOF' | sudo tee -a /etc/systemd/system/base-boot.service
################################################################################
# base-boot.service
#
# This service unit is for additional startup services required on boot
# By @ml4
# Licensed under the MIT licence.
#
################################################################################

[Unit]
Description=Runs /usr/local/bin/base-boot.sh

[Service]
ExecStart=/usr/local/bin/base-boot.sh

[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' | sudo tee -a /usr/local/bin/base-boot.sh
#!/bin/bash

## boot notice
#
ME=$(hostname -f)
echo " " | mail -s "${ME} just booted" %%GMAIL%%

## ensure /var/logs are only readable by root
#
sudo find /var/log -type f -exec sudo chmod g-wx,o-rwx "{}" + -o -type d -exec sudo chmod g-w,o-rwx "{}" +
EOF
sudo sed -i "s/%%GMAIL%%/${GMAIL}/" /usr/local/bin/base-boot.sh
checkOrRun "sudo chown root:root /usr/local/bin/base-boot.sh"
checkOrRun "sudo chmod 744 /usr/local/bin/base-boot.sh"
checkOrRun "sudo systemctl enable base-boot"
checkOrRun "sudo systemctl start base-boot"

echo "##################################################################################################"
echo
banner "INIT DONE"
echo "##################################################################################################"
trap 'echo' EXIT
exit 0
#
## Jah Brendan
