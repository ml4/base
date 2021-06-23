#!/bin/bash
#
## installHC.sh
## 2021-01-06 ml4
## Automate the secure downloading of a hashicorp tool from ubuntu pkg libraries to the current machine
## Ubuntu/Debian only, but capable to download Consul, Vault and Nomad.
## Bits ripped off similar work by @methridge together with my desktop downloader.
## Needs access to root to be effective.
#
#############################################################################################################################

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
readonly SCRIPT_NAME="$(basename "${0}")"

function usage {
  echo -e "Usage:\n\n"
  echo -e "\tinstallHC.sh <tool> <version> [<local_only>]\n"
  echo -e "where tool is one of the tool downloads on releases.hashicorp.com e.g. packer (local case)"
  echo -e "where version is a semver matching the download version to get e.g. 1.6.5"
  echo -e "where local_only is some text in order to instantiate \${3} which makes the download binary to local directory only"
  echo -e "if local_only is not specified, the downloader will install dependencies with apt, create a user and install directories, perms etc."
  exit 1
}

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
  elif [ "${level}" == "DIVIDE" ]
  then
    COL=${bldpur}
  elif [ "${level}" == "WARN" ]
  then
    COL=${bldylw}
  fi

  local -r func="$2"
  local -r message="$3"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "${bldcyn}${timestamp}${txtrst} [${COL}${level}${txtrst}] [${SCRIPT_NAME}:${func}] ${message}"
}

## remove ent/prem capability while knitting into AWS pipeline
#
function install_tool {
  platform="linux_amd64"
  local -r tool="${1}"
  local -r version="${2}"

  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes update"
  apt-get --quiet --assume-yes update
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes upgrade"
  apt-get --quiet --assume-yes upgrade
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes dist-upgrade"
  apt-get --quiet --assume-yes dist-upgrade
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes autoremove"
  apt-get --quiet --assume-yes autoremove

  curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
  apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
  apt-get --quiet --assume-yes install ${tool}

  log "INFO" ${FUNCNAME[0]} "Running post installation tasks for ${tool}"
  if [[ "${tool}" == "consul" ]]
  then
    log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install vault"
    apt-get --quiet --assume-yes install vault    # vault agent

    log "INFO" ${FUNCNAME[0]} "Setting firewall for ${tool}"
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8300 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8300 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8301 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8301 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p udp --dport 8301 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p udp --dport 8301 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8302 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8302 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p udp --dport 8302 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p udp --dport 8302 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8500 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8500 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8501 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8501 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8502 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8502 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8600 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8600 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 21000:21255 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 21000:21255 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 21500:21755 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 21500:21755 -m state --state NEW -j ACCEPT
  elif [[ "${tool}" == "nomad" ]]
  then
    log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install vault"
    apt-get --quiet --assume-yes install vault      # vault agent

    log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install consul"
    apt-get --quiet --assume-yes install consul     # consul agent
  elif [[ "${tool}" == "terraform" ]]
  then
    log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install vault"
    apt-get --quiet --assume-yes install vault      # vault agent

    log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install consul"
    apt-get --quiet --assume-yes install consul     # consul agent

    log "INFO" ${FUNCNAME[0]} "Setting firewall for ${tool}"
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8800 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8800 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
  elif [[ "${tool}" == "vault" ]]
  then
    log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install consul"
    apt-get --quiet --assume-yes install consul     # consul agent

    log "INFO" ${FUNCNAME[0]} "Setting firewall for ${tool}"
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8200 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8200 -m state --state NEW -j ACCEPT
    log "INFO" ${FUNCNAME[0]} "iptables -A INPUT -p tcp --dport 8201 -m state --state NEW -j ACCEPT"
    iptables -A INPUT -p tcp --dport 8201 -m state --state NEW -j ACCEPT
  fi
  iptables-save  > /etc/iptables/rules.v4
}

#    #   ##   # #    #
##  ##  #  #  # ##   #
# ## # #    # # # #  #
#    # ###### # #  # #
#    # #    # # #   ##
#    # #    # # #    #

## main
#
function main {
  if [[ ${EUID} -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
  fi

  tool=${1}
  version=${2}
  if [[ -z ${2} ]]
  then
    usage
  fi
  local_only=${3:-"NO"}

  ## if bastion machine_type, exit.  This should be the only non-HashiCorp machine type
  #
  if [[ ${tool} == "bastion" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Bastion deployment - nothing more to do"
    exit 0
  fi

  ## create separate temp dir for apt commands given that /tmp has noexec set on CIS benchmarked systems
  #
  rm -rf /home/${USER}/tmp 2> /dev/null
  mkdir --parents /home/${USER}/tmp
  TMPDIR=$(mktemp -d /home/${USER}/tmp/XXXX)
  TMP=$TMPDIR
  TEMP=$TMPDIR
  export TMPDIR TMP TEMP
  #
  ## see https://serverfault.com/a/72971/390412

  log "INFO" ${FUNCNAME[0]} "Tool: ${tool}"
  log "INFO" ${FUNCNAME[0]} "Version: ${version}"
  log "INFO" ${FUNCNAME[0]} "Setting debconf set selections up"
  echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
  install_tool ${tool} "${version}"
  log "INFO" ${FUNCNAME[0]} "All done.  Tool configuration is expected to take place outside this script"
  #
  ## expects a configuration to be made, but this is just an installer.
  ## don't dig gruntworks mega cli wrapping script.  Let's get tool config in a file.
}

main "$@"
#
## jah
