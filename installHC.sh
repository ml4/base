#!/bin/bash
#
## installHC.sh
## 2021-01-06 ml4
## Automate the secure downloading of a tool from releases.hashicorp.com to the current machine
## Ubuntu/Debian only, but capable to download Consul, Vault and Nomad.
## Bits ripped off similar work by @methridge together with my desktop downloader.
## Needs access to root to be effective.
#
## NOTE: Due to use of Gruntworks run scripts (not install scripts as I already did this one and theirs
## does not verify GPG), this script is currently for consul, vault and nomad only.
#
#############################################################################################################################

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
readonly SCRIPT_NAME="$(basename "$0")"
readonly SYSTEM_BIN_DIR="/usr/local/bin"

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

function install_dependencies {
  local -r tool="$1"
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes update"
  apt-get --quiet --assume-yes update
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes upgrade"
  apt-get --quiet --assume-yes upgrade
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes dist-upgrade"
  apt-get --quiet --assume-yes dist-upgrade
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes autoremove"
  apt-get --quiet --assume-yes autoremove
  log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes install curl unzip jq net-tools git"
  apt-get --quiet --assume-yes install curl unzip jq net-tools git telnet

  log "INFO" ${FUNCNAME[0]} "Installing AWS CLI"
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  ./aws/install

  if [[ ${tool} == "consul" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Installing CNI plugins"
    curl -sSL -o /tmp/cni-plugins.tgz https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz
    mkdir -p /opt/cni/bin
    tar -C /opt/cni/bin -xzf /tmp/cni-plugins.tgz
  fi

  if [[ ${tool} == "vault" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Installing Lib Cap"
    apt-get --quiet --assume-yes install libcap2-bin
  fi

  log "INFO" ${FUNCNAME[0]} "Dependancies Installed"
}

function user_exists {
  local -r username="$1"
  id "${username}" >/dev/null 2>&1
}

function create_user {
  local -r tool="$1"
  if $(user_exists "${tool}"); then
    echo "User ${tool} already exists. Will not create again."
  else
    log "INFO" ${FUNCNAME[0]} "Creating user named ${tool}"
    useradd --system --home /etc/${tool}.d --shell /bin/false ${tool}
  fi
}

function create_install_paths {
  local -r tool="$1"
  log "INFO" ${FUNCNAME[0]} "Creating install dirs for ${tool}"

  ## deployment guides - Jan 2021
  #
  ## consul
  #
  ## /usr/bin       = binary
  ## /opt/consul    = data
  ## /etc/consul.d  = cfg, tls cert/key
  #
  ## nomad
  #
  ## /usr/local/bin = binary      # /usr/bin used for this
  ## /opt/nomad     = data
  ## /etc/nomad.d   = cfg, tls cert/key
  #
  ## vault
  #
  ## /usr/local/bin = binary      # /usr/bin used for this
  ## /etc/vault.d   = cfg, tls cert/key
  #
  ## Sounds like /usr/bin for Consul is to match FHS and packaging efforts
  ## so I will use /usr/bin for all tools and pressure the team to snap into line.
  ## As /usr/bin has to be present, create only data and cfg dirs
  #
  mkdir --parents /opt/${tool}/{bin,config,data,tls/ca,log}
  mkdir --parents /etc/${tool}.d
}

## remove ent/prem capability while knitting into AWS pipeline
#
function install_binaries {
  platform="linux_amd64"
  local -r tool="${1}"
  local -r version="${2}"
  dest_path="/opt/${tool}/bin/${tool}"

  ## handle keys first
  #
  if [[ -z $(gpg --list-keys | grep 51852D87348FFC4C) ]]
  then
    log "INFO" ${FUNCNAME[0]} "Getting HashiCorp public GPG key"
    cat <<EOF >/tmp/hashicorp.asc
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
ZF5q4h4I33PSGDdSvGXn9UMY5Isjpg==
=7pIB
-----END PGP PUBLIC KEY BLOCK-----
EOF
    gpg --import /tmp/hashicorp.asc
    rm -f /tmp/hashicorp.asc
  else
    log "INFO" ${FUNCNAME[0]} "Already got HashiCorp key in your keyring"
  fi

  ## get media
  #
  # remove existing as unzip -o varies platform-platform
  rm -f ${tool}_${version}_${platform}.zip 2>/dev/null
  log "INFO" ${FUNCNAME[0]} "Getting https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_${platform}.zip"
  curl -#Ok https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_${platform}.zip
  rm -f ${tool}_${version}_SHA256SUMS 2>/dev/null

  log "INFO" ${FUNCNAME[0]} "Getting https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS"
  curl -#Ok https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS
  rm -f ${tool}_${version}_SHA256SUMS.sig 2>/dev/null

  log "INFO" ${FUNCNAME[0]} "Getting https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS.sig"
  curl -#Ok https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS.sig

  log "INFO" ${FUNCNAME[0]} "Verifying SHA256SUMS file"
  gpg --verify ${tool}_${version}_SHA256SUMS.sig ${tool}_${version}_SHA256SUMS >/dev/null 2>&1

  log "INFO" ${FUNCNAME[0]} "Grepping ${tool}_${version}_${platform}.zip from ${tool}_${version}_SHA256SUMS and comparing sums"
  putativesum=$(grep ${tool}_${version}_${platform}.zip ${tool}_${version}_SHA256SUMS  | awk '{print $1}')

  foundsum=$(sha256sum ${tool}_${version}_${platform}.zip | awk '{print $1}')

  if [ "${putativesum}" != "${foundsum}" ]
  then
    log "ERROR" ${FUNCNAME[0]} "Sum of zip ${tool}_${version}_${platform}.zip is not what is in the SHA256SUMS file.  Possible tampering!"
    exit 1
  else
    log "INFO" ${FUNCNAME[0]} "Sum of ${tool}_${version}_${platform}.zip checks out.  Unzipping into local directory..."
    unzip -o ${tool}_${version}_${platform}.zip >/dev/null 2>&1
    log "INFO" ${FUNCNAME[0]} "Tidying away download files"
    rm ${tool}_${version}_${platform}.zip
    rm ${tool}_${version}_SHA256SUMS
    rm ${tool}_${version}_SHA256SUMS.sig
  fi

  if [[ "${local_only}" == "NO" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Moving ${tool} binary to ${dest_path}"
    chown ${tool}:${tool} "${tool}"
    mv "${tool}" "${dest_path}"
    chmod a+x "${dest_path}"
    chown --recursive ${tool}:${tool} /opt/${tool}
  fi

  ## create symlink in system bin
  #
  local -r symlink_path="${SYSTEM_BIN_DIR}/${tool}"
  if [[ -f "${symlink_path}" ]]; then
    log "INFO" ${FUNCNAME[0]} "Symlink ${symlink_path} already exists. Will not add again."
  else
    log "INFO" ${FUNCNAME[0]} "Adding symlink to ${dest_path} in ${symlink_path}"
    ln -s "${dest_path}" "${symlink_path}"
  fi
}

function run_post_installation_tasks {
  local -r tool="$1"
  log "INFO" ${FUNCNAME[0]} "Running post installation tasks for ${tool}"

  ## installation of gruntworks run-tool scripting
  #
  log "INFO" ${FUNCNAME[0]} "Cloning Gruntworks module to install run-${tool} script"
  pushd ${TMPDIR} 2>/dev/null
  git clone https://github.com/hashicorp/terraform-aws-${tool}.git
  rCode=${?}
  if [[ ${rCode} > 0 ]]
  then
    log "ERROR" ${FUNCNAME[0]} "Problem with git clone git@github.com:hashicorp/terraform-aws-${tool}.git"
    exit ${rCode}
  fi

  mv terraform-aws-${tool}/modules/run-${tool}/run-${tool} /opt/${tool}/bin/run-${tool}
  rCode=${?}
  if [[ ${rCode} > 0 ]]
  then
    log "ERROR" ${FUNCNAME[0]} "Problem with mv terraform-aws-${tool}/modules/run-${tool}/run-${tool} /opt/${tool}/bin/run-${tool}"
    exit ${rCode}
  fi

  chmod a+x /opt/${tool}/bin/run-${tool}
  rCode=${?}
  if [[ ${rCode} > 0 ]]
  then
    log "ERROR" ${FUNCNAME[0]} "Problem with chmod a+x /opt/${tool}/bin/run-${tool}"
    exit ${rCode}
  else
    log "INFO" ${FUNCNAME[0]} "Installed /opt/${tool}/bin/run-${tool}"
  fi

  if [[ "${tool}" == "consul" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Adding systemd-resolved for ${tool}"
    terraform-aws-consul/modules/setup-systemd-resolved/setup-systemd-resolved
  fi
  popd 2>/dev/null

  if [[ "${tool}" == "consul" ]]
  then
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
    if [[ -z $(iptables -L | grep 8500) ]]
    then
      log "ERROR" ${FUNCNAME[0]} "iptables commands did not stick. Investigate further"
      exit 1
    fi
  elif [[ "${tool}" == "nomad" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Doing nothing yet for ${tool}"
  elif [[ "${tool}" == "terraform" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Doing nothing yet for ${tool}"
  elif [[ "${tool}" == "vault" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Setting firewall for ${tool}"
    iptables -A INPUT -p tcp --dport 8200 -m state --state NEW -j ACCEPT
    iptables -A INPUT -p tcp --dport 8201 -m state --state NEW -j ACCEPT
  fi
}

# function install_dnsmasq {
#   log "INFO" ${FUNCNAME[0]} "Installing Dnsmasq and ResolvConf"
#   apt-get --quiet --assume-yes install dnsmasq resolvconf
# }

# function configure_dnsmasq_resolv {
#   log "INFO" ${FUNCNAME[0]} "Configuring Dnsmasq and ResolvConf"
#   # Configure dnsmasq
#   mkdir --parents /etc/dnsmasq.d
#   cat <<EOF >/tmp/10-consul
# # Enable forward lookup of the '$consul_domain' domain:
# server=/consul/127.0.0.1#8600

# listen-address=127.0.0.1
# bind-interfaces
# EOF
#   mv -f /tmp/10-consul /etc/dnsmasq.d
#   chown --recursive root:root /etc/dnsmasq.d

#   # Setup resolv to use dnsmasq for consul
#   mkdir --parents /etc/resolvconf/resolv.conf/
#   echo "127.0.0.1" | tee /etc/resolvconf/resolv.conf/head
#   echo "127.0.0.53" | tee -a /etc/resolvconf/resolv.conf/head
#   systemctl enable resolvconf
#   systemctl start resolvconf
#   systemctl restart dnsmasq
# }

# function create_service {
#   local -r tool="$1"
#   local -r tmpf="/tmp/${tool}.service"
#   touch "${tmpf}"

#   cat <EOF >/tmp/${tool}.service
# [Unit]
# Description="HashiCorp ${tool}"
# Documentation=https://www.hashicorp.com/
# Requires=network-online.target
# After=network-online.target
# ConditionFileNotEmpty=/etc/${tool}.d/${tool}.hcl

# [Service]
# Type=notify
# User=${tool}
# Group=${tool}
# Restart=on-failure
# EOF
#   rCode=${?}
#   if [[ ${rCode} > 0 ]]
#   then
#     echo "ERROR: Return status greater than zero when writing file /tmp/${tool}.service"
#     exit ${rCode}
#   fi


#   if [[ ${tool} == "consul" ]]
#   then
#     cat <<EOF >/tmp/${tool}.service
# ExecStart=/opt/${tool}/bin/${tool} agent -config-dir=/etc/${tool}.d/ -data-dir /opt/${tool}/data
# ExecReload=/opt/${tool}/bin/${tool} reload
# KillMode=process
# TimeoutSec=300s
# LimitNOFILE=65536

# [Install]
# WantedBy=multi-user.target
# EOF
#   elif [[ ${tool} == "vault" ]]
#   then
#     cat <<EOF >/tmp/${tool}.service
# ProtectSystem=full
# ProtectHome=read-only
# PrivateTmp=yes
# PrivateDevices=yes
# SecureBits=keep-caps
# AmbientCapabilities=CAP_IPC_LOCK
# Capabilities=CAP_IPC_LOCK+ep
# CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
# NoNewPrivileges=yes
# ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
# ExecReload=/bin/kill --signal HUP \$MAINPID
# KillMode=process
# KillSignal=SIGINT
# RestartSec=5
# TimeoutStopSec=30
# StartLimitIntervalSec=60
# StartLimitBurst=3
# EOF
#   fi

#   mkdir --parents /usr/lib/systemd/system
#   mv -f /tmp/${tool}.service /usr/lib/systemd/system/${tool}.service

#   log "INFO" ${FUNCNAME[0]} "Configuring and enabling ${tool} Service"
#   chown root:root /usr/lib/systemd/system/${tool}.service
#   chmod 644 /usr/lib/systemd/system/${tool}.service
#   systemctl enable ${tool}  # started by the run-${tool}.sh script (which is run by terraform on provision)
# }

# function install_envoy {
#   log "INFO" ${FUNCNAME[0]} "Installing dnsmasq resolvconf"
#   apt-get --quiet --assume-yes install dnsmasq resolvconf

#   log "INFO" ${FUNCNAME[0]} "Updating"
#   apt-get --quiet --assume-yes update

#   log "INFO" ${FUNCNAME[0]} "Installing apt-transport-https ca-certificates curl gnupg-agent software-properties-common"
#   apt-get --quiet --assume-yes install apt-transport-https ca-certificates curl gnupg-agent software-properties-common

#   log "INFO" ${FUNCNAME[0]} "Curling getenvoy apt-key"
#   curl -sL 'https://getenvoy.io/gpg' | apt-key add -
#   apt-key fingerprint 6FF974DB 2>/dev/null

#   log "INFO" ${FUNCNAME[0]} "add-apt-repository getenvoy-deb"
#   add-apt-repository \
#     "deb [arch=amd64] https://dl.bintray.com/tetrate/getenvoy-deb \
#     $(lsb_release -cs) \
#     nightly"

#   log "INFO" ${FUNCNAME[0]} "apt-get --quiet --assume-yes update"
#   apt-get --assume-yes update

#   log "INFO" ${FUNCNAME[0]} "apt-get install -y getenvoy-envoy"
#   apt-get install -y getenvoy-envoy
# }

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

  ## write descriptor
  #
  date=$(date '+%Y-%m-%d %H:%M')
  echo "## phoenix build descriptor" | tee /etc/phoenix
  echo "#" | tee -a /etc/phoenix
  echo "tool:  ${tool}" | tee -a /etc/phoenix
  echo "build: ${date}" | tee -a /etc/phoenix

  ## if bastion machine_type, exit.  This should be the only non-HashiCorp machine type
  #
  if [[ ${tool} == "bastion" ]]
  then
    log "INFO" ${FUNCNAME[0]} "Bastion deployment - nothing more to do"
    exit 0
  fi

  ## create separate temp dir for apt commands given that /tmp has noexec set on CIS
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

  if [[ "${local_only}" == "NO" ]]
  then
    log "INFO" ${FUNCNAME[0]} "MAIN MODE - INSTALLATION WITH USER CREATION AND DEPENDENCY MANAGEMENT"
    install_dependencies ${tool}
    create_user ${tool}
    create_install_paths ${tool}
  else
    log "INFO" ${FUNCNAME[0]} "LOCAL ONLY MODE - DOWNLOADING BINARY TO $(pwd) ONLY"
  fi

  install_binaries ${tool} "${version}"

  if [[ "${local_only}" == "NO" ]]
  then
    # if [[ "${tool}" == "consul" ]]
    # then
    #   install_dnsmasq # even without attempt to install resolvconf, presumably dnsmasq was trying a /tmp exec
    #   configure_dnsmasq_resolv
    #   install_envoy # was not working from https://www.getenvoy.io/install/envoy/ubuntu/ on 2020-01-06
    # fi
    run_post_installation_tasks ${tool}
    # create_service ${tool}
  fi

  log "INFO" ${FUNCNAME[0]} "All done.  Tool configuration is expected to take place outside this script"
  #
  ## expects a configuration to be made, but this is just an installer.
  ## don't dig gruntworks mega cli wrapping script.  Let's get tool config in a file.
}

main "$@"
#
## jah
