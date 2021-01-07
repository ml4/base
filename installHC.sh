#!/bin/bash
#
## installHC.sh
## 2021-01-06 ml4
## Automate the secure downloading of a tool from releases.hashicorp.com to the current machine
## Ubuntu/Debian only, but capable to download Consul, Vault and Nomad.
## Bits ripped off similar work by @methridge together with my desktop downloader.
## Needs sudo access to root to be effective.
#
#############################################################################################################################

set -Eo pipefail

export DEBIAN_FRONTEND=noninteractive

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
  elif [ "${level}" == "WARN" ]
  then
    COL=${bldylw}
  fi
  local -r message="$2"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "${bldcyn}${timestamp}${txtrst} [${COL}${level}${txtrst}] ${message}"
}

## next few I found in @methridge 2020-01-01ish
#
function install_dependencies {
  log "INFO" "Installing dependencies"
  sudo apt-get --quiet --assume-yes update
  sudo apt-get --quiet --assume-yes upgrade
  sudo apt-get --quiet --assume-yes dist-upgrade
  sudo apt-get --quiet --assume-yes autoremove
  sudo apt-get --quiet --assume-yes install curl unzip jq net-tools docker.io

  # Install CNI
  curl -sSL -o /tmp/cni-plugins.tgz https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz
  sudo mkdir -p /opt/cni/bin
  sudo tar -C /opt/cni/bin -xzf /tmp/cni-plugins.tgz

  log "INFO" "Dependancies Installed"
}

function user_exists {
  local -r username="$1"
  id "$username" >/dev/null 2>&1
}

function create_user {
  local -r user="$1"
  if $(user_exists "$user"); then
    echo "User $user already exists. Will not create again."
  else
    log "INFO" "Creating user named $user"
    sudo useradd --system --home /etc/$user.d --shell /bin/false $user
  fi
}

function create_install_paths {
  local -r tool="$1"
  log "INFO" "Creating install dirs for ${tool}"
  sudo mkdir --parents /etc/${tool}.d
  sudo mkdir --parents /opt/${tool}/bin
  sudo mkdir --parents /opt/${tool}/data
  sudo mkdir --parents /opt/${tool}/log
  sudo mkdir --parents /opt/${tool}/tls
}

## remove ent/prem capability while knitting into AWS pipeline
#
function install_binaries {
  platform="linux_amd64"
  local -r tool="${1}"
  local -r version="${2}"
  dest_path="/opt/${tool}/bin"

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
  rm -f ${tool}_${version}_${platform}.zip 2>/dev/null
  log "INFO" "Getting https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_${platform}.zip"
  curl -#Ok https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_${platform}.zip
  rCode=${?}
  if [[ $rCode -gt 0 ]]
  then
    log "ERROR" "Failed to download https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_${platform}.zip"
    exit ${rCode}
  fi
  rm -f ${tool}_${version}_SHA256SUMS 2>/dev/null
  log "INFO" "Getting https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS"
  curl -#Ok https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS
  rCode=${?}
  if [[ $rCode -gt 0 ]]
  then
    log "ERROR" "Failed to download https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS"
    exit ${rCode}
  fi

  rm -f ${tool}_${version}_SHA256SUMS.sig 2>/dev/null
  log "INFO" "Getting https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS.sig"
  curl -#Ok https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS.sig
  rCode=${?}
  if [[ $rCode -gt 0 ]]
  then
    log "ERROR" "Failed to download https://releases.hashicorp.com/${tool}/${version}/${tool}_${version}_SHA256SUMS.sig"
    exit ${rCode}
  fi

  log "INFO" "Verifying SHA256SUMS file"
  gpg --verify ${tool}_${version}_SHA256SUMS.sig ${tool}_${version}_SHA256SUMS >/dev/null 2>&1
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to verify ${tool}_${version}_SHA256SUMS"
    exit ${rCode}
  else
    log "INFO" "OK signature for SHA256SUMS file checks out"
  fi

  log "INFO" "Grepping ${tool}_${version}_${platform}.zip from ${tool}_${version}_SHA256SUMS and comparing sums"
  putativesum=$(grep ${tool}_${version}_${platform}.zip ${tool}_${version}_SHA256SUMS  | awk '{print $1}')
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to get putativesum |${putativesum}|"
    exit ${rCode}
  else
    log "INFO" "OK putative SHA256SUM checks out: ${putativesum}"
  fi

  foundsum=$(sha256sum ${tool}_${version}_${platform}.zip | awk '{print $1}')
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to get foundsum |${foundsum}|"
    exit ${rCode}
  else
    log "INFO" "OK found SHA256SUM checks out: ${foundsum}"
  fi

  if [ "${putativesum}" != "${foundsum}" ]
  then
    log "ERROR" "Sum of zip ${tool}_${version}_${platform}.zip is not what is in the SHA256SUMS file.  Possible tampering!"
    exit 1
  else
    log "INFO" "Sum of ${tool}_${version}_${platform}.zip checks out.  Unzipping into local directory..."
    unzip -o ${tool}_${version}_${platform}.zip >/dev/null 2>&1
    rCode=${?}
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Unzip operation failed.  Stopping here"
    fi
    log "INFO" "Tidying away download files"
    rm ${tool}_${version}_${platform}.zip
    rm ${tool}_${version}_SHA256SUMS
    rm ${tool}_${version}_SHA256SUMS.sig
  fi

  if [[ -z "${local_only}" ]]
  then
    log "INFO" "Moving ${tool} binary to ${dest_path}"
    sudo mv "${tool}" "${dest_path}"
    rCode=${?}
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Failed to sudo mv ${tool} ${dest_path}"
      exit ${rCode}
    else
      log "INFO" "Moved ${tool} to ${dest_path}"
    fi

    sudo chown "root:root" "${dest_path}"
    rCode=${?}
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Failed to sudo chown root:root ${dest_path}"
      exit ${rCode}
    else
      log "INFO" "Chowned root:root ${dest_path}"
    fi

    sudo chmod a+x "${dest_path}"
    rCode=${?}
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Failed to sudo chmod a+x ${dest_path}"
      exit ${rCode}
    else
      log "INFO" "Chmoded a+x ${dest_path}"
    fi

    sudo chown --recursive ${tool}:${tool} /opt/${tool}
    rCode=${?}
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Failed to sudo chown --recursive ${tool}:${tool} /opt/${tool}"
      exit ${rCode}
    else
      log "INFO" "OK: sudo chown --recursive ${tool}:${tool} /opt/${tool}"
    fi
  fi
}

function install_dnsmasq {
  log "INFO" "Installing Dnsmasq and ResolvConf"
  sudo apt-get --quiet --assume-yes install dnsmasq resolvconf
}

function configure_dnsmasq_resolv {
  log "INFO" "Configuring Dnsmasq and ResolvConf"
  # Configure dnsmasq
  sudo mkdir --parents /etc/dnsmasq.d
  cat <<EOF >/tmp/10-consul
# Enable forward lookup of the '$consul_domain' domain:
server=/consul/127.0.0.1#8600

listen-address=127.0.0.1
bind-interfaces
EOF
  rCode=${?}
  if [[ ${rCode} == 0 ]]
  then
    sudo mv -f /tmp/10-consul /etc/dnsmasq.d
    rCode=${?}
    if [[ ${rCode} > 0 ]]
    then
      log "ERROR" "Problem moving /tmp/10-consul /etc/dnsmasq.d"
      exit ${rCode}
    else
      sudo chown --recursive root:root /etc/dnsmasq.d
      if [[ ${rCode} > 0 ]]
      then
        log "ERROR" "Problem with sudo chown --recursive root:root /etc/dnsmasq.d"
        exit ${rCode}
      fi
    fi
  fi
  # Setup resolv to use dnsmasq for consul
  sudo mkdir --parents /etc/resolvconf/resolv.conf/
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to sudo mkdir --parents /etc/resolvconf/resolv.conf/"
    exit ${rCode}
  else
    log "INFO" "OK: sudo mkdir --parents /etc/resolvconf/resolv.conf/"
  fi
  echo "127.0.0.1" | sudo tee /etc/resolvconf/resolv.conf/head
  echo "127.0.0.53" | sudo tee -a /etc/resolvconf/resolv.conf/head
  sudo systemctl enable resolvconf
  sudo systemctl start resolvconf
  sudo systemctl restart dnsmasq
}

function create_service {
  local -r tool="$1"
  cat <<EOF >/tmp/${tool}.service
[Unit]
Description="HashiCorp ${tool}"
Documentation=https://www.hashicorp.com/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/${tool}.d/${tool}.hcl

[Service]
Type=notify
User=${tool}
Group=${tool}
ExecStart=/opt/${tool}/bin/${tool} agent -config-dir=/etc/${tool}.d/ -data-dir /opt/${tool}/data
ExecReload=/opt/${tool}/bin/${tool} reload
KillMode=process
Restart=on-failure
TimeoutSec=300s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to execute heredoc to /tmp/${tool}.service"
    exit ${rCode}
  else
    sudo mkdir --parents /usr/lib/systemd/system
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Failed to execute sudo mkdir --parents /usr/lib/systemd/system"
      exit ${rCode}
    fi
    sudo mv /tmp/${tool}.service /usr/lib/systemd/system/${tool}.service
    if [[ ${rCode} -gt 0 ]]
    then
      log "ERROR" "Failed to execute sudo mv /tmp/${tool}.service /usr/lib/systemd/system/${tool}.service"
      exit ${rCode}
    fi
  fi

  log "INFO" "Configuring ${tool} Service"

  sudo chown root:root /usr/lib/systemd/system/${tool}.service
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to execute sudo chown root:root /usr/lib/systemd/system/${tool}.service"
    exit ${rCode}
  fi

  sudo chmod 644 /usr/lib/systemd/system/${tool}.service
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "Failed to execute sudo chmod 644 /usr/lib/systemd/system/${tool}.service"
    exit ${rCode}
  fi
}

function install_envoy {
  log "INFO" "Installing dnsmasq resolvconf"
  sudo apt-get --quiet --assume-yes install dnsmasq resolvconf
  log "INFO" "Updating"
  sudo apt-get --quiet --assume-yes update
  log "INFO" "Installing apt-transport-https ca-certificates curl gnupg-agent software-properties-common"
  sudo apt-get --quiet --assume-yes install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
  log "INFO" "Curling getenvoy apt-key"
  curl -sL 'https://getenvoy.io/gpg' | sudo apt-key add -
  apt-key fingerprint 6FF974DB 2>/dev/null
  rCode=${?}
  if [[ ${rCode} -gt 0 ]]
  then
    log "ERROR" "apt-key fingerprint 6FF974DB did not check out.  Stopping here"
    exit ${rCode}
  fi

  log "INFO" "add-apt-repository getenvoy-deb"
  sudo add-apt-repository \
    "deb [arch=amd64] https://dl.bintray.com/tetrate/getenvoy-deb \
    $(lsb_release -cs) \
    nightly"

  log "INFO" "apt-get --quiet --assume-yes update"
  sudo apt-get --assume-yes update
  log "INFO" "sudo apt-get install -y getenvoy-envoy"
  sudo apt-get install -y getenvoy-envoy
}

#    #   ##   # #    #
##  ##  #  #  # ##   #
# ## # #    # # # #  #
#    # ###### # #  # #
#    # #    # # #   ##
#    # #    # # #    #

## main
#
tool=${1}
version=${2}
if [[ -z ${2} ]]
then
  usage
fi
local_only=${3}
log "INFO" "Tool: ${tool}"
log "INFO" "Version: ${version}"

log "INFO" "Setting debconf set selections up"
echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections

if [[ -z "${local_only}" ]]
then
  log "INFO" "LOCAL ONLY MODE - DOWNLOADING BINARY TO ${pwd} ONLY"
  install_dependencies
  create_user ${tool}
  create_install_paths ${tool}
fi

install_binaries ${tool} "${version}"

if [[ -z "${local_only}" ]]
then
  if [[ "${tool}" == "consul" ]]
  then
    install_dnsmasq
    configure_dnsmasq_resolv
    # install_envoy # was not working from https://www.getenvoy.io/install/envoy/ubuntu/ on 2020-01-06
  fi
  create_service ${tool}
fi

log "INFO" "All done.  Tool configuration is expected to take place outside this script"
#
## expects a configuration to be made, but this is just an installer.
## don't dig gruntworks mega cli wrapping script.  Let's get tool config in a file.
#
## done
