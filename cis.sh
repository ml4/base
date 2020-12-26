#!/bin/bash
#
## cis.sh: Apply CIS v2.0.1 Ubuntu 18.04 benchmarking.
## (c) 2020:10:28::ml4
## Injection script for packer to run on the build machine image to set up cis compliance.
#
###########################################################################################

set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

 ####  #  ####
#    # # #
#      #  ####
#      #      #
#    # # #    #
 ####  #  ####

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
  >&2 echo -e "[${COL}${level}${txtrst}] ${message}"
}


## Process stdout/err handling
## https://intoli.com/blog/exit-on-errors-in-bash-scripts/
## https://stackoverflow.com/questions/3684212/using-strftime-function-in-mawk
## https://stackoverflow.com/a/25548995/259453
#
last_comm=
curr_comm=
log_file=/root/base.log
exec > >(stdbuf -i0 -oL -eL awk '{print strftime("%Y-%m-%d %H:%M:%S"), $0 }' | stdbuf -i0 -oL -eL tee "$log_file") 2>&1
trap 'last_comm=${curr_comm}; curr_comm=${BASH_COMMAND}' DEBUG
trap 'log "ERROR" "Command \"${last_comm}\" exited with exit code $?."' EXIT

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
function logRun {
  local -r cis="${1}"
  local -r cmd="${2}"
  log "INFO" "${cis}: ${cmd}"
  ${cmd}
}

## init
#
DATE="$(date +%Y-%m-%d::%H%M%S)"
log "INFO" "STARTING CIS BENCHMARKING SCRIPT AT ${DATE}"

if [ -z "${GMAIL}" ]
then
  handleExit "GMAIL variable unset" "1"
fi
if [ -z "${GMAILPASSWORD}" ]
then
  handleExit "GMAILPASSWORD variable unset" "1"
fi
if [ -z "${REMOTELOGHOST}" ]
then
  log "WARN" "REMOTELOGHOST is not set; Using self pending future configuration update on hydration"
  REMOTELOGHOST=${HOSTNAME}.${DOMAIN}
fi

 #####  ###  #####          #
#     #  #  #     #        ##
#        #  #             # #
#        #   #####  #####   #
#        #        #         #
#     #  #  #     #         #
 #####  ###  #####        #####

echo
echo "##################################################################################################"
echo
banner "CIS: 1"
echo "##################################################################################################"

# CIS benchmarking 1.1 Filesystem Configuration
# CIS benchmarking 1.1.1: Remove unneeded filesystems
# CIS benchmarking 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)
# CIS benchmarking 1.1.1.8 Ensure mounting of FAT filesystems is limited (Not Scored)
# CIS benchmarking 1.1.23 Disable USB Storage (Scored)
CISCONFIG=/etc/modprobe.d/CIS.conf
for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage
do
  log "INFO" "1.1.1: Disabling ${fs}"
  echo "install ${fs} /bin/true" | sudo tee -a ${CISCONFIG}
  if [[ $(lsmod | grep ${fs}) ]]
  then
    log "INFO" "1.1.1: Removing FS ${fs}"
    sudo rmmod ${fs}
  fi
done

## %% start The following dealt with already by the preseed
#
# CIS benchmarking 1.1.2 Ensure /tmp is configured (Scored)
# CIS benchmarking 1.1.3 Ensure nodev option set on /tmp partition (Scored)
# CIS benchmarking 1.1.4 Ensure nosuid option set on /tmp partition (Scored)
# CIS benchmarking 1.1.5 Ensure noexec option set on /tmp partition (Scored)
## partman docs are awful, so have to paper over the options/noexec fstab write failure in here
## especially as adding the cis recommendation also failed to take hold.  edit the fstab in place
log "INFO" "1.1.5: Adding noexec to /etc in fstab as partman failed to do so"
sudo sed -ie 's/\( \/tmp\s*ext4\s*\)nodev,nosuid\(\s*\)/\1nodev,nosuid,noexec\2/' /etc/fstab

# CIS benchmarking 1.1.6 Ensure separate partition exists for /var (Scored)
# CIS benchmarking 1.1.7 Ensure separate partition exists for /var/tmp (Scored)
# CIS benchmarking 1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
# CIS benchmarking 1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
# CIS benchmarking 1.1.10 Ensure noexec option set on /var/tmp partition (Scored)
# CIS benchmarking 1.1.11 Ensure separate partition exists for /var/log (Scored)
# CIS benchmarking 1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
# CIS benchmarking 1.1.13 Ensure separate partition exists for /home (Scored)
# CIS benchmarking 1.1.14 Ensure nodev option set on /home partition (Scored)
#
## %% end

# CIS benchmarking 1.1.15 Ensure nodev option set on /dev/shm (Scored)
# CIS benchmarking 1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
# CIS benchmarking 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)
log "INFO" "1.1.15-1.1.17: Adding explicit /dev/shm content to fstab..."
echo -e "tmpfs\t\t\t\t\t\t/dev/shm\t\ttmpfs\tdefaults,nodev,nosuid,noexec  0 0" | sudo tee -a /etc/fstab

# CIS benchmarking 1.1.18 Ensure nodev option set on removable media partitions (Not Scored)
# CIS benchmarking 1.1.19 Ensure nosuid option set on removable media partitions (Not Scored)
# CIS benchmarking 1.1.20 Ensure noexec option set on removable media partitions (Not Scored)
# CIS benchmarking 1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)
for dir in $(df --local -P | tail -n +2 | awk '{print $6}')
do
  log "INFO" "1.1.21: Running check in ${dir} for directories that need the sticky bit"
  sudo find "${dir}" -mount -type d -perm -0002 -exec chmod a+t {} \;
done

# 1.1.21 Disable Automounting
if [[ $(systemctl is-active --quiet autofs) == 0 ]]
then
  logRun "1.1.21" "systemctl disable autofs"
else
  log "INFO" "1.1.21: autofs already disabled."
fi

# CIS benchmarking 1.1.22 Disable Automounting (Scored)
logRun "1.1.22" "sudo apt-get --quiet --assume-yes purge --auto-remove autofs"

# CIS benchmarking 1.2 Configure Software Updates
# CIS benchmarking 1.2.1 Ensure package manager repositories are configured (Not Scored)
# CIS benchmarking 1.2.2 Ensure GPG keys are configured (Not Scored)

# CIS benchmarking 1.3 Configure sudo
# CIS benchmarking 1.3.1 Ensure sudo is installed (Scored)
logRun "1.3.1" "sudo apt-get --quiet --assume-yes install sudo"

# CIS benchmarking 1.3.2 Ensure sudo commands use pty (Scored)
if [[ -z $(grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*) ]]
then
  log "INFO" "1.3.2: echo 'Defaults use_pty' | sudo tee -a /etc/sudoers.d/69includeDefaults"
  echo 'Defaults use_pty' | sudo tee -a /etc/sudoers.d/69includeDefaults
  if [ ! -f /etc/sudoers.d/69includeDefaults ]
  then
    handleExit "1.3.2: Tried to write /etc/sudoers.d/69includeDefaults failed" "1"
  fi
fi

# CIS benchmarking 1.3.3 Ensure sudo log file exists (Scored)
if [[ -z $(sudo grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*) ]]
then
  log "INFO" "1.3.3: Ensure sudo log file exists"
  echo 'Defaults logfile="/var/log/sudo.log"' | sudo tee -a /etc/sudoers.d/69includeDefaults
  if [ ! -f /etc/sudoers.d/69includeDefaults ]
  then
     handleExit "1.3.3: Tried to write /etc/sudoers.d/69includeDefaults failed" "1"
  fi
fi

# CIS benchmarking 1.4 Filesystem Integrity Checking
# CIS benchmarking 1.4.1 Ensure AIDE is installed (Scored)
# first, install and setup sSMTP MTA for aide to supposedly use to alert on hackage: https://rianjs.net/2013/08/send-email-from-linux-server-using-gmail-and-ubuntu-two-factor-authentication
logRun "1.4.1" "sudo apt-get --quiet --assume-yes install ssmtp mailutils"

log "INFO" "1.4.1: Uncommenting and adding FromLineOverride=YES to /etc/ssmtp/ssmtp.conf"
sudo sed -i s/^#FromLineOverride=YES$/FromLineOverride=YES/ /etc/ssmtp/ssmtp.conf

log "INFO" "1.4.1: Adding mailhub=smtp.gmail.com to /etc/ssmtp/ssmtp.conf"
sudo sed -i s/^mailhub=.*$/mailhub=smtp.gmail.com:587/ /etc/ssmtp/ssmtp.conf

if [[ -z $(sudo grep '^AuthUser=' /etc/ssmtp/ssmtp.conf) ]]
then
  log "INFO" "1.4.1: Appending AuthUser to /etc/ssmtp/ssmtp.conf"
  echo "AuthUser=${GMAIL}" | sudo tee -a /etc/ssmtp/ssmtp.conf
else
  log "INFO" "1.4.1: Amending AuthUser=${GMAIL} in /etc/ssmtp/ssmtp.conf"
  sudo sed -i "s/^AuthUser=.*$/AuthUser=${GMAIL}/" /etc/ssmtp/ssmtp.conf
fi

if [[ -z $(sudo grep '^AuthPass=' /etc/ssmtp/ssmtp.conf) ]]
then
  log "INFO" "1.4.1: Appending AuthPass=<GMAILPASSWORD> to /etc/ssmtp/ssmtp.conf"
  echo "AuthPass=%%GMAILPASSWORD%%" | sudo tee -a /etc/ssmtp/ssmtp.conf
  sudo sed -i "s/AuthPass=%%GMAILPASSWORD%%/AuthPass=${GMAILPASSWORD}/" /etc/ssmtp/ssmtp.conf
else
  log "INFO" "1.4.1: Amending AuthPass in /etc/ssmtp/ssmtp.conf"
  sudo sed -i "s/^AuthPass=.*$/AuthPass=${GMAILPASSWORD}/" /etc/ssmtp/ssmtp.conf
fi

if [[ -z $(sudo grep '^UseSTARTTLS=' /etc/ssmtp/ssmtp.conf) ]]
then
  log "INFO" "1.4.1: Appending UseSTARTTLS=YES to /etc/ssmtp/ssmtp.conf"
  echo "UseSTARTTLS=YES" | sudo tee -a /etc/ssmtp/ssmtp.conf
else
  log "INFO" "1.4.1: Amending UseSTARTTLS in /etc/ssmtp/ssmtp.conf"
  sudo sed -i 's/^UseSTARTTLS=.*$/UseSTARTTLS=YES/' /etc/ssmtp/ssmtp.conf
fi
log "INFO" "1.4.1: Emailing ${GMAIL} with update to system build process"
log "WARN" "1.4.1: If this fails, check the email password first!"
echo "$(date +%Y-%m-%d::%H:%M): Email alerts will come to this address" | sudo mail -s "`hostname -f`: sSMTP MTA is up" ${GMAIL}

logRun "1.4.1" "sudo apt-get --quiet --assume-yes install aide"
logRun "1.4.1" "sudo aideinit -y -f --"
logRun "1.4.1" "sudo cp -a /var/lib/aide/aide.db /var/lib/aide/aide.db.`hostname`"
logRun "1.4.1" "sudo gzip -f /var/lib/aide/aide.db.`hostname`"

# CIS benchmarking 1.4.2 Ensure filesystem integrity is regularly checked (Scored)
log "INFO" "1.4.2: Running 0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check into crontab"
echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" | sudo crontab -

# CIS benchmarking 1.5 Secure Boot Settings
## use grub2-setpassword on another linux system to generate your own crypt and replace this one
# CIS benchmarking 1.5.1 Ensure permissions on bootloader config are configured (Scored)
## NOTE further update to the grub.cfg perms required as update-grub undoes the work.  See the end.
logRun "1.5.1" "sudo chown root:root /boot/grub/grub.cfg"
logRun "1.5.1" "sudo chmod og-rwx /boot/grub/grub.cfg"

log "INFO" "1.5.1: adding unrestricted to grub configuration"
sudo sed -i 's/--class gnu-linux --class gnu --class os/--class gnu-linux --class gnu --class os --unrestricted/' /etc/grub.d/10_linux

# CIS benchmarking 1.5.2 Ensure bootloader password is set (Scored)
log "INFO" "1.5.2: Running set password crypt on grub2 changes"
echo 'cat <<EOF' | sudo tee -a /etc/grub.d/69_bootSecurity
echo 'set superusers="root"' | sudo tee -a /etc/grub.d/69_bootSecurity
#echo "password_pbkdf2 root grub.pbkdf2.sha512.10000.1405BE64EEFF70D3979367597E913DD7A9ABA878020C555BC93DE87C7090077B584F95F89175343A627D11A69B4E413EB824F436335191BA7301100514DF9D0B.ACD09665412D8682AFC28067158EB2B4717B664766C3FAB45F911044815B10B097E594E594353FEF93D344BF61AE48D7B01863E4953685A77FCC05ECD3A29B66" | sudo tee -a /etc/grub.d/69_bootSecurity
echo "password_pbkdf2 root ${GRUB_PASSWORD}" | sudo tee -a /etc/grub.d/69_bootSecurity
echo 'EOF' | sudo tee -a /etc/grub.d/69_bootSecurity
logRun "1.5.2" "sudo chmod 0755 /etc/grub.d/69_bootSecurity"
logRun "1.5.1-1.5.2" "sudo update-grub"

# CIS benchmarking 1.5.3 Ensure authentication required for single user mode (Scored)
log "INFO" "1.5.3: Running echo root:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13 ; echo '') | sudo chpasswd"
echo "root:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13 ; echo '')" | sudo chpasswd

# CIS benchmarking 1.5.4 Ensure interactive boot is not enabled (Not Scored)

# CIS benchmarking 1.6 Additional Process Hardening
# CIS benchmarking 1.6.1 Ensure XD/NX support is enabled (Scored)
log "INFO" "1.6.1: Checking for NX/XD support"
if [[ -z $(sudo journalctl | grep 'protection: active') ]]
then
    handleExit "1.6.1: Error, NX/XD kernel support is absent, please fix the build." "1"
fi

# CIS benchmarking 1.6.2 Ensure address space layout randomization (ASLR) is enabled (Scored)
log "INFO" "1.6.2: Checking for address space layout randomisation (ASLR)"
if [[ $(sysctl kernel.randomize_va_space) ]]
then
  log "INFO" "1.6.2: Running kernel tweaks"
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
kernel.randomize_va_space = 2
EOF
fi
# no need to do sysctl -w now as done later

# CIS benchmarking 1.6.3 Ensure prelink is disabled (Scored)
logRun "1.6.3" "sudo apt-get --quiet --assume-yes purge prelink"

# CIS benchmarking 1.6.4 Ensure core dumps are restricted (Scored)
log "INFO" "1.6.4: Running echo '* hard core 0' | sudo tee -a /etc/security/limits.conf"
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf

log "INFO" "1.6.4: Running echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.conf"
echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.conf

log "INFO" "1.6.4: Running sudo echo '@reboot root sysctl -p' | sudo tee -a /etc/crontab"
echo '@reboot root sysctl -p' | sudo tee -a /etc/crontab

# CIS benchmarking 1.7 Mandatory Access Control
# CIS benchmarking 1.7.1 Configure AppArmor
# CIS benchmarking 1.7.1.1 Ensure AppArmor is installed (Scored)
logRun "1.7.1.1" "sudo apt-get --quiet --assume-yes install apparmor apparmor-utils"

# CIS benchmarking 1.7.1.2 Ensure AppArmor is enabled in bootloader configuration (Scored)
if [[ -n $(sudo grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1" | grep -v '/boot/memtest86+.bin') ]]
then
  log "INFO" "1.7.1.2: Ensure apparmor=1 is enabled in bootloader configuration"
  sudo sed -i 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 apparmor=1"/' /etc/default/grub
fi
if [[ -n $(sudo grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor" | grep -v '/boot/memtest86+.bin') ]]
then
  log "INFO" "1.7.1.2: Ensure security=apparmor is enabled in bootloader configuration"
  sudo sed -i 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 security=apparmor"/' /etc/default/grub
fi

# CIS benchmarking 1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Scored)
if [[ $(sudo apparmor_status | grep "profiles are in complain mode." | awk '{print $1}') -gt 0 ]]
then
  handleExit "1.7.1.3: Error, there are apparmor profiles in complain mode, please investigate the build." "1"
fi
if [[ $(sudo apparmor_status | grep "unconfined"  | awk '{print $1}') -gt 0 ]]
then
  handleExit "1.7.1.3: Error, there are unconfined apparmor profiles, please investigate the build." "1"
fi
## Note rsyslogd will be unconfined but have a profile set after this command.
## This should thus be run after the above checks for outliers.  As this build will result inevitably in the image going down,
## when it comes up, the rsyslogd enforcing profile will be applied which is a healthy approach.
#
# CIS benchmarking 1.7.1.4 Ensure all AppArmor Profiles are enforcing (Scored)
logRun "1.7.1.4" "sudo aa-enforce /etc/apparmor.d/*"

# CIS benchmarking 1.8 Warning Banners
# CIS benchmarking 1.8.1 Command Line Warning Banners
# CIS benchmarking 1.8.1.1 Ensure message of the day is configured properly (Scored)
## CIS advice is off here as Ubuntu has used PAM-based motd for several versions
log "INFO" "1.8.1.1: Writing /etc/motd"
cat << EOF | sudo tee -a /etc/motd
WARNING:  Unauthorized access to this system is forbidden and will be
prosecuted by law. By accessing this system, you agree that your actions
may be monitored if unauthorized usage is suspected.
EOF
logRun "1.8.1.1" "sudo rm -f /etc/update-motd.d/*"

# CIS benchmarking 1.8.1.2 Ensure local login warning banner is configured properly (Scored)
log "INFO" "1.8.1.2: Writing /etc/issue"
echo "Authorized users only. All activity may be monitored and reported." | sudo tee /etc/issue

# CIS benchmarking 1.8.1.3 Ensure remote login warning banner is configured properly (Scored)
log "INFO" "1.8.1.3: Writing /etc/issue.net"
echo "Authorized users only. All activity may be monitored and reported." | sudo tee /etc/issue.net

# CIS benchmarking 1.8.1.4 Ensure permissions on /etc/motd are configured (Scored)
logRun "1.8.1.4" "sudo chown root:root /etc/motd"
logRun "1.8.1.4" "sudo chmod 644 /etc/motd"

# CIS benchmarking 1.8.1.5 Ensure permissions on /etc/issue are configured (Scored)
logRun "1.8.1.5" "sudo chown root:root /etc/issue"
logRun "1.8.1.5" "sudo chmod 644 /etc/issue"

# CIS benchmarking 1.8.1.6 Ensure permissions on /etc/issue.net are configured (Scored)
logRun "1.8.1.6" "sudo chown root:root /etc/issue.net"
logRun "1.8.1.6" "sudo chmod 644 /etc/issue.net"

# CIS benchmarking 1.9 Ensure updates, patches, and additional security software are installed (Not Scored)
#
## all done

 #####  ###  #####         #####
#     #  #  #     #       #     #
#        #  #                   #
#        #   #####  #####  #####
#        #        #       #
#     #  #  #     #       #
 #####  ###  #####        #######

echo
echo "##################################################################################################"
echo
banner "CIS: 2"
echo "##################################################################################################"

# CIS benchmarking 2 Services
# CIS benchmarking 2.1 inetd Services
# CIS benchmarking 2.1.1 Ensure xinetd is not installed (Scored)
# CIS benchmarking 2.1.2 Ensure openbsd-inetd is not installed (Scored)
logRun "2.1.1-2.1.2" "sudo apt-get --quiet --assume-yes purge --auto-remove xinetd openbsd-inetd"

# CIS benchmarking 2.2 Special Purpose Services
# CIS benchmarking 2.2.1 Time Synchronization
# CIS benchmarking 2.2.1.1 Ensure time synchronization is in use (Scored)
logRun "2.2.1.1" "sudo apt-get --quiet --assume-yes install ntp"

# CIS benchmarking 2.2.1.2 Ensure systemd-timesyncd is configured (Not Scored)
# CIS benchmarking 2.2.1.3 Ensure chrony is configured (Scored) - not needed as NTP is used below
# CIS benchmarking 2.2.1.4 Ensure ntp is configured (Scored)
log "INFO" "2.2.1.4: sed to remove ntp default restrictions for re-addition later"
sudo sed -i 's/^restrict.*default.*$//' /etc/ntp.conf

log "INFO" "2.2.1.4: Running sed to remove ntp default restrictions for re-addition later"
echo "restrict -4 default kod nomodify notrap nopeer noquery" | sudo tee -a /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" | sudo tee -a /etc/ntp.conf
# ubuntu preseed uses the term pool instead of server in the configuration file for this service. correct:
log "INFO" "2.2.1.4: Fixing ntp configuration to use the word server instead of the word pool"
sudo sed -i 's/^pool/server/g' /etc/ntp.conf

if [[ $(grep "RUNASUSER=ntp" /etc/init.d/ntp) != "RUNASUSER=ntp" ]]
then
  log "WARN" "2.2.1.4: NTP not running as ntp user, setting to ntp user"
  sudo sed -i 's/^RUNASUSER=.*$/RUNASUSER=ntp/' /etc/init.d/ntp
fi

logRun "2.2.1.4" "sudo mkdir -pm 0755 /etc/sysconfig"
if [[ ! -f /etc/sysconfig/ntpd ]]
then
  log "INFO" "2.2.1.4: /etc/sysconfig/ntpd does not exist - adding config"
  echo 'NTPD_OPTIONS="-u ntp:ntp"' | sudo tee -a /etc/sysconfig/ntpd
elif [[ -z $(grep "^NTPD_OPTIONS" /etc/sysconfig/ntpd) ]]
then
  log "INFO" "2.2.1.4: Adding options to /etc/sysconfig/ntpd"
  echo 'NTPD_OPTIONS="-u ntp:ntp"' | sudo tee -a /etc/sysconfig/ntpd
fi

if [[ ! -f /etc/sysconfig/ntp ]]
then
  log "INFO" "2.2.1.4: /etc/sysconfig/ntp does not exist - adding config"
  echo 'NTPD_OPTIONS="-u ntp:ntp"' | sudo tee -a /etc/sysconfig/ntp
elif [[ -z $(grep "^NTPD_OPTIONS" /etc/sysconfig/ntp) ]]
then
  log "INFO" "2.2.1.4: Adding options to /etc/sysconfig/ntp"
  echo 'NTPD_OPTIONS="-u ntp:ntp"' | sudo tee -a /etc/sysconfig/ntp
fi

logRun "2.2.1.4" "sudo systemctl restart ntp"

# CIS benchmarking 2.2.2 Ensure X Window System is not installed (Scored)
# CIS benchmarking 2.2.3 Ensure Avahi Server is not enabled (Scored)
# CIS benchmarking 2.2.4 Ensure CUPS is not enabled (Scored)
# CIS benchmarking 2.2.5 Ensure DHCP Server is not enabled (Scored)
# CIS benchmarking 2.2.6 Ensure LDAP server is not enabled (Scored)
# CIS benchmarking 2.2.7 Ensure NFS and RPC are not enabled (Scored)
# CIS benchmarking 2.2.8 Ensure DNS Server is not enabled (Scored)
# CIS benchmarking 2.2.9 Ensure FTP Server is not enabled (Scored)
# CIS benchmarking 2.2.10 Ensure HTTP server is not enabled (Scored)
# CIS benchmarking 2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)
# CIS benchmarking 2.2.12 Ensure Samba is not enabled (Scored)
# CIS benchmarking 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
# CIS benchmarking 2.2.14 Ensure SNMP Server is not enabled (Scored)
# CIS benchmarking 2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored) - removed/replaced with sSMTP
# CIS benchmarking 2.2.16 Ensure rsync service is not enabled (Scored)
# CIS benchmarking 2.2.17 Ensure NIS Server is not enabled (Scored)
logRun "2.2.2-2.2.17" "sudo apt-get --quiet --assume-yes purge --auto-remove xserver-xorg*"
logRun "2.2.2-2.2.17" "sudo apt-get --quiet --assume-yes purge --auto-remove avahi-daemon cups dhcp3-server isc-dhcp-server slapd nfs-kernel-server nfs-common rpcbind bind9 vsftpd apache2 dovecot exim cyrus-imapd samba samba-common squid snmpd postfix rsync nis"

# CIS benchmarking 2.3 Service Clients
# CIS benchmarking 2.3.1 Ensure NIS Client is not installed (Scored) - already done in 2.2.17 above
# CIS benchmarking 2.3.2 Ensure rsh client is not installed (Scored)
# CIS benchmarking 2.3.3 Ensure talk client is not installed (Scored)
# CIS benchmarking 2.3.4 Ensure telnet client is not installed (Scored)
# CIS benchmarking 2.3.5 Ensure LDAP client is not installed (Scored)
logRun "2.3" "sudo apt-get --quiet --assume-yes purge --auto-remove rsh-client rsh-redone-client talk telnet ldap-utils"
#
## all done

 #####  ###  #####         #####
#     #  #  #     #       #     #
#        #  #                   #
#        #   #####  #####  #####
#        #        #             #
#     #  #  #     #       #     #
 #####  ###  #####         #####

echo
echo "##################################################################################################"
echo
banner "CIS: 3"
echo "##################################################################################################"

# CIS benchmarking 3 Network Configuration
# CIS benchmarking 3.1 Network Parameters (Host Only)
# CIS benchmarking 3.1.1 Ensure IP forwarding is disabled (Scored)
# CIS benchmarking 3.1.2 Ensure packet redirect sending is disabled (Scored)
# CIS benchmarking 3.2 Network Parameters (Host and Router)
# CIS benchmarking 3.2.1 Ensure source routed packets are not accepted (Scored)
# CIS benchmarking 3.2.2 Ensure ICMP redirects are not accepted (Scored)
# CIS benchmarking 3.2.3 Ensure secure ICMP redirects are not accepted (Scored) - Also see https://bugs.launchpad.net/ubuntu/+source/procps/+bug/50093
# CIS benchmarking 3.2.4 Ensure suspicious packets are logged (Scored)
# CIS benchmarking 3.2.5 Ensure broadcast ICMP requests are ignored (Scored)
# CIS benchmarking 3.2.6 Ensure bogus ICMP responses are ignored (Scored)
# CIS benchmarking 3.2.7 Ensure Reverse Path Filtering is enabled (Scored)
# CIS benchmarking 3.2.8 Ensure TCP SYN Cookies is enabled (Scored)
# CIS benchmarking 3.2.9 Ensure IPv6 router advertisements are not accepted (Scored)
log "INFO" "3: Running kernel tweaks"
cat << EOF | sudo tee -a /etc/sysctl.conf

## kernel tweaks from build process
#
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
#
## end kernel tweaks from build process
EOF

## apply
#
logRun "3.2.1" "sysctl -w net.ipv4.route.flush=1"
logRun "3.2.1" "sysctl -w net.ipv6.route.flush=1"

## engage
#
log "INFO" "3: Running @reboot sleep 60; sudo /sbin/sysctl -p into crontab: https://bugs.launchpad.net/ubuntu/+source/procps/+bug/50093"
log "INFO" "3: NOTE adding sleep 60 to get round cron implementation bug: https://unix.stackexchange.com/questions/109804/crontabs-reboot-only-works-for-root/109805#109805"
echo "@reboot sleep 60; sudo /sbin/sysctl -p" | sudo crontab -

# CIS benchmarking 3.3 TCP Wrappers
# CIS benchmarking 3.3.1 Ensure TCP Wrappers is installed (Not Scored)
logRun "3.3.1" "sudo apt-get --quiet --assume-yes install tcpd"

# CIS benchmarking 3.3.2 Ensure /etc/hosts.allow is configured (Scored) - We cannot know ahead of time which cloud subnet this host will be part of
logRun "3.3.2" "test -f /etc/hosts.allow"
# CIS benchmarking 3.3.3 Ensure /etc/hosts.deny is configured (Scored)
logRun "3.3.3" "test -f /etc/hosts.deny"
log "INFO" "3.3.3: Adding commented ALL: ALL to /etc/hosts.deny - See https://github.com/ml4/packer-base-ubuntu for more information"
echo '# Ubuntu 18 CIS v2.0.1 item3.3.3 # ALL: ALL' | sudo tee -a /etc/hosts.deny

# CIS benchmarking 3.3.4 Ensure permissions on /etc/hosts.allow are configured (Scored)
logRun "3.3.4" "sudo chown root:root /etc/hosts.allow"
logRun "3.3.4" "sudo chmod 644 /etc/hosts.allow"
# CIS benchmarking 3.3.5 Ensure permissions on /etc/hosts.deny are configured (Scored)
logRun "3.3.5" "sudo chown root:root /etc/hosts.deny"
logRun "3.3.5" "sudo chmod 644 /etc/hosts.deny"

# CIS benchmarking 3.4 Uncommon Network Protocols
# CIS benchmarking 3.4.1 Ensure DCCP is disabled (Scored)
# CIS benchmarking 3.4.2 Ensure SCTP is disabled (Scored)
# CIS benchmarking 3.4.3 Ensure RDS is disabled (Scored)
# CIS benchmarking 3.4.4 Ensure TIPC is disabled (Scored)
#
CISCONFIG=/etc/modprobe.d/CIS.conf
for fs in dccp sctp rds tipc
do
  log "INFO" "3.4: Disabling ${fs}"
  echo "install ${fs} /bin/true" | sudo tee -a ${CISCONFIG}
  if [[ $(lsmod | grep ${fs}) ]]
  then
    log "INFO" "3.4: Removing FS ${fs}"
    sudo rmmod ${fs}
  fi
done

# CIS benchmarking 3.5 Firewall Configuration
# CIS benchmarking 3.5.1 Ensure Firewall software is installed
# CIS benchmarking 3.5.1.1 Ensure a Firewall package is installed (Scored)
log "INFO" "3.5.1: Installing iptables"
logRun "3.5.1" "sudo apt-get --quiet --assume-yes install iptables"

# CIS benchmarking 3.5.2 Configure UncomplicatedFirewall
# CIS benchmarking 3.5.2.1 Ensure ufw service is enabled (Scored)
logRun "3.5.2.1" "sudo ufw --force enable"
# next two are to allow completion of the scripting below and allow incoming ssh
logRun "3.5.2.1" "sudo ufw allow proto tcp from any to any port 22"
logRun "3.5.2.1" "sudo ufw allow out to any"

# CIS benchmarking 3.5.2.2 Ensure default deny firewall policy (Scored) - even though iptables is installed, CIS-CAT still wants to see this
logRun "3.5.2.2" "sudo ufw default deny incoming"
logRun "3.5.2.2" "sudo ufw default deny outgoing"
logRun "3.5.2.2" "sudo ufw default deny routed"

# CIS benchmarking 3.5.2.3 Ensure loopback traffic is configured (Scored) - even though iptables is installed, CIS-CAT still wants to see this
logRun "3.5.2.3" "sudo ufw allow in on lo"
logRun "3.5.2.3" "sudo ufw deny in from 127.0.0.0/8"
logRun "3.5.2.3" "sudo ufw deny in from ::1"

# CIS benchmarking 3.5.2.4 Ensure outbound connections are configured (Not Scored)
# CIS benchmarking 3.5.2.5 Ensure firewall rules exist for all open ports (Not Scored)
# CIS benchmarking 3.5.3 Configure nftables
# CIS benchmarking 3.5.3.1 Ensure iptables are flushed (Not Scored)
# CIS benchmarking 3.5.3.2 Ensure a table exists (Scored)
# CIS benchmarking 3.5.3.3 Ensure base chains exist (Scored)
# CIS benchmarking 3.5.3.4 Ensure loopback traffic is configured (Scored)
# CIS benchmarking 3.5.3.5 Ensure outbound and established connections are configured (Not Scored)
# CIS benchmarking 3.5.3.6 Ensure default deny firewall policy (Scored)
# CIS benchmarking 3.5.3.7 Ensure nftables service is enabled (Scored)
# CIS benchmarking 3.5.3.8 Ensure nftables rules are permanent (Scored)
# Using iptables over other firewall software - for now. Move to nftables in time.
# CIS benchmarking 3.5.4 Configure iptables
# CIS benchmarking 3.5.4.1 Configure IPv4 iptables
# Flush IPtables rules
logRun "3.5.4" "sudo iptables -F"
# CIS benchmarking 3.5.4.1.1 Ensure default deny firewall policy (Scored)
# Ensure default deny firewall policy
logRun "3.5.4" "sudo iptables -P INPUT DROP"
logRun "3.5.4" "sudo iptables -P OUTPUT DROP"
logRun "3.5.4" "sudo iptables -P FORWARD DROP"
# CIS benchmarking 3.5.4.1.2 Ensure loopback traffic is configured (Scored)
# Ensure loopback traffic is configured
logRun "3.5.4" "sudo iptables -A INPUT -i lo -j ACCEPT "
logRun "3.5.4" "sudo iptables -A OUTPUT -o lo -j ACCEPT "
logRun "3.5.4" "sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP"
# CIS benchmarking 3.5.4.1.3 Ensure outbound and established connections are configured (Not Scored)
# Ensure outbound and established connections are configured
logRun "3.5.4" "sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT "
logRun "3.5.4" "sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT "
logRun "3.5.4" "sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT "
logRun "3.5.4" "sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT "
logRun "3.5.4" "sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT"
logRun "3.5.4" "sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"
# CIS benchmarking 3.5.4.1.4 Ensure firewall rules exist for all open ports (Scored)
# Open inbound ssh(tcp port 22) connections
logRun "3.5.4.1.4" "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT"

# ipv6 FW not going in just yet due to poor support from public cloud vendors. COMMENTING OUT UNLESS CISCAT BARFS
# CIS benchmarking 3.5.4.2 Configure IPv6 ip6tables
# Flush IPtables rules
# logRun "sudo ip6tables -F"
# # CIS benchmarking 3.5.4.2.1 Ensure IPv6 default deny firewall policy (Scored)
# # Ensure default deny firewall policy
# logRun "sudo ip6tables -P INPUT DROP"
# logRun "sudo ip6tables -P OUTPUT DROP"
# logRun "sudo ip6tables -P FORWARD DROP"
# # CIS benchmarking 3.5.4.2.2 Ensure IPv6 loopback traffic is configured (Scored)
# # Ensure loopback traffic is configured
# logRun "sudo ip6tables -A INPUT -i lo -j ACCEPT "
# logRun "sudo ip6tables -A OUTPUT -o lo -j ACCEPT "
# logRun "sudo ip6tables -A INPUT -s ::1 -j DROP"
# # CIS benchmarking 3.5.4.2.3 Ensure IPv6 outbound and established connections are configured (Not Scored)
# logRun "sudo ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT "
# logRun "sudo ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT "
# logRun "sudo ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT "
# logRun "sudo ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT "
# logRun "sudo ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT"
# logRun "sudo ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"
# # CIS benchmarking 3.5.4.2.4 Ensure IPv6 firewall rules exist for all open ports (Not Scored)
# # Open inbound ssh(tcp port 22) connections
# logRun "sudo ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT"

# CIS benchmarking 3.6 Ensure wireless interfaces are disabled (Scored)
logRun "3.6" "sudo apt-get --quiet --assume-yes install network-manager"
logRun "3.6" "sudo /etc/init.d/network-manager start"
logRun "3.6" "sudo nmcli radio all off"
# logRun "3.6" "sudo apt-get --quiet --assume-yes purge network-manager"

# CIS benchmarking 3.7 Disable IPv6 (Not Scored) - See 4.1.1.4 below for disablement
#
## all done

 #####  ###  #####        #
#     #  #  #     #       #    #
#        #  #             #    #
#        #   #####  ##### #    #
#        #        #       #######
#     #  #  #     #            #
 #####  ###  #####             #

echo
echo "##################################################################################################"
echo
banner "CIS: 4"
echo "##################################################################################################"

# CIS benchmarking 4 Logging and Auditing
## NOTE: This implementation pertains to root-only log access, not third-party group addition.
## The tenets are to maintain maximum security, and expectation of the machine shipping all logs to a
## cloud-based central logging facility.
# CIS benchmarking 4.1 Configure System Accounting (auditd)
# CIS benchmarking 4.1.1 Ensure auditing is enabled
# CIS benchmarking 4.1.1.1 Ensure auditd is installed (Scored)
logRun "4.1.1.1" "sudo apt-get --quiet --assume-yes install auditd audispd-plugins"

# CIS benchmarking 4.1.1.2 Ensure auditd service is enabled (Scored)
logRun "4.1.1.2" "sudo systemctl --now enable auditd"

# CIS benchmarking 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored)
# CIS benchmarking 4.1.1.4 Ensure audit_backlog_limit is sufficient (Scored)
log "INFO" "4.1.1.4: Adding audit lines to Grub config"
sudo sed -i 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 audit=1 ipv6.disable=1 audit_backlog_limit=8192"/' /etc/default/grub
logRun "4.1.1.4" "sudo update-grub"

# CIS benchmarking 4.1.2 Configure Data Retention
logRun "4.1.2" "sudo systemctl enable auditd"
logRun "4.1.2" "sudo systemctl start auditd"

# CIS benchmarking 4.1.2.1 Ensure audit log storage size is configured (Scored)
# CIS benchmarking 4.1.2.2 Ensure audit logs are not automatically deleted (Scored)
# CIS benchmarking 4.1.2.3 Ensure system is disabled when audit logs are full (Scored)
# Plus a load of other changes I liked from cis 1.0.0
if [[ $(sudo test -f /etc/audit/auditd.conf) ]]
then
  handleExit "4.1.2.3: /etc/audit/auditd.conf does not exist - previous step should have installed it." "1"
fi
cat << EOF | sudo tee /etc/audit/auditd.conf
# Configure auditd
# NOTE: non-yorn values in lower case are non-defaults added by the build
action_mail_acct = ${GMAIL}
admin_space_left = 50
admin_space_left_action = halt
disk_error_action = syslog
disk_full_action = rotate
dispatcher = /sbin/audispd
disp_qos = lossy
distribute_network = no
enable_krb5 = no
flush = none
freq = 50
##krb5_key_file = /etc/audit/audit.key
krb5_principal = auditd
local_events = yes
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = root
max_log_file = 100
max_log_file_action = keep_logs
name_format = user
name = %%PHOENIX%%
# num_logs = 5  # CIS=max_log_file_action = keep_logs, so I set space_left_action = rotate
priority_boost = 4
space_left = 100
space_left_action = rotate
tcp_client_max_idle = 0
##tcp_client_ports = 1024-65535
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
use_libwrap = yes
verify_email = yes
write_logs = yes
EOF

# CIS benchmarking 4.1.3 Ensure events that modify date and time information are collected (Scored)
log "INFO" "4.1.3: Adding date modify actions to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.3 Ensure events that modify date and time information are collected (Scored)
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

# CIS benchmarking 4.1.4 Ensure events that modify user/group information are collected (Scored)
log "INFO" "4.1.4: Adding user/group modify actions to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.4 Ensure events that modify user/group information are collected (Scored)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF

# CIS benchmarking 4.1.5 Ensure events that modify the system's network environment are collected (Scored)
log "INFO" "4.1.5: Adding network modify actions to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.5 Ensure events that modify the system's network environment are collected (Scored)
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
EOF

# CIS benchmarking 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
log "INFO" "4.1.6: Adding MAC modify actions to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF

# CIS benchmarking 4.1.7 Ensure login and logout events are collected (Scored)
log "INFO" "4.1.7: Adding login/out modify actions to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.7 Ensure login and logout events are collected (Scored)
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
EOF

# CIS benchmarking 4.1.8 Ensure session initiation information is collected (Scored)
log "INFO" "4.1.8: Adding session initiation information collection to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.8 Ensure session initiation information is collected (Scored)
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF

# CIS benchmarking 4.1.9 Ensure discretionary access control permission modification events are collected (Scored)
log "INFO" "4.1.9: Adding discretionary access control rules to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.9 Ensure discretionary access control permission modification events are collected (Scored)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF

# CIS benchmarking 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
log "INFO" "4.1.10: Adding unauthorized file access rules to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF

# CIS benchmarking 4.1.11 Ensure use of privileged commands is collected (Scored)
log "INFO" "4.1.11: Adding privileged command access rules to audit.rules"
echo -e "\n# CIS benchmarking 4.1.11 Ensure use of privileged commands is collected (Scored)" | sudo tee -a /etc/audit/rules.d/audit.rules
sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.12 Ensure successful file system mounts are collected (Scored)
log "INFO" "4.1.12: Adding successful file system mounts to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.12 Ensure successful file system mounts are collected (Scored)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOF

# CIS benchmarking 4.1.13 Ensure file deletion events by users are collected (Scored)
log "INFO" "4.1.13: Adding file deletion events to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.13 Ensure file deletion events by users are collected (Scored)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF

# CIS benchmarking 4.1.14 Ensure changes to system administration scope (sudoers) is collected (Scored)
log "INFO" "4.1.14: Adding changes to sudoers to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.14 Ensure changes to system administration scope (sudoers) is collected (Scored)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

# CIS benchmarking 4.1.15 Ensure system administrator actions (sudolog) are collected (Scored)
log "INFO" "4.1.15: Adding system administrator actions to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.15 Ensure system administrator actions (sudolog) are collected (Scored)
-w /var/log/sudo.log -p wa -k actions
EOF

# CIS benchmarking 4.1.16 Ensure kernel module loading and unloading is collected (Scored)
log "INFO" "4.1.16: Adding kernel module un/loading to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.16 Ensure kernel module loading and unloading is collected (Scored)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

# CIS benchmarking 4.1.17 Ensure the audit configuration is immutable (Scored)
log "INFO" "4.1.17: Adding audit configuration immutability to audit.rules"
cat << 'EOF' | sudo tee -a /etc/audit/rules.d/audit.rules

# CIS benchmarking 4.1.17 Ensure the audit configuration is immutable (Scored)
-e 2
EOF

# Now reload the audit system
logRun "4.1.17" "sudo apt-get --quiet --assume-yes install policykit-1"
logRun "4.1.17" "sudo systemctl reload auditd"

# CIS benchmarking 4.2 Configure Logging
# CIS benchmarking 4.2.1 Configure rsyslog
# CIS benchmarking 4.2.1.1 Ensure rsyslog is installed (Scored)
logRun "4.2.1.1" "sudo apt-get --quiet --assume-yes install rsyslog"

# CIS benchmarking 4.2.1.2 Ensure rsyslog Service is enabled (Scored)
logRun "4.2.1.2" "sudo systemctl --now enable rsyslog"

# CIS benchmarking 4.2.1.3 Ensure logging is configured (Not Scored)
# CIS benchmarking 4.2.1.4 Ensure rsyslog default file permissions configured (Scored)
# CIS benchmarking 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored)
logRun "4.2.1.5" "sudo touch /etc/rsyslog.d/69-remote.conf"
log "INFO" "4.2.1.5: Configuring rsyslog to be configured to send logs to a remote log host"
cat << 'EOF' | sudo tee -a /etc/rsyslog.d/69-remote.conf
# CIS benchmarking 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored)
*.* @@${REMOTELOGHOST}
EOF
logRun "4.2.1.4-5" "sudo pkill -HUP rsyslogd"

# CIS benchmarking 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)
# CIS benchmarking 4.2.2 Configure journald
# CIS benchmarking 4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)
if [[ -z $(sudo grep -E -i "^\s*ForwardToSyslog=yes" /etc/systemd/journald.conf) ]]
then
  if [[ -n $(sudo grep -E -i "^#ForwardToSyslog=yes" /etc/systemd/journald.conf) ]]
  then
    log "INFO" "4.2.2.1: Making journald write to syslog"
    sudo sed -i 's/^#ForwardToSyslog=yes/ForwardToSyslog=yes/' /etc/systemd/journald.conf
  else
    echo "ForwardToSyslog=yes" | sudo tee -a /etc/systemd/journald.conf
  fi
else
  log "INFO" "4.2.2.1: Journald is already writing to syslog"
fi

# CIS benchmarking 4.2.2.2 Ensure journald is configured to compress large log files (Scored)
if [[ -z $(sudo grep -E -i "^\s*Compress=yes" /etc/systemd/journald.conf) ]]
then
  if [[ -n $(sudo grep -E -i "^#Compress=yes" /etc/systemd/journald.conf) ]]
  then
    log "INFO" "4.2.2.2: Making journald configured to compress large log files"
    sudo sed -i 's/^#Compress=yes/Compress=yes/' /etc/systemd/journald.conf
  else
    echo "Compress=yes" | sudo tee -a /etc/systemd/journald.conf
  fi
else
  log "INFO" "4.2.2.2: Journald is already writing to syslog"
fi

# CIS benchmarking 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)
if [[ -z $(sudo grep -E -i "^\s*Storage=persistent" /etc/systemd/journald.conf) ]]
then
  if [[ -n $(sudo grep -E -i "^#Storage=persistent" /etc/systemd/journald.conf) ]]
  then
    log "INFO" "4.2.2.3: Making journald configured to write logfiles to persistent disk"
    sudo sed -i 's/^#Storage=persistent/Storage=persistent/' /etc/systemd/journald.conf
  else
    echo "Storage=persistent" | sudo tee -a /etc/systemd/journald.conf
  fi
else
  log "INFO" "4.2.2.3: Journald is already writing to syslog"
fi

# CIS benchmarking 4.2.3 Ensure permissions on all logfiles are configured (Scored)
log "INFO" "4.2.3: sudo find /var/log -type f -exec sudo chmod g-wx,o-rwx {} + -o -type d -exec sudo chmod g-w,o-rwx {} +"
sudo find /var/log -type f -exec sudo chmod g-wx,o-rwx "{}" + -o -type d -exec sudo chmod g-w,o-rwx "{}" +
## See base-init.sh for this being made available as a systemd unit for boot-time refresh of permissions

# CIS benchmarking 4.3 Ensure logrotate is configured (Not Scored)
#
## all done

 #####  ###  #####        #######
#     #  #  #     #       #
#        #  #             #
#        #   #####  ##### ######
#        #        #             #
#     #  #  #     #       #     #
 #####  ###  #####         #####

echo
echo "##################################################################################################"
echo
banner "CIS: 5"
echo "##################################################################################################"

# CIS benchmarking 5 Access, Authentication and Authorization
# CIS benchmarking 5.1 Configure cron
# CIS benchmarking 5.1.1 Ensure cron daemon is enabled (Scored)
logRun "5.1.1" "sudo systemctl --now enable cron"

# CIS benchmarking 5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
logRun "5.1.2" "sudo chown root:root /etc/crontab"
logRun "5.1.2" "sudo chmod og-rwx /etc/crontab"

# CIS benchmarking 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)
logRun "5.1.3" "sudo chown root:root /etc/cron.hourly"
logRun "5.1.3" "sudo chmod og-rwx /etc/cron.hourly"

# CIS benchmarking 5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)
logRun "5.1.4" "sudo chown root:root /etc/cron.daily"
logRun "5.1.4" "sudo chmod og-rwx /etc/cron.daily"

# CIS benchmarking 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)
logRun "5.1.5" "sudo chown root:root /etc/cron.weekly"
logRun "5.1.5" "sudo chmod og-rwx /etc/cron.weekly"

# CIS benchmarking 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)
logRun "5.1.6" "sudo chown root:root /etc/cron.monthly"
logRun "5.1.6" "sudo chmod og-rwx /etc/cron.monthly"

# CIS benchmarking 5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)
logRun "5.1.7" "sudo chown root:root /etc/cron.d"
logRun "5.1.7" "sudo chmod og-rwx /etc/cron.d"

# CIS benchmarking 5.1.8 Ensure at/cron is restricted to authorized users (Scored)
logRun "5.1.8" "sudo rm -f /etc/cron.deny 2>/dev/null"
logRun "5.1.8" "sudo rm -f /etc/at.deny 2>/dev/null"
logRun "5.1.8" "sudo touch /etc/cron.allow"
logRun "5.1.8" "sudo touch /etc/at.allow"
logRun "5.1.8" "sudo chmod og-rwx /etc/cron.allow"
logRun "5.1.8" "sudo chmod og-rwx /etc/at.allow"
logRun "5.1.8" "sudo chown root:root /etc/cron.allow"

# CIS benchmarking 5.2 SSH Server Configuration
# CIS benchmarking 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
logRun "5.2.1" "sudo chown root:root /etc/ssh/sshd_config"
logRun "5.2.1" "sudo chmod og-rwx /etc/ssh/sshd_config"

# CIS benchmarking 5.2.2 Ensure permissions on SSH private host key files are configured (Scored)
log "INFO" "5.2.2: Running sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;"
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
log "INFO" "5.2.2: Running sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;"
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;

# CIS benchmarking 5.2.3 Ensure permissions on SSH public host key files are configured (Scored)
log "INFO" "5.2.3: Running sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;"
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
log "INFO" "5.2.3: Running sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;"
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

# CIS benchmarking 5.2.4 Ensure SSH Protocol is not set to 1 (Scored)
# CIS benchmarking 5.2.5 Ensure SSH LogLevel is appropriate (Scored)
# CIS benchmarking 5.2.6 Ensure SSH X11 forwarding is disabled (Scored)
# CIS benchmarking 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
# CIS benchmarking 5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
# CIS benchmarking 5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored)
# CIS benchmarking 5.2.10 Ensure SSH root login is disabled (Scored)
# CIS benchmarking 5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored)
# CIS benchmarking 5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored)
# CIS benchmarking 5.2.13 Ensure only strong Ciphers are used (Scored)
# CIS benchmarking 5.2.14 Ensure only approved MAC algorithms are used (Scored)
# CIS benchmarking 5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)
# CIS benchmarking 5.2.16 Ensure SSH Idle Timeout Interval is configured (Scored)
# CIS benchmarking 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
# CIS benchmarking 5.2.18 Ensure SSH access is limited (Scored)
# CIS benchmarking 5.2.19 Ensure SSH warning banner is configured (Scored) - see second section
# CIS benchmarking 5.2.20 Ensure SSH PAM is enabled (Scored)
# CIS benchmarking 5.2.21 Ensure SSH AllowTcpForwarding is disabled (Scored)
# CIS benchmarking 5.2.22 Ensure SSH MaxStartups is configured (Scored)
# CIS benchmarking 5.2.23 Ensure SSH MaxSessions is set to 4 or less (Scored)
for entry in 'Protocol 2' 'LogLevel INFO' 'X11Forwarding no' 'MaxAuthTries 4' 'IgnoreRhosts yes' 'HostbasedAuthentication no' 'PermitRootLogin no' 'PermitEmptyPasswords no' 'PermitUserEnvironment no' 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr' 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' 'ClientAliveInterval 300' 'ClientAliveCountMax 0' 'LoginGraceTime 60' 'AllowUsers ubuntu' 'UsePAM yes' 'AllowTcpForwarding no' 'maxstartups 10:30:60' 'MaxSessions 4'
do
  key=$(echo ${entry} | cut -f1 -d' ')
  val=$(echo ${entry} | cut -f2 -d' ')

  if [[ $(sudo grep -e ^${key} /etc/ssh/sshd_config) ]]
  then
    log "INFO" "5.2.x: Setting sshd ${key} to ${val}"
    sudo sed -i "s/^${key}.*$/${key} ${val}/" /etc/ssh/sshd_config
  elif [[ $(sudo grep -e "^#${KEY} /etc/ssh/sshd_config") ]]
  then
    log "INFO" "5.2.x: Uncommenting and setting sshd ${key} to ${val}"
    sudo sed -i "s/^#${key}.*$/${key} ${val}/" /etc/ssh/sshd_config
  else
    log "INFO" "Appending ${key} ${val} to /etc/ssh/sshd_config"
    echo "${key} ${val}" | sudo tee -a /etc/ssh/sshd_config
  fi
done

## The amount of additional conditionals for slashes means it's easier to make a separate case for sshd_Config Banner /etc/issue.net
# CIS benchmarking 5.2.15 Ensure SSH warning banner is configured (Scored)
if [[ $(sudo grep -e ^Banner /etc/issue.net /etc/ssh/sshd_config) ]]
then
  log "INFO" "5.2.15: Setting sshd Banner /etc/issue.net"
  sudo sed -i "s/^Banner.*$/Banner \/etc\/issue.net/" /etc/ssh/sshd_config
elif [[ $(sudo grep -e "^#${KEY} /etc/ssh/sshd_config") ]]
then
  log "INFO" "5.2.15: Uncommenting and setting sshd Banner /etc/issue.net"
  sudo sed -i "s/^#Banner.*$/Banner \/etc\/issue.net/" /etc/ssh/sshd_config
else
  log "INFO" "5.2.15: Appending 'Banner /etc/issue.net' to /etc/ssh/sshd_config"
  echo "Banner /etc/issue.net" | sudo tee -a /etc/ssh/sshd_config
fi

# CIS benchmarking 5.3 Configure PAM
# CIS benchmarking 5.3.1 Ensure password creation requirements are configured (Scored)
# Settings in /etc/security/pwquality.conf must use spaces around the = symbol
logRun "5.3.1" "sudo apt-get --quiet --assume-yes install libpam-pwquality"
if [[ $(grep -e "^password.*requisite.*pam_pwquality.so.*retry=" /etc/pam.d/common-password) ]]
then
  log "INFO" "5.3.1: Setting /etc/pam.d/common-password retry=3"
  sudo sed -i "s/^password.*requisite.*pam_pwquality.so.*retry=.*$/password requisite pam_pwquality.so retry=3/" /etc/pam.d/common-password
elif [[ $(grep -e '^#.*password.*requisite.*pam_pwquality.so.*retry=' /etc/pam.d/common-password) ]]
then
  log "INFO" "5.3.1: sed password requisite pam_pwquality in /etc/pam.d/common-password"
  sudo sed -i 's/^#.*password.*requisite.*pam_pwquality.so.*retry=/password requisite pam_pwquality.so retry=3/' /etc/pam.d/common-password
else
  log "INFO" "5.3.1: Appending '/etc/pam.d/common-password retry=3' to /etc/pam.d/common-password"
  echo "password requisite pam_pwquality.so retry=3" | sudo tee -a /etc/pam.d/common-password
fi

for entry in 'minlen = 14' 'dcredit = -1' 'ucredit = -1' 'ocredit = -1' 'lcredit = -1'
do
  key=$(echo ${entry} | cut -f1 -d' ')
  val=$(echo ${entry} | cut -f3 -d' ')

  if [[ $(sudo grep -e ^${key} /etc/security/pwquality.conf) ]]
  then
    log "INFO" "5.3.1: Setting pwquality ${key} to ${val}"
    sudo sed -i "s/^${key}.*$/${key} = ${val}/" /etc/security/pwquality.conf
  elif [[ $(sudo grep -e ^"# ${key}" /etc/security/pwquality.conf) ]]
  then
    log "INFO" "5.3.1: Uncommenting and setting pwquality ${key} to ${val}"
    sudo sed -i "s/^# ${key} = .*$/${key} = ${val}/" /etc/security/pwquality.conf
  else
    log "INFO" "5.3.1: Appending /etc/security/pwquality.conf with ${key} ${val}"
    echo "${key} = ${val}" | sudo tee -a /etc/security/pwquality.conf
  fi
done

# CIS benchmarking 5.3.2 Ensure lockout for failed password attempts is configured (Scored)
if [[ $(sudo grep -e "^auth.*required.*pam_tally2.so.*" /etc/pam.d/common-auth) ]]
then
  log "INFO" "5.3.2: Setting /etc/pam.d/common-auth user lockout"
  sudo sed -i "s/^auth.*required.*pam_tally2.so.*/auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900/" /etc/pam.d/common-auth
elif [[ $(grep -e '^#auth.*required.*pam_tally2.so.*' /etc/pam.d/common-auth) ]]
then
  log "INFO" "5.3.2: Uncommenting /etc/pam.d/common-auth user lockout"
  sudo sed -i 's/^#auth.*required.*pam_tally2.so.*/auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900/' /etc/pam.d/common-auth
else
  log "INFO" "5.3.2: Appending 'auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' to /etc/pam.d/common-auth"
  echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
fi

if [[ $(sudo grep -e "^account\s*requisite" /etc/pam.d/common-account) ]]
then
  log "INFO" "5.3.2: Setting /etc/pam.d/common-account user lockout"
  sudo sed -i "s/^account\s*requisite\s*.*$/account requisite pam_deny.so/" /etc/pam.d/common-account
elif [[ $(grep -e '^#account\s*requisite\s*.*' /etc/pam.d/common-account) ]]
then
  log "INFO" "5.3.2: Uncommenting /etc/pam.d/common-account user lockout"
  sudo sed -i "s/^#account\s*requisite\s*.*$/account requisite pam_deny.so/" /etc/pam.d/common-account
else
  log "INFO" "5.3.2: Appending 'account requisite pam_deny.so' to /etc/pam.d/common-account"
  echo "account requisite pam_deny.so" | sudo tee -a /etc/pam.d/common-account
fi

if [[ $(sudo grep -e "^account\s*required" /etc/pam.d/common-account) ]]
then
  log "INFO" "5.3.2: Setting /etc/pam.d/common-account user lockout"
  sudo sed -i "s/^account\s*required\s*.*$/account required pam_tally2.so/" /etc/pam.d/common-account
elif [[ $(grep -e '^#account\s*required\s*.*' /etc/pam.d/common-account) ]]
then
  log "INFO" "5.3.2: Uncommenting /etc/pam.d/common-account user lockout"
  sudo sed -i "s/^#account\s*required\s*.*$/account required  /" /etc/pam.d/common-account
else
  log "INFO" "5.3.2: Appending 'account required pam_tally2.so' to /etc/pam.d/common-account"
  echo "account required pam_tally2.so" | sudo tee -a /etc/pam.d/common-account
fi

# CIS benchmarking 5.3.3 Ensure password reuse is limited (Scored)
if [[ $(sudo grep -e "^password.*required.*pam_pwhistory.so.*remember=" /etc/pam.d/common-password) ]]
then
  log "INFO" "5.3.3: Setting /etc/pam.d/common-password password required pam_pwhistory.so remember=5"
  sudo sed -i "s/^password.*required.*pam_pwhistory.so.*remember=.*$/password required pam_pwhistory.so remember=5/" /etc/pam.d/common-password
elif [[ $(sudo grep -e '^#password.*required.*pam_pwhistory.so.*remember=.*' /etc/pam.d/common-password) ]]
then
  log "INFO" "5.3.3: Uncommenting /etc/pam.d/common-password password required pam_pwhistory.so remember=5"
  sudo sed -i 's/^#.*password.*required.*pam_pwhistory.so.*remember=/password required pam_pwhistory.so remember=5/' /etc/pam.d/common-password
else
  log "INFO" "5.3.3: Appending '/etc/pam.d/common-password remember=5' to /etc/pam.d/common-password"
  echo "password required pam_pwhistory.so remember=5" | sudo tee -a /etc/pam.d/common-password
fi

# CIS benchmarking 5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)
if [[ $(sudo egrep -e '^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512' /etc/pam.d/common-password) ]]
then
  log "INFO" "5.3.4: Password hashing algorithm already at sha512"
else
  log "WARN" "5.3.4: PAM pam_unix.so not set to sufficiently strong algorithm: resetting to sha512"
  sudo sed -i 's/^password.*pam_unix.so.*/password  [success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512/' /etc/pam.d/common-password
fi

# CIS benchmarking 5.4 User Accounts and Environment
# CIS benchmarking 5.4.1 Set Shadow Password Suite Parameters
# CIS benchmarking 5.4.1.1 Ensure password expiration is 365 days or less (Scored)
log "INFO" "5.4.1.1: Setting PASS_MAX_DAYS to 90 in /etc/login.defs"
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
log "INFO" "5.4.1.1: Running sudo cat /etc/shadow | cut -d: -f1 | while read entry; do chage --maxdays 90 ${entry}; done"
sudo cat /etc/shadow | cut -d: -f1 | while read entry
do
  chage --maxdays 90 ${entry}
done

# CIS benchmarking 5.4.1.2 Ensure minimum days between password changes is configured (Scored).
log "INFO" "5.4.1.2: Setting PASS_MIN_DAYS to 7 in /etc/login.defs"
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
log "INFO" "5.4.1.2: Running sudo cat /etc/shadow | cut -d: -f1 | while read entry; do chage --mindays 1 ${entry}; done"
sudo cat /etc/shadow | cut -d: -f1 | while read entry
do
  chage --mindays 1 ${entry}
done

# CIS benchmarking 5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)
log "INFO" "5.4.1.3: Setting PASS_WARN_AGE to 7 in /etc/login.defs"
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
logRun "5.4.1.3" "sudo chage --warndays 7 ubuntu"

# CIS benchmarking 5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)
logRun "5.4.1.4" "sudo useradd -D -f 30"
logRun "5.4.1.4" "sudo chage --inactive 30 ubuntu"

# CIS benchmarking 5.4.1.5 Ensure all users last password change date is in the past (Scored)
for my_uid in `sudo cat /etc/shadow | cut -d: -f1`
do
  date_sec=$(date -d "$(sudo chage --list ${my_uid} | grep -E "Last .* change" | awk '{print $5,$6,$7}')" +%s)
  date_now=$(date -d now +%s)
  if [ ${date_sec} -ge ${date_now} ]
  then
    handleExit "5.4.1.5: User ${my_uid} last password change date set in the future" "1"
  fi
done

# CIS benchmarking 5.4.2 Ensure system accounts are secured (Scored)
# This code taken from the ubuntu CIS benchmarking document. Note, ubuntu uid must be > 1000 (under default circumstances).
log "INFO" "5.4.2: set all system accounts to a non login shell"
sudo awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd | while read -r user; do sudo usermod -s "$(which nologin)" "$user"; done

log "INFO" "5.4.2: automatically lock non root system accounts"
sudo awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' sudo passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | while read -r user; do sudo usermod -L "$user"; done

# CIS benchmarking 5.4.3 Ensure default group for the root account is GID 0 (Scored)
logRun "5.4.3" "sudo usermod -g 0 root"

# CIS benchmarking 5.4.4 Ensure default user umask is 027 or more restrictive (Scored)
# umask is not set by default, but if found not in column 1 (i.e. in a conditional) it will need further investigation.
# We append both system bash.bashrc and profile files in case of users not using bash.
if [[ $(sudo grep -E '.+umask' /etc/bash.bashrc) ]]
then
  handleExit "5.4.4: umask command found not on column 1; default /etc/bash.bashrc needs investigating" "1"
fi
if [[ $(sudo grep -E '.+umask' /etc/profile) ]]
then
  handleExit "5.4.4: umask command found not on column 1; default /etc/profile needs investigating" "1"
fi
if [[ $(sudo grep -E '.+umask' /etc/profile.d/*.sh) ]]
then
  handleExit "5.4.4: umask command found not on column 1; default /etc/profile.d/*.sh files need investigating" "1"
fi

if [[ "$(sudo grep '^umask' /etc/bash.bashrc)" ]]
then
  log "INFO" "5.4.4: Running sudo sed -i s/^umask.*/umask 027/ /etc/bash.bashrc"
  sudo sed -i "s/^umask.*/umask 027/" /etc/bash.bashrc
else
  log "INFO" "5.4.4: Appending umask 027 to /etc/bash.bashrc"
  echo "umask 027" | sudo tee -a /etc/bash.bashrc
fi

if [[ "$(sudo grep '^umask' /etc/profile)" ]]
then
  log "INFO" "5.4.4: Running sudo sed -i "s/^umask.*/umask 027/" /etc/profile"
  sudo sed -i "s/^umask.*/umask 027/" /etc/profile
else
  log "INFO" "5.4.4: Appending umask 027 to /etc/profile"
  echo "umask 027" | sudo tee -a /etc/profile
fi

if [[ "$(ls -1 /etc/profile.d | grep umask)" ]]
then
  handleExit "5.4.4: Unexpected umask file in /etc/profile.d" "1"
else
  log "INFO" "5.4.4: Creating umask file in /etc/profile.d"
  echo "umask 027" | sudo tee -a /etc/profile.d/69-umask027.sh
fi

# CIS benchmarking 5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)
if [[ "$(sudo grep -e '^.*TMOUT' /etc/bash.bashrc)" ]]
then
  log "INFO" "5.4.5: Running sudo sed -i s/^.*TMOUT.*/readonly TMOUT=900 ; export TMOUT/ /etc/bash.bashrc"
  sudo sed -i "s/^.*TMOUT.*/readonly TMOUT=900 ; export TMOUT/" /etc/bash.bashrc
else
  log "INFO" "5.4.5: Appending readonly TMOUT=900 ; export TMOUT to /etc/bash.bashrc"
  echo "readonly TMOUT=900 ; export TMOUT" | sudo tee -a /etc/bash.bashrc
fi

if [[ "$(sudo grep -e "^.*TMOUT" /etc/profile)" ]]
then
  log "INFO" "5.4.5: Running sudo sed -i s/^.*TMOUT.*/readonly TMOUT=900 ; export TMOUT/ /etc/profile"
  sudo sed -i "s/^.*TMOUT.*/readonly TMOUT=900 ; export TMOUT/" /etc/profile
else
  log "INFO" "5.4.5: Appending readonly TMOUT=900 ; export TMOUT to /etc/profile"
  echo "readonly TMOUT=900 ; export TMOUT" | sudo tee -a /etc/profile
fi

# CIS benchmarking 5.5 Ensure root login is restricted to system console (Not Scored)
# CIS benchmarking 5.6 Ensure access to the su command is restricted (Scored)
logRun "5.6" "sudo groupadd sugroup"
if [[ "$(sudo grep -e '^# auth\s+required\s+pam_wheel.so.*' /etc/pam.d/su)" ]]
then
  log "INFO" "5.6: Uncommenting auth.*required.*pam_wheel.so in /etc/pam.d/su"
  sudo sed -i "s/^# auth.*required.*pam_wheel.so.*/auth required pam_wheel.so use_uid group=sugroup/" /etc/pam.d/su
else
  log "INFO" "5.6: Appending auth required pam_wheel.so to /etc/pam.d/su"
  echo "auth required pam_wheel.so use_uid group=sugroup" | sudo tee -a /etc/pam.d/su
fi

#
## all done

 #####  ###  #####         #####
#     #  #  #     #       #     #
#        #  #             #
#        #   #####  ##### ######
#        #        #       #     #
#     #  #  #     #       #     #
 #####  ###  #####         #####

echo
echo "##################################################################################################"
echo
banner "CIS: 6"
echo "##################################################################################################"

# CIS benchmarking 6.1 System File Permissions
# CIS benchmarking 6.1.1 Audit system file permissions (Not Scored)
# CIS benchmarking 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
logRun "6.1.2" "sudo chown root:root /etc/passwd"
logRun "6.1.2" "sudo chmod u-x,go-wx /etc/passwd"

# CIS benchmarking 6.1.3 Ensure permissions on /etc/gshadow- are configured (Scored)
logRun "6.1.3" "sudo chown root:shadow /etc/gshadow-"
logRun "6.1.3" "sudo chmod g-wx,o-rwx /etc/gshadow-"

# CIS benchmarking 6.1.4 Ensure permissions on /etc/shadow are configured (Scored)
logRun "6.1.4" "sudo chown root:shadow /etc/shadow"
logRun "6.1.4" "sudo chmod o-rwx,g-wx /etc/shadow"

# CIS benchmarking 6.1.5 Ensure permissions on /etc/group are configured (Scored)
logRun "6.1.5" "sudo chown root:root /etc/group"
logRun "6.1.5" "sudo chmod 644 /etc/group"

# CIS benchmarking 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)
logRun "6.1.6" "sudo chown root:root /etc/passwd-"
logRun "6.1.6" "sudo chmod 600 /etc/passwd-"

# CIS benchmarking 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
logRun "6.1.7" "sudo chown root:shadow /etc/shadow-"
logRun "6.1.7" "sudo chmod 600 /etc/shadow-"

# CIS benchmarking 6.1.8 Ensure permissions on /etc/group- are configured (Scored)
logRun "6.1.8" "sudo chown root:root /etc/group-"
logRun "6.1.8" "sudo chmod u-x,go-wx /etc/group-"

# CIS benchmarking 6.1.9 Ensure permissions on /etc/gshadow are configured (Scored)
logRun "6.1.9" "sudo chown root:shadow /etc/gshadow"
logRun "6.1.9" "sudo chmod o-rwx,g-rw /etc/gshadow"

# CIS benchmarking 6.1.10 Ensure no world writable files exist (Scored)
if [[ $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' sudo find '{}' -xdev -type f -perm -0002) ]]
then
  handleExit "6.1.10: There should be no world-writable files on a default image. Please investigate" "1"
fi

# CIS benchmarking 6.1.11 Ensure no unowned files or directories exist (Scored)
# When investigating this manually, /var/lib/private/systemd/timesync/clock was found to be present with an unowned uid/gid.
logRun "6.1.11" "sudo chown -R root:root /var/lib/private/systemd/timesync"
# There should be no unowned files at this point.  If there are, it is due to the above machinations.
unowned=$(for i in $(sudo lsblk | awk '{print $7}' | tail -n +2 | grep -v ^$); do sudo find ${i} -xdev -nouser; done)
if [[ -n "${unowned}" ]]
then
  echo
  echo "${unowned}"
  handleExit "6.1.11: Search for unowned files found the above files.  Build needs investigation" "69"
fi

# CIS benchmarking 6.1.12 Ensure no ungrouped files or directories exist (Scored)
ungrouped=$(for i in $(lsblk | awk '{print $7}' | tail -n +2 | grep -v ^$); do sudo find ${i} -xdev -nogroup; done)
if [[ -n "${ungrouped}" ]]
then
  echo
  echo "${ungrouped}"
  handleExit "6.1.12: Search for ungrouped files found the above files.  Build needs investigation" "70"
fi

# CIS benchmarking 6.1.13 Audit SUID executables (Not Scored)
# CIS benchmarking 6.1.14 Audit SGID executables (Not Scored)
# CIS benchmarking 6.2 User and Group Settings
# CIS benchmarking 6.2.1 Ensure password fields are not empty (Scored)
if [[ -n $(sudo cat /etc/shadow | awk -F: '($2 == "" ) { print $1 }') ]]
then
  handleExit "6.2.1: At least one user has no password set.  Correct your build." "71"
fi

# CIS benchmarking 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)
if [[ -n $(sudo grep '^\+:' /etc/passwd) ]]
then
  handleExit "6.2.2: Password file has pluses in harking back from the age of NIS.  Correct your build." "72"
fi

# CIS benchmarking 6.2.3 Ensure all users' home directories exist (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [ ! -d "${dir}" ]
  then
    handleExit "6.2.3: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "73"
  fi
done

# CIS benchmarking 6.2.4 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
if [[ -n $(sudo grep '^\+:' /etc/shadow) ]]
then
  handleExit "6.2.4: Shadow file has pluses in harking back from the age of NIS.  Correct your build." "74"
fi

# CIS benchmarking 6.2.5 Ensure no legacy "+" entries exist in /etc/group (Scored)
if [[ -n $(sudo grep '^\+:' /etc/group) ]]
then
  handleExit "6.2.5: Group file has pluses in harking back from the age of NIS.  Correct your build." "75"
fi

# CIS benchmarking 6.2.6 Ensure root is the only UID 0 account (Scored)
if [[ $(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | wc -l) != 1 ]]
then
  handleExit "6.2.6: More than one user has UID 0.  Correct your build." "76"
fi

# CIS benchmarking 6.2.7 Ensure root PATH Integrity (Scored)
if [[ $(sudo echo $PATH | grep ::) != "" ]]
then
  handleExit "6.2.7: Empty Directory in root PATH (::)" "77"
fi

if [[ $(sudo echo $PATH | grep :$) != "" ]]
then
  handleExit "6.2.7: Trailing : in PATH" "78"
fi

echo 'echo ${PATH}' | sudo sh | sed -e 's/::/:/' -e 's/:$//' -e 's/:/\n/g' | while read p
do
  if [[ "${p}" == "." ]]
  then
    handleExit "6.2.7: root PATH contains '.'.  Correct your build." "79"
  fi
  if [[ -d ${p} ]]
  then
    dir_perm=$(ls -ldH ${p} | cut -f1 -d" ")
    if [[ $(echo ${dir_perm} | cut -c6) != "-" ]]
    then
      handleExit "6.2.7: root PATH: Group Write permission set on directory ${p}.  Correct your build." "80"
    fi
    if [ $(echo ${dir_perm} | cut -c9) != "-" ]
    then
      handleExit "6.2.7: root PATH: Other Write permission set on directory ${p}.  Correct your build." "81"
    fi
    if [ $(ls -ldH ${p} | awk '{print $3}') != "root" ]
    then
        handleExit "6.2.7: root PATH: ${p} is not owned by root.  Correct your build." "82"
    fi
  else
    log "WARN" "6.2.7: From root PATH, ${p} is not a directory."
  fi
done

# CIS benchmarking 6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [ ! -d "${dir}" ]
  then
    handleExit "6.2.8: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "83"
  else
    dir_perm=$(ls -ld ${dir} | cut -f1 -d" ")
    if [[ $(echo ${dir_perm} | cut -c6) != "-" ]]
    then
      handleExit "6.2.8: Group Write permission set on the home directory (${dir}) of user ${user}.  Correct your build." "84"
    fi

    if [[ $(echo ${dir_perm} | cut -c8) != "-" ]]
    then
      handleExit "6.2.8: Other Read permission set on the home directory (${dir}) of user ${user}.  Correct your build." "85"
    fi

    if [[ $(echo ${dir_perm} | cut -c9) != "-" ]]
    then
      handleExit "6.2.8: Other Write permission set on the home directory (${dir}) of user ${user}.  Correct your build." "86"
    fi

    if [[ $(echo ${dir_perm} | cut -c10) != "-" ]]
    then
      handleExit "6.2.8: Other Execute permission set on the home directory (${dir}) of user ${user}.  Correct your build." "87"
    fi
  fi
done

# CIS benchmarking 6.2.9 Ensure users own their home directories (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [ ! -d "${dir}" ]
  then
    handleExit "6.2.9: The home directory (${dir}) of user ${user} does not exist.  Correct your build" "88"
  else
    owner=$(stat -L -c "%U" "${dir}")
    if [[ "${owner}" != "${user}" ]]
    then
      handleExit "6.2.9: The home directory (${dir}) of user ${user} is owned by ${owner}.  Correct your build." "89"
    fi
  fi
done

# CIS benchmarking 6.2.10 Ensure users' dot files are not group or world writable (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [[ ! -d "${dir}" ]]
  then
    handleExit "6.2.10: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "90"
  else
    for file in ${dir}/.[A-Za-z0-9]*
    do
      if [ ! -h "${file}" -a -f "${file}" ]
      then
        fileperm=$(ls -ld ${file} | cut -f1 -d" ")
        if [[ $(echo ${fileperm} | cut -c6) != "-" ]]
        then
          handleExit "6.2.10: Group Write permission set on file ${file}.  Correct your build." "91"
        fi

        if [[ $(echo ${fileperm} | cut -c9) != "-" ]]
        then
          handleExit "6.2.10: Other Write permission set on file ${file}.  Correct your build." "92"
        fi
      fi
    done
  fi
done

# CIS benchmarking 6.2.11 Ensure no users have .forward files (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [[ ! -d "${dir}" ]]
  then
    handleExit "6.2.11: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "93"
  else
    if [ ! -h "${dir}/.forward" -a -f "${dir}/.forward" ]
    then
      handleExit "6.2.11: .forward file ${dir}/.forward exists.  Correct your build." "94"
    fi
  fi
done

# CIS benchmarking 6.2.12 Ensure no users have .netrc files (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [[ ! -d "${dir}" ]]
  then
    handleExit "6.2.12: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "95"
  else
    if [ ! -h "${dir}/.netrc" -a -f "${dir}/.netrc" ]
    then
      handleExit "6.2.12: .netrc file ${dir}/.netrc exists.  Correct your build." "96"
    fi
  fi
done

# CIS benchmarking 6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [[ ! -d "${dir}" ]]
  then
    handleExit "6.2.13: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "97"
  else
    for file in ${dir}/.netrc
    do
      if [ ! -h "${file}" -a -f "${file}" ]
      then
        file_perm=$(ls -ld ${file} | cut -f1 -d" ")
        if [[ $(echo ${file_perm} | cut -c5) != "-" ]]
        then
          handleExit "6.2.13: Group Read set on ${file}.  Correct your build." "98"
        fi

        if [[ $(echo ${file_perm} | cut -c6) != "-" ]]
        then
          handleExit "6.2.13: Group Write set on ${file}.  Correct your build." "99"
        fi

        if [[ $(echo ${file_perm} | cut -c7) != "-" ]]
        then
          handleExit "6.2.13: Group Execute set on ${file}.  Correct your build." "100"
        fi

        if [[ $(echo ${file_perm} | cut -c8) != "-" ]]
        then
          handleExit "6.2.13: Other Read set on ${file}.  Correct your build." "101"
        fi

        if [[ $(echo ${file_perm} | cut -c9) != "-" ]]
        then
          handleExit "6.2.13: Other Write set on ${file}.  Correct your build." "102"
        fi

        if [[ $(echo ${file_perm} | cut -c10) != "-" ]]
        then
          handleExit "6.2.13: Other Execute set on ${file}.  Correct your build." "103"
        fi
      fi
    done
  fi
done

# CIS benchmarking 6.2.14 Ensure no users have .rhosts files (Scored)
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir
do
  if [[ ! -d "${dir}" ]]
  then
    handleExit "6.2.14: The home directory (${dir}) of user ${user} does not exist.  Correct your build." "104"
  else
    for file in ${dir}/.rhosts
    do
      if [ ! -h "${file}" -a -f "${file}" ]
      then
        handleExit "6.2.14: .rhosts file in ${dir}.  Correct your build." "105"
      fi
    done
  fi
done

# CIS benchmarking 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)
for i in $(cut -s -d: -f4 /etc/passwd | sort -u )
do
  if [[ $(grep -q -P "^.*?:[^:]*:${i}:" /etc/group) -ne 0 ]]
  then
    handleExit "6.2.15: Group ${i} is referenced by /etc/passwd but does not exist in /etc/group.  Correct your build." "106"
  fi
done

# CIS benchmarking 6.2.16 Ensure no duplicate UIDs exist (Scored)
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x
do
  [ -z "${x}" ] && break
  set - ${x}
  if [[ ${1} -gt 1 ]]
  then
    users=$(awk -F: '($3 == n) { print $1 }' n=${2} /etc/passwd | xargs)
    handleExit "6.2.16: Duplicate UID (${2}): ${users}.  Correct your build." "107"
  fi
done

# CIS benchmarking 6.2.17 Ensure no duplicate GIDs exist (Scored)
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x
do
  [ -z "${x}" ] && break
  set - ${x}
  if [[ ${1} -gt 1 ]]
  then
    groups=$(awk -F: '($3 == n) { print $1 }' n=${2} /etc/group | xargs)
    handleExit "6.2.17: Duplicate GID (${2}): ${groups}" "108"
  fi
done

# CIS benchmarking 6.2.18 Ensure no duplicate user names exist (Scored)
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x
do
  [ -z "${x}" ] && break
  set - ${x}
  if [[ ${1} -gt 1 ]]
  then
    uids=$(awk -F: '($1 == n) { print $3 }' n=${2} /etc/passwd | xargs)
    handleExit "6.2.18: Duplicate User Name (${2}): ${uids}" "109"
  fi
done

# CIS benchmarking 6.2.19 Ensure no duplicate group names exist (Scored)
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x
do
  [ -z "${x}" ] && break
  set - ${x}
  if [[ ${1} -gt 1 ]]
  then
    gids=$(gawk -F: '($1 == n) { print $3 }' n=${2} /etc/group | xargs)
    handleExit "6.2.19: Duplicate Group Name (${2}): ${gids}" "110"
  fi
done

# CIS benchmarking 6.2.20 Ensure shadow group is empty (Scored)
if [[ -n $(grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group) ]]
then
  handleExit "6.2.20: Users are assigned to the shadow group.  Correct your build." "111"
fi

shadow_group=$(grep shadow /etc/group | awk -F: '{print $3}')
if [[ -n $(awk -v shadow_gp=${shadow_group} -F: '($4 == "shadow_gp") { print }' /etc/passwd) ]]
then
  handleExit "6.2.20: Users are assigned to the shadow group.  Correct your build." "112"
fi

# CIS benchmarking 1.5.1 Ensure permissions on bootloader config are configured (Scored)
## NOTE further update to the grub.cfg perms required as update-grub undoes the work.  See the end.
logRun "1.5.1" "sudo chown root:root /boot/grub/grub.cfg"
logRun "1.5.1" "sudo chmod og-rwx /boot/grub/grub.cfg"
# logRun "3.6" "sudo apt-get --quiet --assume-yes remove network-manager"

## jah brendan
#
echo "##################################################################################################"
echo
banner "CIS DONE"
echo "##################################################################################################"
trap 'echo' EXIT
exit 0
#
## all done
