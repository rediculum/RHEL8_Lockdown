#!/bin/bash

#This script will run through several checks and for each check output to the terminal 'OK' or 'ERROR
#The checks are designed to test whether or not the host conforms to the benchmarks in the
#following document
#https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v1.0.0.pdf

#This is aimed to be a starting point for a sysadmin to check or audit hosts he/she supports
#It's envisaged that it will need customising to suit a particular environment
#e.g. there are about 200 checks, someone may want to chop out X of them to suit their environment
#The script does not change anything on the host, mostly it runs a lot of greps & cuts 
#on config files.
#To quickly get an idea of what this script does have a look at the 'main' and 'func_wrapper' functions  
#Copyright (c) 2015, Ross Hamilton. All rights reserved.

. /etc/os-release
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"

FSTAB='/etc/fstab'
YUM_CONF='/etc/yum.conf'
GRUB_CFG='/boot/grub2/grub.cfg'
GRUB_DIR='/etc/grub.d'
SELINUX_CFG='/etc/selinux/config'
JOURNALD_CFG='/etc/systemd/journald.conf'
CHRONY_CONF='/etc/chrony.conf'
SECURETTY_CFG='/etc/securetty'
LIMITS_CNF='/etc/security/limits.conf'
SYSCTL_CNF='/etc/sysctl.d/50-CIS.conf'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
AUDIT_RULES='/etc/audit/audit.rules'
LOGR_SYSLOG='/etc/logrotate.d/syslog'
ANACRONTAB='/etc/anacrontab'
CRONTAB='/etc/crontab'
CRON_HOURLY='/etc/cron.hourly'
CRON_DAILY='/etc/cron.daily'
CRON_WEEKLY='/etc/cron.weekly'
CRON_MONTHLY='/etc/cron.monthly'
CRON_DIR='/etc/cron.d'
AT_ALLOW='/etc/at.allow'
AT_DENY='/etc/at.deny'
CRON_ALLOW='/etc/cron.allow'
CRON_DENY='/etc/cron.deny'
SSHD_CFG='/etc/ssh/sshd_config'
SYSTEM_AUTH='/etc/pam.d/system-auth'
PWQUAL_CNF='/etc/security/pwquality.conf'
PASS_AUTH='/etc/pam.d/password-auth'
PAM_SU='/etc/pam.d/su'
GROUP='/etc/group'
LOGIN_DEFS='/etc/login.defs'
PASSWD='/etc/passwd'
SHADOW='/etc/shadow'
GSHADOW='/etc/gshadow'
BASHRC='/etc/bashrc'
PROF_D='/etc/profile.d'
PROFILE='/etc/profile'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
BANNER_MSG='/etc/dconf/db/gdm.d/01-banner-message'
TOTAL=0; PASS=0; FAILED=0

function echo_bold {
  echo -e "\e[1m${@} \e[0m"
}

function echo_red {
  echo -e "\e[91m${@} \e[0m"
}

function echo_green {
  echo -e "\e[92m${@} \e[0m"
}

function separate_partition {
  # Test that the supplied $1 is a separate partition

  local filesystem="${1}"
  grep -q "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return
}

function mount_option {
  # Test the the supplied mount option $2 is in use on the supplied filesystem $1

  local filesystem="${1}"
  local mnt_option="${2}"

  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep -q "${mnt_option}" || return

  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep -q "${mnt_option}" || return
}

function bind_mounted_to {
  # Test that a directory /foo/dir is bind mounted onto a particular filesystem

  local directory="${1}"
  local filesystem="${2}"
  local E_NO_MOUNT_OUTPUT=1

  grep "^${filesystem}[[:space:]]" "${FSTAB}" | grep -q "${directory}" || return

  local grep_mount
  grep_mount=$(mount | grep "^${filesystem}[[:space:]]" | grep "${directory}")
  #If $directory doesn't appear in the mount output as mounted on the $filesystem  
  #it may appear in the output as being mounted on the same device as $filesystem, check for this
  local fs_dev
  local dir_dev
  fs_dev="$(mount | grep "[[:space:]]${filesystem}[[:space:]]" | cut -d" " -f1)"
  dir_dev="$(mount | grep "[[:space:]]${directory}[[:space:]]" | cut -d" " -f1)"
  if [[ -z "${grep_mount}" ]] && [[ "${fs_dev}" != "${dir_dev}" ]] ; then
    return "${E_NO_MOUNT_OUTPUT}"
  fi
}

function test_disable_mounting {
  # Test the the supplied filesystem type $1 is disabled

  local module="${1}"
  modprobe -n -v ${module} | grep -q "install \+/bin/true" || return 

  lsmod | grep -qv "${module}" || return
}

function gpg_key_installed {
  # Test GPG Key is installed
  rpm -q gpg-pubkey | grep -q gpg || return
}

function yum_gpgcheck {
  # Check that gpgcheck is Globally Activated
  cut -d \# -f1 ${YUM_CONF} | grep 'gpgcheck' | grep -q 'gpgcheck=1' || return
}

function yum_update {
  # Check for outstanding pkg update with yum
  yum -q check-update || return
}

function rpm_installed {
  # Test whether an rpm is installed

  local rpm="${1}"
  local rpm_out
  rpm_out="$(rpm -q --queryformat "%{NAME}\n" ${rpm})"
  [[ "${rpm}" = "${rpm_out}" ]] || return
}

function verify_aide_cron {
  # Verify there is a cron job scheduled to run the aide check
  crontab -u root -l | cut -d\# -f1 | grep -q "aide \+--check" || return
}

function verify_selinux_grubcfg {
  # Verify SELinux is not disabled in grub.cfg file 

  local grep_out1
  grep_out1="$(grep selinux=0 ${GRUB_CFG})"
  [[ -z "${grep_out1}" ]] || return

  local grep_out2
  grep_out2="$(grep enforcing=0 ${GRUB_CFG})"
  [[ -z "${grep_out2}" ]] || return
}

function verify_selinux_state {
  # Verify SELinux configured state in /etc/selinux/config
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUX=' | tr -d '[[:space:]]' | grep -q 'SELINUX=enforcing' || return
}

function verify_selinux_policy {
  # Verify SELinux policy in /etc/selinux/config
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUXTYPE=' | tr -d '[[:space:]]' | grep -q 'SELINUXTYPE=targeted' || return
}

function rpm_not_installed {
  # Check that the supplied rpm $1 is not installed
  local rpm="${1}"
  rpm -q ${rpm} | grep -q "package ${rpm} is not installed" || return
}

function unconfined_procs {
  # Test for unconfined daemons
  local ps_out
  ps_out="$(ps -eZ | egrep 'initrc|unconfined' | egrep -v 'bash|ps|grep')"
  [[ -n "${ps_out}" ]] || return
}

function check_grub_owns {
  # Check User/Group Owner on grub.cfg file
  stat -L -c "%u %g" ${GRUB_CFG} | grep -q '0 0' || return
}

function check_grub_perms {
  # Check Perms on grub.cfg file
  stat -L -c "%a" ${GRUB_CFG} | grep -q '.00' || return
}

function check_file_perms {
  # Check Perms on a supplied file match supplied pattern
  local file="${1}"
  local pattern="${2}"

  stat -L -c "%a" ${file} | grep -q "${pattern}" || return
}

function check_root_owns {
  # Check User/Group Owner on the specified file
  local file="${1}"
  stat -L -c "%u %g" ${file} | grep -q '0 0' || return
}

function check_boot_pass {
  grep -q 'set superusers=' "${GRUB_CFG}"
  if [[ "$?" -ne 0 ]]; then
    grep -q 'set superusers=' ${GRUB_DIR}/* || return
    file="$(grep 'set superusers' ${GRUB_DIR}/* | cut -d: -f1)"
    grep -q 'password' "${file}" || return
  else
    grep -q 'password' "${GRUB_CFG}" || return
  fi
}

function check_svc_not_enabled {
  # Verify that the service $1 is not enabled
  local service="$1" 
  systemctl list-unit-files | grep -qv "${service}" && return 
  systemctl is-enabled "${service}" | grep -q 'enabled' || return
}

function check_svc_enabled {
  # Verify that the service $1 is enabled
  local service="$1" 
  systemctl list-unit-files | grep -q "${service}.service" || return 
  systemctl is-enabled "${service}" | grep -q 'enabled' && return
}

function chrony_cfg {
   egrep -q "^(server|pool)" ${CHRONY_CONF} || return
}

function restrict_core_dumps {
  # Verify that suid programs cannot dump their core
  egrep -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${LIMITS_CNF}" || return
  cut -d\# -f1 ${SYSCTL_CNF} | grep fs.suid_dumpable | cut -d= -f2 | tr -d '[[:space:]]' | grep -q '0' || return 
}

function chk_sysctl_cnf {
  # Check the sysctl_conf file contains a particular flag, set to a particular value 
  local flag="$1"
  local value="$2"
  local sysctl_cnf="$3"

  cut -d\# -f1 ${sysctl_cnf} | grep "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}


function chk_sysctl {
  local flag="$1"
  local value="$2"

  sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}

function sticky_wrld_w_dirs {
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \
\( -perm -0002 -a ! -perm -1000 \))"
  [[ -z "${dirs}" ]] || return
}

function check_umask {
  cut -d\# -f1 /etc/init.d/functions | grep -q "umask[[:space:]]027" || return
}

function check_def_tgt {
  #Check that the default boot target is multi-user.target 
  local default_tgt
  default_tgt="$(systemctl get-default)"
  [[ "${default_tgt}" = "multi-user.target" ]] || return
}

function mta_local_only {
  # If port 25 is being listened on, check it is on the loopback address
  netstat_out="$(netstat -an | grep "LIST" | grep ":25[[:space:]]")"
  if [[ "$?" -eq 0 ]] ; then
    ip=$(echo ${netstat_out} | cut -d: -f1 | cut -d" " -f4)
    [[ "${ip}" = "127.0.0.1" ]] || return    
  fi
}

function ip6_router_advertisements_dis {
  # Check that IPv6 Router Advertisements are disabled
  # If ipv6 is disabled then we don't mind what IPv6 router advertisements are set to
  # If ipv6 is enabled then both settings should be set to zero
  chk_sysctl net.ipv6.conf.all.disable_ipv6 1 && return
  chk_sysctl net.ipv6.conf.all.accept_ra 0 || return
  chk_sysctl net.ipv6.conf.default.accept_ra 0 || return
}
  
function ip6_redirect_accept_dis {
  # Check that IPv6 Redirect Acceptance is disabled
  # If ipv6 is disabled then we don't mind what IPv6 redirect acceptance is set to
  # If ipv6 is enabled then both settings should be set to zero
  chk_sysctl net.ipv6.conf.all.disable_ipv6 1 && return
  chk_sysctl net.ipv6.conf.all.accept_redirects 0 || return
  chk_sysctl net.ipv6.conf.default.accept_redirects 0 || return
}

function chk_file_exists {
  local file="$1"
  [[ -f "${file}" ]] || return
}

function chk_file_not_exists {
  local file="$1"
  [[ -f "${file}" ]] && return 1 || return 0
}
 
function chk_hosts_deny_content {
  # Check the hosts.deny file resembles ALL: ALL
  cut -d\# -f1 ${HOSTS_DENY} | grep -q "ALL[[:space:]]*:[[:space:]]*ALL" || return
}

function chk_cis_cnf { 
  local protocol="$1"
  local file="$2"
  grep -q "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return
} 

function chk_rsyslog_remote_host {
  # rsyslog should be configured to send logs to a remote host
  # grep output should resemble 
  # *.* @@loghost.example.com
  grep -q "^*.*[^I][^I]*@" ${RSYSLOG_CNF} || return
}

function audit_log_storage_size {
  # Check the max size of the audit log file is configured
  cut -d\# -f1 ${AUDITD_CNF} | egrep -q "max_log_file[[:space:]]|max_log_file=" || return
}


function dis_on_audit_log_full {
  # Check auditd.conf is configured to notify the admin and halt the system when audit logs are full
  cut -d\# -f2 ${AUDITD_CNF} | grep 'space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'email' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'action_mail_acct' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'root' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'admin_space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'halt' || return
}

function keep_all_audit_info {
  # Check auditd.conf is configured to retain audit logs
  cut -d\# -f2 ${AUDITD_CNF} | grep 'max_log_file_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'keep_logs' || return
}

function audit_procs_prior_2_auditd {
  # Check lines that start with linux have the audit=1 parameter set
  grep_grub="$(grep "^[[:space:]]*linux" ${GRUB_CFG} | grep -v 'audit=1')"
  [[ -z "${grep_grub}" ]] || return
}

function audit_backlog_limits {
  # Check lines that start with linux have the audit=1 parameter set
  grep_grub="$(grep "^[[:space:]]*linux" ${GRUB_CFG} | grep -v 'audit_backlog_limit=')"
  [[ -z "${grep_grub}" ]] || return
}

function audit_date_time {
  # Confirm that the time-change lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+stime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/localtime" || return
}

function audit_user_group {
  # Confirm that the identity lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/group" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/passwd" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/gshadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/shadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/security\/opasswd" || return
}

function audit_network_env {
  # Confirm that the system-locale lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b32" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/issue" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/issue.net" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/hosts" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/sysconfig\/network" || return
}

function audit_logins_logouts {
  # Confirm that the logins lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/faillog" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/lastlog" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/tallylog" || return
}

function audit_session_init {
  # Confirm that the logins lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/run\/utmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/wtmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/btmp" || return
}

function audit_sys_mac {
  # Confirm that the logins lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+MAC-policy" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/selinux\/" || return
}

function audit_dac_perm_mod_events {
  # Confirm that perm_mod lines matching the patterns below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
  | egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
  | egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
  | egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
  | egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
  | egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
  | egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
  | egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
  | egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function unsuc_unauth_acc_attempts {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function coll_priv_cmds {
  local priv_cmds
  priv_cmds="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f)"
  for cmd in ${priv_cmds} ; do
    cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+privileged" | egrep "\-F[[:space:]]+path=${cmd}" \
    | egrep "\-F[[:space:]]+perm=x" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
    | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  done
}

function coll_suc_fs_mnts {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function coll_file_del_events {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function coll_chg2_sysadm_scope {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+scope" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/sudoers" || return

}

function coll_sysadm_actions {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+actions" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/sudo.log" || return

}

function kmod_lod_unlod {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/insmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/rmmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/modprobe" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-S[[:space:]]+delete_module" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+init_module" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function audit_cfg_immut {
  # There should be a "-e 2" at the end of the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep -q "^-e[[:space:]]+2" || return
}

function logrotate_cfg {
  [[ -f "${LOGR_SYSLOG}" ]] || return

  local timestamp
  timestamp=$(date '+%Y%m%d_%H%M%S')
  local tmp_data="/tmp/logrotate.tmp.${timestamp}"
  local file_list="/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/cron"
  local line_num
  line_num=$(grep -n '{' "${LOGR_SYSLOG}" | cut -d: -f1)
  line_num=$((${line_num} - 1))
  head -${line_num} "${LOGR_SYSLOG}" > ${tmp_data}
  for file in ${file_list} ; do
    grep -q "${file}" ${tmp_data} || return
  done
  rm "${tmp_data}" 
}

function at_cron_auth_users {
 [[ ! -f ${AT_DENY} ]] || return 
 [[ ! -f ${CRON_DENY} ]] || return 
 check_root_owns "${CRON_ALLOW}"
 check_root_owns "${AT_ALLOW}"
 check_file_perms "${CRON_ALLOW}" 600 
 check_file_perms "${AT_ALLOW}" 600 
}

function chk_param {
  local file="${1}" 
  local parameter="${2}" 
  local value="${3}" 
  [[ -z ${3} ]] && spacer="" || spacer="[[:space:]]"
  cut -d\# -f1 ${file} | egrep -q "^${parameter}${spacer}${value}" || return
}


function ssh_maxauthtries {
  local allowed_max="${1}"
  local actual_value
  actual_value=$(cut -d\# -f1 ${SSHD_CFG} | grep 'MaxAuthTries' | cut -d" " -f2)
  [[ ${actual_value} -le ${allowed_max} ]] || return 
}

function ssh_user_group_access {
  local allow_users
  local allow_groups
  local deny_users
  local deny_users
  allow_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowUsers" | cut -d" " -f2)"
  allow_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowGroups" | cut -d" " -f2)"
  deny_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyUsers" | cut -d" " -f2)"
  deny_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyGroups" | cut -d" " -f2)"
  [[ -n "${allow_users}" ]] || return
  [[ -n "${allow_groups}" ]] || return
  [[ -n "${deny_users}" ]] || return
  [[ -n "${deny_groups}" ]] || return
}

function pass_hash_algo {
  local algo="${1}"
  if [[ $MAIN_VERSION_ID -lt 8 ]]; then
    authconfig --test | grep 'hashing' | grep -q "${algo}" || return
  else
    grep -q "^password.*$algo.*" /etc/authselect/password-auth || return
  fi
}

function pass_req_params {
  # verify the pam_pwquality.so params in /etc/pam.d/system-auth
  grep pam_pwquality.so ${SYSTEM_AUTH} | grep 'password' | grep 'requisite' | grep 'try_first_pass' | grep -q 'local_users_only' || return
  grep -q 'minlen = 14' ${PWQUAL_CNF} || return
  grep -q 'dcredit = -1' ${PWQUAL_CNF} || return
  grep -q 'ucredit = -1' ${PWQUAL_CNF} || return
  grep -q 'ocredit = -1' ${PWQUAL_CNF} || return
  grep -q 'lcredit = -1' ${PWQUAL_CNF} || return
  grep -q 'retry = 3' ${PWQUAL_CNF} || return
}

function failed_pass_lock {
  if [[ ${MAIN_VERSION_ID} -lt 8 ]]; then
    egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_deny.so' || return
    egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep 'pam_faillock.so' | grep 'preauth' | grep 'audit' | grep 'silent' | grep 'deny=5' | grep -q 'unlock_time=900' || return
    grep 'auth' ${PASS_AUTH} | grep 'pam_unix.so' | egrep -q "\[success=1[[:space:]]+default=bad\]" || return
    grep 'auth' ${PASS_AUTH} | grep 'pam_faillock.so' | grep 'authfail' | grep 'audit' | grep 'deny=5' | grep 'unlock_time=900' | egrep -q "\[default=die\]" || return
    egrep "auth[[:space:]]+sufficient" ${PASS_AUTH} | grep 'pam_faillock.so' | grep 'authsucc' | grep 'audit' | grep 'deny=5' | grep -q 'unlock_time=900' || return
    egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_deny.so' || return
   
    egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_env.so' || return
    egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep 'pam_faillock.so' | grep 'preauth' | grep 'audit' | grep 'silent' | grep 'deny=5' | grep -q 'unlock_time=900' || return
    grep 'auth' ${SYSTEM_AUTH} | grep 'pam_unix.so' | egrep -q "\[success=1[[:space:]]+default=bad\]" || return
    grep 'auth' ${SYSTEM_AUTH} | grep 'pam_faillock.so' | grep 'authfail' | grep 'audit' | grep 'deny=5' | grep 'unlock_time=900' | egrep -q "\[default=die\]" || return
    egrep "auth[[:space:]]+sufficient" ${SYSTEM_AUTH} | grep 'pam_faillock.so' | grep 'authsucc' | grep 'audit' | grep 'deny=5' | grep -q 'unlock_time=900' || return
    egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_deny.so' || return
  else
    grep -q "with-faillock" /etc/authselect/authselect.conf || return
  fi
}

function remember_passwd {
 egrep "auth[[:space:]]+sufficient" ${SYSTEM_AUTH} | grep 'pam_unix.so' | grep -q 'remember=5' || return
}

function su_access {
  egrep "auth[[:space:]]+required" "${PAM_SU}" | grep 'pam_wheel.so' | grep -q 'use_uid' || return
  grep 'wheel' "${GROUP}" | cut -d: -f4 | grep -q 'root' || return
}

function dis_sys_accs {
  # Check that system accounts are disabled
  local accounts 
  accounts="$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" \
&& $1!="halt" && $3<1000 && $7!="/sbin/nologin") {print}')"
  [[ -z "${accounts}" ]] || return
}

function root_def_grp {
  local gid1
  local gid2
  gid1="$(grep "^root:" "${PASSWD}" | cut -d: -f4)" 
  [[ "${gid1}" -eq 0 ]] || return
  gid2="$(id -g root)" 
  [[ "${gid2}" -eq 0 ]] || return
}

function def_umask_for_users {
  cut -d\#  -f1 "${BASHRC}" | egrep -q "umask[[:space:]]+027" || return
  egrep -q "umask[[:space:]]+027" ${PROFILE} ${PROF_D}/* || return
}

function inactive_usr_acs_locked {
  # After being inactive for a period of time the account should be disabled
  local days
  local inactive_threshold=30
  days="$(useradd -D | grep INACTIVE | cut -d= -f2)"
  [[ ${days} -ge ${inactive_threshold} ]] || return
}

function warning_banners {
  # Check that system login banners don't contain any OS information
  local motd
  local issue
  local issue_net
  motd="$(egrep '(\\v|\\r|\\m|\\s)' ${MOTD})"
  issue="$(egrep '(\\v|\\r|\\m|\\s)' ${ISSUE})"
  issue_net="$(egrep '(\\v|\\r|\\m|\\s)' ${ISSUE_NET})"
  [[ -z "${motd}" ]] || return
  [[ -z "${issue}" ]] || return
  [[ -z "${issue_net}" ]] || return
}

function gnome_banner {
  # On a host aiming to meet CIS requirements GNOME is unlikely to be installed 
  # Thus the function says if the file exists then it should have these lines in it
  if [[ -f "${BANNER_MSG}" ]] ; then
    egrep '[org/gnome/login-screen]' ${BANNER_MSG} || return
    egrep 'banner-message-enable=true' ${BANNER_MSG} || return
    egrep 'banner-message-text=' ${BANNER_MSG} || return
  fi
}

function unowned_files {
  local uo_files
  uo_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
  [[ -z "${uo_files}" ]] || return
}
 

function ungrouped_files {
  local ug_files
  ug_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
  [[ -z "${ug_files}" ]] || return
}

function suid_exes {
  # For every suid exe on the host use the rpm cmd to verify that it should be suid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local suid_exes rpm rpm_out
  suid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for suid_exe in ${suid_exes}
  do
    rpm=$(rpm -qf $suid_exe)
    rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
    [[ -z "${rpm_out}" ]] || return
  done
}
 
function sgid_exes {
  # For every sgid exe on the host use the rpm cmd to verify that it should be sgid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local sgid_exes rpm rpm_out
  sgid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for sgid_exe in ${sgid_exes}
  do
    rpm=$(rpm -qf $suid_exe)
    rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
    [[ -z "${rpm_out}" ]] || return
  done
}

function passwd_field_chk {
  local shadow_out
  shadow_out="$(awk -F: '($2 == "" ) { print $1 }' ${SHADOW})"
  [[ -z "${shadow_out}" ]] || return
}

function nis_in_file {
  # Check for lines starting with + in the supplied file $1 
  # In /etc/{passwd,shadow,group} it used to be a marker to insert data from NIS 
  # There shouldn't be any entries like this
  local file="${1}"
  local grep_out
  grep_out="$(grep '^+:' ${file})"
  [[ -z "${grep_out}" ]] || return
}

function no_uid0_other_root {
  local grep_passwd
  grep_passwd="$(awk -F: '($3 == 0) { print $1 }' ${PASSWD})"
  [[ "${grep_passwd}" = "root" ]] || return  
}

function world_w_dirs {
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)"
  [[ -z "${dirs}" ]] || return   
}

function root_path {
  # There should not be an empty dir in $PATH
  local grep=/bin/grep
  local sed=/bin/sed
  path_grep="$(echo ${PATH} | ${grep} '::')"
  [[ -z "${path_grep}" ]] || return 

  # There should not be a trailing : on $PATH
  path_grep="$(echo ${PATH} | ${grep} :$)"
  [[ -z "${path_grep}" ]] || return 

  path_dirs="$(echo $PATH | ${sed} -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')"
  for dir in ${path_dirs} ; do
    # PATH should not contain .
    [[ "${dir}" != "." ]] || return

    #$dir should be a directory
    [[ -d "${dir}" ]] || return

    local ls_out
    ls_out="$(ls -ldH ${dir})" 
    if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi


    # Directory should be owned by root
    dir_own="$(echo ${ls_out} | awk '{print $3}')"
    [[ "${dir_own}" = "root" ]] || return
  done
}

function is_group_readable {
  local ls_output="${1}"
  # 5th byte of ls output is the field for group readable
  [[ "${ls_output:4:1}" = "r" ]] || return
}

function is_group_writable {
  local ls_output="${1}"
  # 6th byte of ls output is the field for group writable
  [[ "${ls_output:5:1}" = "w" ]] || return
}

function is_group_executable {
  local ls_output="${1}"
  # 7th byte of ls output is the field for group readable
  [[ "${ls_output:6:1}" = "r" ]] || return
}

function is_other_readable {
  local ls_output="${1}"
  # 8th byte of ls output is the field for other readable
  [[ "${ls_output:7:1}" = "r" ]] || return
}

function is_other_writable {
  local ls_output="${1}"
  # 9th byte of ls output is the field for other writable
  [[ "${ls_output:8:1}" = "w" ]] || return
}

function is_other_executable {
  local ls_output="${1}"
  # 10th byte of ls output is the field for other executable
  [[ "${ls_output:9:1}" = "x" ]] || return
}
 
function home_dir_perms {
  dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  [[ -z "${dirs}" ]] && return
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    local ls_out
    ls_out="$(ls -ldH ${dir})"
    if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_readable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_executable ${ls_out} ; then return 1 ; else return 0 ; fi
  done
}
 
function dot_file_perms {
  dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    for file in ${dir}/.[A-Za-z0-9]* ; do
      if [[ ! -h "${file}" && -f "${file}" ]] ; then
        local ls_out
        ls_out="$(ls -ldH ${dir})"
        if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi 
        if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
      fi 
    done
  done
}

function dot_rhosts_files {
  dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    local file="${dir}/.rhosts"
    if [[ ! -h "${file}" && -f "${file}" ]] ; then
      return 1
    else
      return 0
    fi
  done
}

function chk_groups_passwd {
  # We don't want to see any groups in /etc/passwd that aren't in /etc/group
  group_ids="$(cut -s -d: -f4 ${PASSWD} | sort -u)"
  for group_id in ${group_ids} ; do
    grep -q -P "^.*?:x:${group_id}:" ${GROUP} || return
  done
}

function chk_home_dirs_exist {
  #Check that users home directory do all exist
  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
      return 1 
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function chk_home_dirs_owns {
  #Check that users home directory do all exist
  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
      local owner
      owner="$(stat -L -c "%U" "${dir}")"
      [[ "${owner}" = "${user}" ]] || return
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function dot_netrc_perms {
  dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    for file in ${dir}/.netrc ; do
      if [[ ! -h "${file}" && -f "${file}" ]] ; then
        local ls_out
        ls_out="$(ls -ldH ${dir})"
        if is_group_readable ${ls_out} ; then return 1 ; else return 0 ; fi 
        if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
        if is_group_executable ${ls_out} ; then return 1 ; else return 0 ; fi
        if is_other_readable ${ls_out} ; then return 1 ; else return 0 ; fi 
        if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
        if is_other_executable ${ls_out} ; then return 1 ; else return 0 ; fi
      fi 
    done
  done
}

function user_dot_netrc {
  # We don't want to see any ~/.netrc files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.netrc" && -f "${dir}/.netrc" ]] ; then
      return 1 
    fi
  done
}

function user_dot_forward {
  # We don't want to see any ~/.forward files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.forward" && -f "${dir}/.forward" ]] ; then
      return 1 
    fi
  done
}

function duplicate_uids {
  local num_of_uids
  local uniq_num_of_uids
  num_of_uids="$(cut -f3 -d":" ${PASSWD} | wc -l)"
  uniq_num_of_uids="$(cut -f3 -d":" ${PASSWD} | sort -n | uniq | wc -l)" 
  [[ "${num_of_uids}" -eq "${uniq_num_of_uids}" ]] || return
}

function duplicate_gids {
  local num_of_gids
  local uniq_num_of_gids
  num_of_gids="$(cut -f3 -d":" ${GROUP} | wc -l)"
  uniq_num_of_gids="$(cut -f3 -d":" ${GROUP} | sort -n | uniq | wc -l)" 
  [[ "${num_of_gids}" -eq "${uniq_num_of_gids}" ]] || return
}

function duplicate_usernames {
  local num_of_usernames
  local num_of_uniq_usernames
  num_of_usernames="$(cut -f1 -d":" ${PASSWD} | wc -l)"
  num_of_uniq_usernames="$(cut -f1 -d":" ${PASSWD} | sort | uniq | wc -l)" 
  [[ "${num_of_usernames}" -eq "${num_of_uniq_usernames}" ]] || return
}

function duplicate_groupnames {
  local num_of_groupnames
  local num_of_uniq_groupnames
  num_of_groupnames="$(cut -f1 -d":" ${GROUP} | wc -l)"
  num_of_uniq_groupnames="$(cut -f1 -d":" ${GROUP} | sort | uniq | wc -l)" 
  [[ "${num_of_groupnames}" -eq "${num_of_uniq_groupnames}" ]] || return
}

function redhat_subscription {
  subscription-manager identity >/dev/null || return
}

function wlan_iface_disabled {
  nmcli -c no -m multiline radio all |grep -v "\-HW" |grep -q enabled && return 1 || return 0
}

function chk_cryptopolicy_not_legacy {
  egrep -qi '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config && return 1 || return 0
}

function chk_cryptopolicy_future_fips {
  egrep -qi '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config || return
}

function chk_owner_group {
  local file=$1
  local owner_group=$2
  stat -c '%U:%G' $1 |grep -q "$2" || return
}

function func_wrapper {
  let TOTAL++
  func_name=$1
  shift
  args=$@
  printf "${func_name} ${args}: "
  ${func_name} ${args} >/dev/null 2>&1
  if [[ "$?" -eq 0 ]]; then
    let PASS++
    echo_green OK
  else
    let FAILED++
    echo_red ERROR
  fi
}


function main {
  echo_bold "== CIS 1.1.1 Disable unused file systems"
  func_wrapper test_disable_mounting cramfs
  func_wrapper test_disable_mounting vfat
  func_wrapper test_disable_mounting squashfs
  func_wrapper test_disable_mounting udf
  func_wrapper test_disable_mounting freevxfs
  func_wrapper test_disable_mounting jffs2
  func_wrapper test_disable_mounting hfs
  func_wrapper test_disable_mounting hfsplus

  echo_bold "== CIS 1.1.2 Ensure separate /tmp exists"
  func_wrapper separate_partition /tmp
  echo_bold "== CIS 1.1.3 Ensure nodev option set on /tmp"
  func_wrapper mount_option /tmp nodev
  echo_bold "== CIS 1.1.4 Ensure nosuid option set on /tmp"
  func_wrapper mount_option /tmp nosuid
  echo_bold "== CIS 1.1.5 Ensure noexec option set on /tmp"
  func_wrapper mount_option /tmp noexec
  echo_bold "== CIS 1.1.6 Ensure separate /var exists"
  func_wrapper separate_partition /var
  echo_bold "== CIS 1.1.7 Ensure separate /var/tmp exists"
  func_wrapper bind_mounted_to /var/tmp /tmp
  echo_bold "== CIS 1.1.8 Ensure nodev option set on /var/tmp"
  func_wrapper mount_option /var/tmp nodev
  echo_bold "== CIS 1.1.9 Ensure nosuid option set on /var/tmp"
  func_wrapper mount_option /var/tmp nosuid
  echo_bold "== CIS 1.1.10 Ensure noexec option set on /var/tmp"
  func_wrapper mount_option /var/tmp noexec
  echo_bold "== CIS 1.1.11 Ensure separate /var/log exists"
  func_wrapper separate_partition /var/log
  echo_bold "== CIS 1.1.12 Ensure separate /var/log/audit exists"
  func_wrapper separate_partition /var/log/audit
  echo_bold "== CIS 1.1.13 Ensure separate /home exists"
  func_wrapper separate_partition /home
  echo_bold "== CIS 1.1.14 Ensure nodev option set on /home"
  func_wrapper mount_option /home nodev
  echo_bold "== CIS 1.1.15 Ensure nodev option set on /dev/shm"
  func_wrapper mount_option /dev/shm nodev
  echo_bold "== CIS 1.1.16 Ensure nosuid option set on /dev/shm"
  func_wrapper mount_option /dev/shm nosuid
  echo_bold "== CIS 1.1.17 Ensure noexec option set on /dev/shm"
  func_wrapper mount_option /dev/shm noexec
  echo_bold "== CIS 1.1.21 Ensure sticky bit set on all world-writeable dirs"
  func_wrapper sticky_wrld_w_dirs 
  echo_bold "== CIS 1.1.22 Disable Automounting"
  func_wrapper check_svc_not_enabled autofs
  echo_bold "== CIS 1.1.23 Disable USB Storage"
  func_wrapper test_disable_mounting usb-storage

  if [[ $ID == "rhel" ]]; then
    echo_bold "== CIS 1.2.1 Red Hat Subscription is configured"
    func_wrapper redhat_subscription
    echo_bold "== CIS 1.2.2 Disable rhnsd Daemon"
    func_wrapper check_svc_not_enabled rhnsd
  fi
  echo_bold "== CIS 1.2.3 GPG keys are configured"
  func_wrapper gpg_key_installed
  echo_bold "== CIS 1.2.4 gpgcheck is globally activated"
  func_wrapper yum_gpgcheck
  echo_bold "== CIS 1.2.5 Ensure repos are configured"
  func_wrapper yum_update

  echo_bold "== CIS 1.3.1 Ensure sudo is installd"
  func_wrapper rpm_installed sudo
  echo_bold "== CIS 1.3.2 Ensure pty is set in sudoers (TODO)"
  echo_bold "== CIS 1.3.3 Ensure logfile is set in sudoers (TODO)"

  echo_bold "== CIS 1.4.1 Ensure AIDE is installed"
  func_wrapper rpm_installed aide
  echo_bold "== CIS 1.4.1 Ensure AIDE is scheduled"
  func_wrapper verify_aide_cron

  echo_bold "== CIS 1.5.1 Ensure permissions on bootloader config"
  func_wrapper check_grub_perms
  echo_bold "== CIS 1.5.2 Ensure bootloader password"
  func_wrapper check_boot_pass
  echo_bold "== CIS 1.5.3 Ensure auth for single user mode (TODO)"

  echo_bold "== CIS 1.6.1 Ensure core dumps restricted"
  func_wrapper restrict_core_dumps 
  echo_bold "== CIS 1.6.2 Ensure ASLR enabled"
  func_wrapper chk_sysctl kernel.randomize_va_space 2

  echo_bold "== CIS 1.7.1.1 Ensure SELinux is installed"
  func_wrapper rpm_installed libselinux
  echo_bold "== CIS 1.7.1.2 Ensure SELinux is not disabled in grub"
  func_wrapper verify_selinux_grubcfg
  echo_bold "== CIS 1.7.1.3 Ensure SELinux policy configured"
  func_wrapper verify_selinux_policy
  echo_bold "== CIS 1.7.1.4 Ensure SELinux is enforced"
  func_wrapper verify_selinux_state
  echo_bold "== CIS 1.7.1.5 Ensure no unconfined services"
  func_wrapper unconfined_procs
  echo_bold "== CIS 1.7.1.6 Ensure SETroubleshoot not installed"
  func_wrapper rpm_not_installed setroubleshoot 
  echo_bold "== CIS 1.7.1.7 Ensure MCS Translation Service not installed"
  func_wrapper rpm_not_installed mcstrans
  #func_wrapper check_root_owns ${GRUB_CFG}

  echo_bold "== CIS 1.8.1.1-3 Ensure banners are configured"
  func_wrapper warning_banners
  echo_bold "== CIS 1.8.1.4-6 Ensure banners have permissions set"
  for file in ${MOTD} ${ISSUE} ${ISSUE_NET} ; do
    func_wrapper check_root_owns "${file}"
    func_wrapper check_file_perms "${file}" 644 
  done
  echo_bold "== CIS 1.8.2 Ensure GDM login banner is configured"
  func_wrapper gnome_banner

  echo_bold "== CIS 1.9 Ensure updates, patches and sec software installed"
  func_wrapper yum_update

  echo_bold "== CIS 1.10 Ensure system-wide crypto policy is not legacy"
  func_wrapper chk_cryptopolicy_not_legacy

  echo_bold "== CIS 1.11 Ensure system-wide crypto policy is FUTURE or FIPS"
  chk_cryptopolicy_future_fips

  echo_bold "== CIS 2.1.1 Ensure xinetd not installed"
  func_wrapper rpm_not_installed xinetd

  echo_bold "== CIS 2.2.1.1 Ensure time sync is in use"
  func_wrapper rpm_installed chrony
  echo_bold "== CIS 2.2.1.2 Ensure chrony is configured"
  func_wrapper chrony_cfg
  echo_bold "== CIS 2.2.2 Ensure X Window System not installed"
  func_wrapper rpm_not_installed xorg-x11-server-common
  echo_bold "== CIS 2.2.3-17 Ensure unused services not enabled"
  func_wrapper check_svc_not_enabled rsyncd
  func_wrapper check_svc_not_enabled avahi-daemon
  func_wrapper check_svc_not_enabled snmpd
  func_wrapper check_svc_not_enabled squid
  func_wrapper check_svc_not_enabled smb
  func_wrapper check_svc_not_enabled dovecot
  func_wrapper check_svc_not_enabled httpd
  func_wrapper check_svc_not_enabled vsftpd
  func_wrapper check_svc_not_enabled named
  func_wrapper check_svc_not_enabled nfs
  func_wrapper check_svc_not_enabled rpcbind
  func_wrapper check_svc_not_enabled slapd
  func_wrapper check_svc_not_enabled dhcpd
  func_wrapper check_svc_not_enabled cups
  func_wrapper check_svc_not_enabled ypserv
  echo_bold "== CIS 2.2.18 Ensure MTA is configured local-only (TODO)"

  echo_bold "== CIS 2.3.1-3 Ensure unused services not installed"
  func_wrapper rpm_not_installed ypbind
  func_wrapper rpm_not_installed telnet
  func_wrapper rpm_not_installed openldap-clients

  #func_wrapper check_umask 
  #func_wrapper check_def_tgt

  echo_bold "== CIS 3.1.1 Ensure IP forwarding disabled"
  func_wrapper chk_sysctl net.ipv4.ip_forward 0
  echo_bold "== CIS 3.1.2 Ensure packet redirect sending disabled"
  func_wrapper chk_sysctl net.ipv4.conf.all.send_redirects 0
  func_wrapper chk_sysctl net.ipv4.conf.default.send_redirects 0

  echo_bold "== CIS 3.2.1 Ensure packet redirect sending disabled"
  func_wrapper chk_sysctl net.ipv4.conf.all.accept_source_route 0
  func_wrapper chk_sysctl net.ipv4.conf.default.accept_source_route 0

  echo_bold "== CIS 3.2.2 Ensure ICMP redirects not accepted"
  func_wrapper chk_sysctl net.ipv4.conf.all.accept_redirects 0
  func_wrapper chk_sysctl net.ipv4.conf.default.accept_redirects 0

  echo_bold "== CIS 3.2.3 Ensure secure ICMP redirects not accepted"
  func_wrapper chk_sysctl net.ipv4.conf.all.secure_redirects 0
  func_wrapper chk_sysctl net.ipv4.conf.default.secure_redirects 0

  echo_bold "== CIS 3.2.4 Ensure suspicious packets are logged"
  func_wrapper chk_sysctl net.ipv4.conf.all.log_martians 1
  func_wrapper chk_sysctl net.ipv4.conf.default.log_martians 1

  echo_bold "== CIS 3.2.5 Ensure broadcast ICMP requests ignored"
  func_wrapper chk_sysctl net.ipv4.icmp_echo_bold_ignore_broadcasts 1

  echo_bold "== CIS 3.2.6 Ensure bogus ICMP responses ignored"
  func_wrapper chk_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1

  echo_bold "== CIS 3.2.7 Ensure reverse path filtering enabled"
  func_wrapper chk_sysctl net.ipv4.conf.all.rp_filter 1
  func_wrapper chk_sysctl net.ipv4.conf.default.rp_filter 1

  echo_bold "== CIS 3.2.8 Ensure TCP SYN Cookies enabled"
  func_wrapper chk_sysctl net.ipv4.tcp_syncookies 1

  echo_bold "== CIS 3.2.9 Ensure IPv6 router advert. not accepted"
  func_wrapper ip6_router_advertisements_dis
  func_wrapper ip6_redirect_accept_dis

  echo_bold "== CIS 3.3.1-4 Ensure DCCP, SCTP, RDS and TIPC disabld"
  func_wrapper chk_cis_cnf dccp ${CIS_CNF}
  func_wrapper chk_cis_cnf sctp ${CIS_CNF}
  func_wrapper chk_cis_cnf rds ${CIS_CNF}
  func_wrapper chk_cis_cnf tipc ${CIS_CNF}

  echo_bold "== CIS 3.4.1.1 Ensure a Firwall package installed"
  func_wrapper check_svc_enabled firewalld  
  echo_bold "== CIS 3.4.2.1 Ensure firwall service enabled and running" 
  func_wrapper check_svc_enabled firewalld
  echo_bold "== CIS 3.4.2.2 Ensure iptables service not enabled" 
  func_wrapper check_svc_not_enabled iptables
  echo_bold "== CIS 3.4.2.3 Ensure nftables service not enabled" 
  func_wrapper check_svc_not_enabled nftables
  echo_bold "== CIS 3.4.2.4 - 3.4.4.2.4 not checked since iptables and nftables disabled" 

  echo_bold "== CIS 3.5 Ensure WLAN disabled" 
  func_wrapper wlan_iface_disabled

  echo_bold "== CIS 3.6 Disable IPv6" 
  func_wrapper chk_sysctl net.ipv6.conf.all.disable_ipv6 1

  echo_bold "== CIS 4.1.1.1 Ensure auditd installed" 
  func_wrapper rpm_installed audit
  echo_bold "== CIS 4.1.1.2 Ensure auditd is enabled" 
  func_wrapper check_svc_enabled auditd
  echo_bold "== CIS 4.1.1.3 Ensure auditing procs start prior auditd enabled" 
  func_wrapper audit_procs_prior_2_auditd
  echo_bold "== CIS 4.1.1.4 Ensure audit_backlog_limit is sufficient" 
  func_wrapper audit_backlog_limits
  echo_bold "== CIS 4.1.2.1 Ensure audit log storage size configured" 
  func_wrapper audit_log_storage_size
  echo_bold "== CIS 4.1.2.2 Ensure audit logs are not autom. deleted" 
  func_wrapper keep_all_audit_info
  echo_bold "== CIS 4.1.2.3 Ensure system is dis. when logs are full" 
  func_wrapper dis_on_audit_log_full
  echo_bold "== CIS 4.1.3-17 Ensure events are collected" 
  func_wrapper coll_chg2_sysadm_scope
  func_wrapper audit_logins_logouts
  func_wrapper audit_session_init
  func_wrapper audit_date_time
  func_wrapper audit_sys_mac
  func_wrapper audit_network_env
  func_wrapper audit_dac_perm_mod_events
  func_wrapper unsuc_unauth_acc_attempts
  func_wrapper audit_user_group
  func_wrapper coll_suc_fs_mnts
  func_wrapper coll_priv_cmds
  func_wrapper coll_file_del_events
  func_wrapper kmod_lod_unlod
  func_wrapper coll_sysadm_actions 
  func_wrapper audit_cfg_immut

  echo_bold "== CIS 4.2.1.1 Ensure rsyslog installed" 
  func_wrapper rpm_installed rsyslog
  echo_bold "== CIS 4.2.1.2 Ensure rsyslog enabled" 
  func_wrapper check_svc_enabled rsyslog
  echo_bold "== CIS 4.2.1.3 Ensure rsyslog default file creation perms configured (TODO)" 
  echo_bold "== CIS 4.2.1.4 Ensure logging is configured"
  func_wrapper chk_file_exists ${RSYSLOG_CNF}
  echo_bold "== CIS 4.2.1.5 Ensure rsyslog is configured to send to remote host"
  func_wrapper chk_rsyslog_remote_host 
  echo_bold "== CIS 4.2.1.6 Ensure remote rsyslog messages only accepted on design. log hosts (TODO)"
  echo_bold "== CIS 4.2.2.1 Ensure journald configured to send logs to rsyslog"
  func_wrapper chk_param "${JOURNALD_CFG}" "ForwardToSyslog=yes"
  echo_bold "== CIS 4.2.2.2 Ensure journald configured to compress large logs"
  func_wrapper chk_param "${JOURNALD_CFG}" "Compress=yes"
  echo_bold "== CIS 4.2.2.3 Ensure journald configured to write logs to persist. disk"
  func_wrapper chk_param "${JOURNALD_CFG}" "Storage=persistent"

  echo_bold "== CIS 4.2.3 Ensure perms on all logs configured (TODO)"

  echo_bold "== CIS 4.3 Ensure logrotate is configured"
  func_wrapper logrotate_cfg

  echo_bold "== CIS 5.1.1 Ensure cron daemon is enabled"
  func_wrapper check_svc_enabled crond

  echo_bold "== CIS 5.1.2-7 Ensure perms for crontab files"
  for file in ${ANACRONTAB} ${CRONTAB} ${CRON_HOURLY} ${CRON_DAILY} ${CRON_WEEKLY} ${CRON_MONTHLY} ; do
    func_wrapper check_root_owns "${file}"
    func_wrapper check_file_perms "${file}" 600 
  done
  func_wrapper check_file_perms "${CRON_DIR}" 700

  echo_bold "== CIS 5.1.8 Ensure at/cron is restricted to auth. users"
  func_wrapper at_cron_auth_users

  echo_bold "== CIS 5.2.1 Ensure perms on sshd_config"
  func_wrapper check_file_perms "${SSHD_CFG}" 600 
  func_wrapper check_root_owns "${SSHD_CFG}"

  echo_bold "== CIS 5.2.2 Ensure SSH access is limited to users/groups"
  func_wrapper ssh_user_group_access
  
  echo_bold "== CIS 5.2.3 Ensure perms on SSH private host key files"
  for hostkey in /etc/ssh/ssh_host_*_key; do
    func_wrapper chk_owner_group "${hostkey}" "root:ssh_keys"
    func_wrapper check_file_perms "${hostkey}" 640
  done

  echo_bold "== CIS 5.2.4 Ensure perms on SSH public host key files"
  for pubhostkey in /etc/ssh/ssh_host_*_key.pub; do
    func_wrapper chk_owner_group "${pubhostkey}" "root:root"
    func_wrapper check_file_perms "${pubhostkey}" 644
  done

  echo_bold "== CIS 5.2.5-20 Ensure SSH options are set properly"
  func_wrapper chk_param "${SSHD_CFG}" LogLevel INFO
  func_wrapper chk_param "${SSHD_CFG}" X11Forwarding no
  func_wrapper ssh_maxauthtries 4
  func_wrapper chk_param "${SSHD_CFG}" IgnoreRhosts yes
  func_wrapper chk_param "${SSHD_CFG}" HostbasedAuthentication no
  func_wrapper chk_param "${SSHD_CFG}" Protocol 2
  func_wrapper chk_param "${SSHD_CFG}" PermitRootLogin no
  func_wrapper chk_param "${SSHD_CFG}" PermitEmptyPasswords no
  func_wrapper chk_param "${SSHD_CFG}" PermitUserEnvironment no
  func_wrapper chk_param "${SSHD_CFG}" LoginGraceTime 60
  func_wrapper chk_param "${SSHD_CFG}" ClientAliveInterval 300
  func_wrapper chk_param "${SSHD_CFG}" ClientAliveCountMax 0
  func_wrapper chk_param "${SSHD_CFG}" UsePAM yes
  func_wrapper chk_param "${SSHD_CFG}" AllowTcpForwarding no
  func_wrapper chk_param "${SSHD_CFG}" MaxStartups 10:30:60
  func_wrapper chk_param "${SSHD_CFG}" Ciphers aes128-ctr,aes192-ctr,aes256-ctr
  func_wrapper chk_param "${SSHD_CFG}" Banner /etc/issue.net

  echo_bold "== CIS 5.3.1 Ensure custom authselect profile (TODO)"
  echo_bold "== CIS 5.3.2 Ensure authselect profile (TODO)"
  echo_bold "== CIS 5.3.3 Ensure authselect includes faillock"
  func_wrapper failed_pass_lock
  echo_bold "== CIS 5.4.1 Ensure password creation req. configured"
  func_wrapper pass_req_params 
  echo_bold "== CIS 5.4.2 Ensure lockout for failed password attempts (TODO)"
  echo_bold "== CIS 5.4.3 Ensure password reuse is limited"
  func_wrapper remember_passwd 
  echo_bold "== CIS 5.4.4 Ensure password hashing algo is SH512"
  func_wrapper pass_hash_algo sha512

  echo_bold "== CIS 5.5.1.1-3 Ensure password expiration"
  func_wrapper chk_param "${LOGIN_DEFS}" PASS_MAX_DAYS 90
  func_wrapper chk_param "${LOGIN_DEFS}" PASS_MIN_DAYS 7
  func_wrapper chk_param "${LOGIN_DEFS}" PASS_WARN_AGE 7

  echo_bold "== CIS 5.5.1.4 Ensure inactive password lock 30 days"
  func_wrapper inactive_usr_acs_locked
  echo_bold "== CIS 5.5.1.5 Ensure all users last pwd change date is in past (TODO)"
  echo_bold "== CIS 5.5.2 Ensure sys accounts are secured"
  func_wrapper dis_sys_accs
  echo_bold "== CIS 5.5.3 Ensure shell timeout is 900 (TODO)"
  echo_bold "== CIS 5.5.4 Ensure default group for root is GID 0"
  func_wrapper root_def_grp
  echo_bold "== CIS 5.5.5 Ensure default user umask 027"
  func_wrapper def_umask_for_users 

  echo_bold "== CIS 5.6 Ensure root login restrict to system console"
  func_wrapper chk_file_not_exists "${SECURETTY_CFG}"

  echo_bold "== CIS 5.7 Ensure acces to su command restricted"
  func_wrapper su_access

  echo_bold "== CIS 6.1.1 Audit system file perms (TODO)"
  echo_bold "== CIS 6.1.2-9 Ensure perms on passwd, group and shadow files"
  func_wrapper check_file_perms "${PASSWD}" 644 
  func_wrapper check_file_perms "${SHADOW}" 0
  func_wrapper check_file_perms "${GSHADOW}" 0 
  func_wrapper check_file_perms "${GROUP}" 644 
  for file in ${PASSWD} ${SHADOW} ${GSHADOW} ${GROUP} ; do
    func_wrapper check_root_owns "${file}"
  done

  echo_bold "== CIS 6.1.10 Ensure no world writable files exist"
  func_wrapper world_w_dirs
  
  echo_bold "== CIS 6.1.11 Ensure no unowned files exist"
  func_wrapper unowned_files

  echo_bold "== CIS 6.1.12 Ensure no ungrouped files exist"
  func_wrapper ungrouped_files

  echo_bold "== CIS 6.1.13 Audit SUID executables"
  func_wrapper suid_exes
  echo_bold "== CIS 6.1.13 Audit SGID executables"
  func_wrapper sgid_exes

  echo_bold "== CIS 6.2.1 Ensure password fields not empty"
  func_wrapper passwd_field_chk

  echo_bold "== CIS 6.2.2,4,5 Ensure no legacy entries in passwd, shadow and group"
  func_wrapper nis_in_file ${PASSWD}
  func_wrapper nis_in_file ${SHADOW}
  func_wrapper nis_in_file ${GROUP}

  echo_bold "== CIS 6.2.3 Ensure root PATH integrity"
  func_wrapper root_path

  echo_bold "== CIS 6.2.6 Ensure root only uid0"
  func_wrapper no_uid0_other_root

  echo_bold "== CIS 6.2.7 Ensure users home dirs resticted"
  func_wrapper home_dir_perms

  echo_bold "== CIS 6.2.8 Ensure users home dirs owned"
  func_wrapper chk_home_dirs_owns

  echo_bold "== CIS 6.2.9 Ensure users dot files not group/world writeable"
  func_wrapper dot_file_perms

  echo_bold "== CIS 6.2.10,11,13 Ensure users not have .forward .rhosts files"
  func_wrapper user_dot_forward 
  func_wrapper user_dot_netrc 
  func_wrapper dot_rhosts_files

  echo_bold "== CIS 6.2.12 Ensure users .netrc perms"
  func_wrapper dot_netrc_perms
  
  echo_bold "== CIS 6.2.14 Ensure group in passwd exist in group"
  func_wrapper chk_groups_passwd

  echo_bold "== CIS 6.2.15 Ensure no duplicate UIDs"
  func_wrapper duplicate_uids

  echo_bold "== CIS 6.2.16 Ensure no duplicate GIDs"
  func_wrapper duplicate_gids

  echo_bold "== CIS 6.2.17 Ensure no duplicate user names"
  func_wrapper duplicate_usernames

  echo_bold "== CIS 6.2.18 Ensure no duplicate group names"
  func_wrapper duplicate_groupnames

  echo_bold "== CIS 6.2.19 Ensure shadow group is empty (TODO)"

  echo_bold "== CIS 6.2.20 Ensure all users home dir exist"
  func_wrapper chk_home_dirs_exist
}

function summary {
  # SUMUP
  echo "==============================================================="
  echo ""
  echo "Total $TOTAL checks: $PASS passed / $FAILED failed ($(expr $FAILED \* 100 / $TOTAL)%)"
}

main
summary
