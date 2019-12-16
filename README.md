# RedHat 8 Lockdown

## Fork
This is a fork from https://github.com/naingyeminn/CentOS7_Lockdown  
Add some optimizations and corrections for RHEL8

## File usage
**cis-audit.sh:** A bash script to audit whether a host conforms to the CIS benchmark. Original from [Ross Hamilton](https://github.com/rosshamilton1)

**rhel8.sh:** Script based on CIS Red Hat Enterprise Linux 8 benchmark to apply hardening.

I'm not affiliated with the Center for Internet Security in any way.
Use any material from this repository at your own risk.  

## TODO
Following checks in cis-audit.sh still pending:

CIS 1.3.2 Ensure pty is set in sudoers (TODO)"
CIS 1.3.3 Ensure logfile is set in sudoers (TODO)"
CIS 1.5.3 Ensure auth for single user mode (TODO)"
CIS 2.2.18 Ensure MTA is configured local-only (TODO)"
CIS 4.2.1.3 Ensure rsyslog default file creation perms configured (TODO)" 
CIS 4.2.1.6 Ensure remote rsyslog messages only accepted on design. log hosts (TODO)"
CIS 4.2.3 Ensure perms on all logs configured (TODO)"
CIS 5.3.1 Ensure custom authselect profile (TODO)"
CIS 5.3.2 Ensure authselect profile (TODO)"
CIS 5.4.2 Ensure lockout for failed password attempts (TODO)"
CIS 5.5.1.5 Ensure all users last pwd change date is in past (TODO)"
CIS 5.5.3 Ensure shell timeout is 900 (TODO)"
CIS 6.1.1 Audit system file perms (TODO)"
CIS 6.2.19 Ensure shadow group is empty (TODO)"
