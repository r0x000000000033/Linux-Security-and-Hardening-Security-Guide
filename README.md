<h2 align="center"><code>Linux Security and Hardening Security Guide</code></h2>

@r0x000000000033

### Table of Contents:

- [Password Bootloader GRUB](#password-bootloader-grub)
- [Disable reboot using Ctrl-Alt-Del Keys](#disable-reboot-using-ctrl-alt-del-keys)
- [DNSCrypt](#dnscrypt)
- [Sandboxing](#sandboxing)
- [Lockdown Cronjobs](#lockdown-cronjobs)
- [HidePID](#hidepid)
- [MAC (Mandatory Access Control)](#mac-mandatory-access-control)
  - [Exemples of implementations](#exemples-of-implementations)
- [Security SSH](#security-ssh)
  - [Change default port](#change-default-port)
  - [Blocking root login](#blocking-root-login)
  - [Define unique users to login](#define-unique-users-to-login)
  - [Authentication via RSA public key](#authentication-via-rsa-public-key)
  - [TCP Wrappers: Allowing connections from specific hosts](#tcp-wrappers-allowing-connections-from-specific-hosts)
- [Pam_Tally2](#pam_tally2-block-user-after-n-number-of-incorrect-login-attempts)
- [Port Knocking](#port-knocking)
- [RootKits and Malwares Analyzis](#rootkits-and-malwares-analyzis)
- [FireWall](#firewall)
- [Full Disk Encryption](#full-disk-encryption)
- [Security Server Apache](#security-server-apache)
  - [Apache modules](#apache-modules)
  - [Disable Directory Listing](#disable-directory-listing)
  - [TRACE Method](#trace-method)
  - [Mod_Security](#mod_security)
- [Security FTP](#security-ftp-file-transfer-protocol)
  - [ProFTPD + TLS](#proftpd--tls)
  - [Creating Shellless User Login](#creating-shellless-user-login)
  - [ProFTPD: Allow only specific users to login](#proftpd-allow-only-specific-users-to-login)
- [Listening Ports](#listening-ports)
- [Security Auditing Tools Open Source](#security-auditing-tools-open-source)
  - [NIDS/IPS](#nids-network-intrusion-detection-system-and-ips-intrusion-prevention-systems)
  - [HIDS](#hids-host-based-intrusion-detection-system)

### Introduction

> Hardening is a process of mapping threats, mitigating risks and executing corrective activities, focusing on infrastructure and the main objective of making it prepared to face attack attempts.
> This documentation presents a series of tips and recommendations to improve the security of any Linux distribution.

### Password Bootloader GRUB

1. Using `grub2-setpassword`:

- [x] RHEL8/CentOS8
- [ ] Debian

```shell
# Set Password:
grub2-setpassword

# File containing the password hash:
cat /boot/grub2/user.cfg 
GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.[...]

# Remove –unrestricted from the main CLASS= declaration in /etc/grub.d/10_linux file:
sed -i "/^CLASS=/s/ --unrestricted//" /etc/grub.d/10_linux

# Recreate the grub config with grub2-mkconfig and reboot:
grub2-mkconfig -o /boot/grub2/grub.cfg
reboot
```

2. Using `grub2-mkpasswd-pbkdf2`:

- [x] RHEL8/CentOS8
- [x] Debian

```shell
# Set password and copy the encrypted password hash:

# RHEL8/CentOS8
grub2-mkpasswd-pbkdf2
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.[...]

# Debian-based:
grub-mkpasswd-pbkdf2
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.[...]

# It is not recommended to edit the grub.cfg file directly (/boot/grub2/grub.cfg).
# We can configure GRUB2 Bootloader by modifying the files in the /etc/grub.d/ directory without having to modify the main file.
# Edit the file /etc/grub.d/40_custom and add:
set superusers="root"
password_pbkdf2 root <password-hash>

# Recreate the grub config with grub2-mkconfig and reboot:

# RHEL8/CentOS8:
grub2-mkconfig -o /boot/grub2/grub.cfg

# Debian-based:
grub-mkconfig -o /boot/grub/grub.cfg

reboot
```
Remove GRUB password:
```shell
# RHEL8/CentOS8:
rm -f /boot/grub2/user.cfg

# Debian-based:
grub-mkconfig -o /boot/grub/grub.cfg
```

### Disable reboot using Ctrl-Alt-Del Keys

- [x] RHEL8/CentOS8
- [x] Debian

[masking](https://fedoramagazine.org/systemd-masking-units/) is a feature of systemd to prevent service activation

```shell
systemctl mask ctrl-alt-del.target

# or:
ln -s /dev/null /usr/lib/systemd/system/ctrl-alt-del.target

# Check if it's masked:
systemctl list-unit-files --type target | grep ctrl

# Removed mask:
systemctl unmask ctrl-alt-del.target
```

### DNSCrypt

- [x] Installation OS-specific: https://github.com/jedisct1/dnscrypt-proxy/wiki/installation

Protocol created by OpenBSD that authenticates communications between a client and a DNS resolver. It encapsulates through a secure channel to improve security and prevent DNS spoofing. Uses cryptographic signatures to verify that responses originate from the chosen DNS resolver and have not been tampered with.

```Shell
apt install dnscrypt-proxy
```

Enter your preferred DNS Server, below a list of supported servers.
- [Public DNS Servers](https://dnscrypt.info/public-servers)

Another way to check DNS servers:
```Shell
Local: /var/cache/dnscrypt-proxy/public-resolvers.md
```

Edit dnscrypt-proxy.toml and add the server of your choice:
```Shell
# Edit the file /etc/dnscrypt-proxy/dnscrypt-proxy.toml:
server_names = ['cloudflare']
```

For dnscrypt-proxy to work, you need to configure DNS locally for - 127.0.0.1 or 127.0.2.1 (Debian/Ubuntu).

To know which one to use, check which listen the socket is using:
```Shell
cat /lib/systemd/system/dnscrypt-proxy.socket | grep ListenDatagram
```

Then add localhost:
```Shel
# Edit the file /etc/resolv.conf:
nameserver 127.0.2.1
```

Started dnscrypt-proxy:
```Shell
systemctl start dnscrypt-proxy.service
```

Checking active service:
```Shell
ss -lp 'sport = :domain'
```

### Sandboxing

Security mechanism to separate running programs from an end of supply to a highly controlled and secure environment.

- Exemples of implementations:

  - [Firejail](https://firejail.wordpress.com/)
  - [Bubblewrap](https://github.com/containers/bubblewrap)
  - [Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
  - [Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)

### Lockdown Cronjobs

- [x] RHEL8/CentOS8
- [x] Debian-based

```shell
# Block all users:
echo ALL >> /etc/cron.deny

# Release specific users to access cron:
echo "<user>" >> /etc/cron.allow
```

### HidePID

- [x] RHEL8/CentOS8
- [x] Debian-based

>By default, all local users are allowed to have access to other users' PID and process information.
```
hidepid=0: Allowed for all users
hidepid=1: Remain visible but not accessible for all users.
hidepid=2: hidden to all users.
```
```Shell
# Add in /etc/fstab:
proc	/proc	proc	defaults,hidepid=2  0   0

# Checking:
ls -ld /proc/[0-9]*
ps -aux
top
```

### MAC (Mandatory Access Control)

MAC is based on a hierarchical model. The hierarchy is based on security level. All users are assigned a security or clearance level. All objects are assigned a security label. Users can only access resources that correspond to a security level equal to or lower than theirs in the hierarchy.

In a MAC model, access is controlled strictly by the administrator. The administrator sets all permissions. Users cannot set their own permissions, even if they own the object. Because of this, MAC systems are considered very secure. This is because of the centralized administration. Centralized administration makes it easier for the administrator to control who has access to what. The administrator doesn’t have to worry about someone else setting permissions improperly. Because of the high-level security in MAC systems, MAC access models are often used in government systems.

#### Exemples of implementations:
  - [SELinux](https://selinuxproject.org/page/Main_Page)
  - [Tomoyo](https://tomoyo.osdn.jp/)
  - [AppArmor](https://apparmor.net/)

### Security SSH

- [x] RHEL8/CentOS8
- [x] Debian-based

#### Change default port
>By default, SSH listens on port 22, it is recommended to switch to a high port to make discovering ssh difficult with portscanner.
The maximum value given to a door is 65536
```Shell
# Edit the file /etc/ssh/sshd_config:
[...]
  Port 2222
[...]
```

#### Blocking root login
```
# Edit the file /etc/ssh/sshd_config:
[...]
  # Authentication:
  Permitrootlogin no
[...]
```

#### Define unique users to login
```
# Edit the file /etc/ssh/sshd_config:
[...]
  AllowUsers <user>
[...]
```

#### Authentication via RSA public key
>RSA (Rivest-Shamir-Adleman) is the algorithm used for the SSH protocol version 2.
```Shell
# generating the key
ssh-keygen -t rsa

# Copy key to customers:
ssh-copy-id <user>@<host>

# Enable key authentication:
/etc/ssh/sshd_config
[...]
  PubkeyAuthentication yes
[...]
```

#### TCP Wrappers: Allowing connections from specific hosts

> By default, TCP Wrappers first consult the /etc/hosts.deny file to see which hosts cannot access which service. Then, consult the /etc/hosts.allow file to see if there are any rules that allow certain hosts to connect to specific services.
```Shell
# Edit the file /etc/hosts.deny and add:
sshd: ALL

# This means that, by default, all hosts are prohibited from accessing the SSH service.
# Create rule to authorize only specific hosts:
# Edit the file /etc/hosts.deny and add:
sshd: 192.168.1.2
```

#### [pam_tally2](https://man7.org/linux/man-pages/man8/pam_tally2.8.html): Block user after N number of incorrect login attempts

unlock_time: Blocking time.
even_deny_root: Policy is also apply to root user.
deny: Block by N number of retries.
file: failure logs


- [x] RHEL8/CentOS8
```Shell
# Edit the file /etc/pam.d/system-auth
[...]
	auth        required      pam_tally2.so deny=2 unlock_time=60
[...]
	account     required      pam_tally2.so
```

- [x] Debian-based
```Shell
# Edit the file /etc/pam.d/common-auth.
# add the following line before the start of the configuration blockto make it the first configuration item.
auth          required      pam_tally2.so file=/var/log/tallylog even_deny_root deny=2 unlock_time=900
```

Check if SSH daemon is using PAM module:
```Shell
sshd -T | grep -E "(challenge|pam)"

usepam yes
challengeresponseauthentication no
```

Restart service `ssh`:
```Shell
systemctl restart sshd
```

View the count of login attempts:
```Shell
pam_tally2 --user <user>

Login           Failures Latest failure     From
<user>          6    yy/xx/ww 00:00:00  <IP-Address>
```
Unblock user:
```Shell:
pam_tally2 --reset --user <user>
```

### Port Knocking
  - [FWKnop](https://www.cipherdyne.org/fwknop/) (FireWall KNock OPerator): implements [SPA (Single Packet Authorization)](https://www.cipherdyne.org/fwknop/docs/SPA.html)
  - [Knockd](https://linux.die.net/man/1/knockd)

### RootKits and Malwares Analyzis
  - [CHKRootKit](http://www.chkrootkit.org/)
  - [Rkhunter](http://rkhunter.sourceforge.net/)
  - [Lynis](https://cisofy.com/lynis/)
  - [ClamAV](https://www.clamav.net/)
  - [LMD](https://www.rfxn.com/projects/linux-malware-detect/) (Linux Malware Detect)

### FireWall
  - [IPTables](https://ipset.netfilter.org/iptables.man.html)
  - [FirewallD](https://firewalld.org/)
  - [NFTables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)

### Full Disk Encryption

```Shell
# Benchmark Encryption:
cryptsetup benchmark
```
- [Cryptsetup](https://gitlab.com/cryptsetup/cryptsetup/): LUKS(Linux Unified Key Setup) + DM-Crypt(Back-end)

### Security Server Apache

#### Apache modules

Minimalize your apache web server, disabling unnecessary modules

- [x] RHEL8/CentOS8
```Shell
# List all modules:
httpd -t -D DUMP_MODULES
apachectl -M

# Directory of all modules:
ls /etc/httpd/modules
ls /usr/lib64/httpd/modules
```

Enable/Disable Modules:
```Shell
# Comment the lines 'LoadModule':
/etc/httpd/conf.modules.d/00-base.conf
[...]
  #LoadModule buffer_module modules/mod_buffer.so
  #LoadModule watchdog_module modules/mod_watchdog.so
[...]
# Checking:
apachectl restart
apachectl -M | grep <module>
```

- [x] Debian-based
```Shell
# List all modules:
apachectl -M
apachectl -t -D DUMP_MODULES
a2query -m

# Directory of all modules:
/etc/apache2/mods-available/
/etc/apache2/mods-available/enabled/
```

Enable/Disable Modules:

```Shell
# Enabled:
a2enmod <module>

# Disabled:
a2dismod <module>

# Check modules status:
a2query -m rewrite
```

#### Disable Directory Listing:
>List of directories activated on websites can leave important files to the public
With dorks it is possible to search for sites with this setting enabled in apache.

`:.com.br "index of"`

`:.gov.br "index of"`

Disabled:
```Shell
# Remove 'Indexes' to disable.

# RHEL8/CentOS8
# Edit the file /etc/httpd/conf/httpd.conf:

# Debian-based:
# Edit the file /etc/apache2/apache2.conf:

[...]
<Directory "/var/www/html">
       		Options FollowSymLinks
</Directory>
[...]
```

#### TRACE Method
[Cross-Site Tracing (XST)](https://owasp.org/www-community/attacks/Cross_Site_Tracing) attacks, can steal sensitive header and cookie information on any domain with support for the [HTTP TRACE](https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Methods/TRACE) method.

Test the TRACE Method on the web server:
```Shell
curl -i -X TRACE http://<IP>/
```
Disabled
```
# RHEL8/CentOS8
# Edit the file /etc/httpd/conf/httpd.conf

# Debian-based:
# Edit the file /etc/apache2/conf-enabled/security.conf:

TraceEnable off
```

#### [Mod_Security](https://modsecurity.org/)

- [x] RHEL8/CentOS8

```
Config:/etc/httpd/conf.d/mod_security.conf
Debug Log: /var/log/httpd/modsec_debug.log
Audit log: /var/log/httpd/modsec_audit.log
Rules: /etc/httpd/modsecurity.d/activated_rules
```

> mod_security_crs: Provide basic rules for mod_security
```Shell
dnf install httpd mod_security mod_security_crs
```

- [x] Debian-based:
```Shell
apt install libapache2-mod-security2 -y
```

Configure ModSecurity:
```Shell
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Edit the file /etc/modsecurity/modsecurity.conf:
SecRuleEngine On
```

[OWASP ModSecurity Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset):

```Shell
git clone https://github.com/coreruleset/coreruleset
cd coreruleset/
mv rules/ /etc/modsecurity/
```

Restart service apache:
```Shell
# RHEL8/CentOS8
systemctl restart httpd

# Debian-based:
systemctl restart apache2
```

Check if the ModSecurity module was loaded in Apache:
```Shell
# Verify that the firewall is working:
# RHEL8/CentOS8
tail /var/log/httpd/error.log | grep ModSecurity

# Debian-based:
tail /var/log/apache2/error.log | grep ModSecurity

[:notice] [pid 1601] ModSecurity: APR compiled version="1.4.8"; loaded version="1.4.8"
[:notice] [pid 1601] ModSecurity: PCRE compiled version="8.32 "; loaded version="8.32 2012-11-30"
[:notice] [pid 1601] ModSecurity: LUA compiled version="Lua 5.1"
[:notice] [pid 1601] ModSecurity: LIBXML compiled version="2.9.1"
[:notice] [pid 1601] ModSecurity: Status engine is currently disabled, enable it by set SecStatusEngine to On.
```

### Security FTP (File Transfer Protocol)

- [x] RHEL8/CentOS8
- [x] Debian-based

#### ProFTPD + TLS
```Shell
# RHEL8/CentOS8
dnf install -y openssl

# Debian-based
apt install -y openssl
```
Generating certificate:
```Shell
openssl req -x509 -nodes -newkey rsa:1024 -keyout /etc/pki/tls/certs/proftpd.pem -out /etc/pki/tls/certs/proftpd.pem

# Edit the file /etc/sysconfig/proftpd for enabled:
PROFTPD_OPTIONS="-DTLS"
```

#### Creating Shellless User Login
```Shell
# Edit the file /etc/shells and add:
/bin/false

# Create user:
useradd <user> -s /bin/false
passwd <user>
```

#### ProFTPD: Allow only specific users to login

> AllowUser: User permission
DenyAll: Deny all

```Shell
# Edit the file /etc/proftpd.conf

<Limit LOGIN>
    AllowUser <user>
    DenyAll
</Limit>
```

### Listening Ports

- [x] RHEL8/CentOS8
- [x] Debian-based

>It is important to check for open ports to identify system intruders that open doors for backdoor, malware or to receive outside input

Checking with [netstat](https://man7.org/linux/man-pages/man8/netstat.8.html):
```Shell
netstat -tulpn
netstat -anp | grep <ip>
```
Checking with [ss](https://man7.org/linux/man-pages/man8/ss.8.html)
```Shell
ss -tulpn
```
Checking with [nmap](https://nmap.org/):
```Shell
nmap -sT -O localhost
```
Identify ports:
```Shell
cat /etc/services | grep <port>
```
Information about a port with [lsof](https://man7.org/linux/man-pages/man8/lsof.8.html):
```Shell
lsof -i | grep <port>
```

### Security Auditing Tools Open Source

  - [Lynis](https://cisofy.com/lynis/)
  
#### NIDS (Network Intrusion Detection System) and IPS (Intrusion Prevention Systems):
 
  - [Snort](https://www.snort.org/)
  - [Suricata](https://suricata-ids.org/)
  - [Sguil](http://bammv.github.io/sguil/index.html)
  - [OpenWIPS-ng](https://openwips-ng.org/)
  - [Zeek](https://zeek.org/)
 
#### HIDS (Host-Based Intrusion Detection System):

  - [OSSEC](https://www.ossec.net/)
  - [Tripwire](https://www.tripwire.com/)
  - [wazuh](https://wazuh.com/)
  - [Samhain](https://www.la-samhna.de/samhain/)

