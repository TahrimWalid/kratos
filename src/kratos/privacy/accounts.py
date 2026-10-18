"""Which account names are people, which are the system's, and which are an attacker's guesses.

* System accounts are never masked: they say nothing about a person and the analysis
  needs them (`root`, `www-data`, `sshd`, ...). When the machine's account list is known,
  its UIDs decide (below 1000, and `nobody`, are system); this fixed list covers the rest.
* Names an attacker tried that don't exist on the machine (`Invalid user admin`) are a
  dictionary attack, not people: in standard mode the common dictionary names below stay
  readable, any other nonexistent name becomes `INVALID_USER_n`.
"""
from __future__ import annotations

import re

SYSTEM_ACCOUNTS = frozenset("""
root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody nogroup
systemd-network systemd-resolve systemd-timesync systemd-coredump systemd-oom systemd-journal-remote
messagebus syslog _apt tss uuidd tcpdump sshd landscape pollinate fwupd-refresh usbmux dnsmasq avahi
avahi-autoipd polkitd rtkit colord chrony _chrony ntp ntpsec postfix dovecot dovenull mysql redis nginx
apache httpd named bind unbound lxd ftp adm operator halt shutdown sddm gdm lightdm cups-pk-helper saned
kernoops whoopsie geoclue pulse speech-dispatcher hplip nm-openvpn _rpc statd rpc rpcuser Debian-exim
Debian-snmp sssd nscd dhcpcd _laurel clamav ossec wazuh zabbix prometheus node_exporter grafana
elasticsearch kibana logstash opensearch postgres mongodb memcache rabbitmq haproxy squid bind9 tor
_flatpak flatpak openldap ldap netdata snmp vnstat lldpd smmsp mailnull dbus gluster ceph libvirt-qemu
libvirt-dnsmasq qemu kvm docker containerd incus-admin _sshd sshd-session systemd-network-wait
""".split())

# Common names in SSH dictionary attacks (the guesses, not people). Kept readable in standard
# mode ONLY when the machine has no such account -- an existing "admin" is always masked.
DICTIONARY_NAMES = frozenset("""
admin administrator adm test test1 test2 testuser tester testing user user1 user2 guest oracle ubuntu
postgres mysql ftpuser ftp git pi support info demo centos ec2-user debian deploy dev developer devops
hadoop jenkins minecraft nagios steam tomcat www web webmaster webadmin zabbix ansible vagrant docker
kafka elastic redis student teamspeak ts3 server service backup apache operator manager sales office
system sysadmin root1 toor mother master default temp tmp anonymous ubnt pos sa db dbadmin odoo
gitlab wordpress wp mail postfix nginx httpd azureuser azure cloud cloud-user opc fedora rocky alma
ansadmin hduser hdfs spark solr nexus sonar runner gitlab-runner bitnami
""".split())

# The login a cloud or OS image creates for everyone ("ubuntu" on Ubuntu images, "ec2-user"
# on Amazon Linux): it names the image, not a person, and "ubuntu" is also the OS id the
# package check reads (ID=ubuntu). Readable in standard mode; strict masks it.
IMAGE_DEFAULT_ACCOUNTS = frozenset("""
ubuntu ec2-user centos debian fedora cloud-user azureuser opc rocky almalinux alpine arch vagrant pi
""".split())

FIRST_HUMAN_UID = 1000
_NOBODY_UID = 65534
# A Linux login name: what useradd accepts, plus the dots and $ that Samba/AD names carry.
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$-]{0,31}$")
MIN_LEN = 3          # shorter names are masked only in strict mode (they hide inside other words)


def is_system(name: str, uid: int | None = None) -> bool:
    if uid is not None:
        return uid < FIRST_HUMAN_UID or uid == _NOBODY_UID
    return name in SYSTEM_ACCOUNTS


def plausible_name(name: str) -> bool:
    return bool(NAME_RE.match(name)) and not name.replace(".", "").replace("-", "").isdigit()
