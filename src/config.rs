//! Site constants. Edit here, rebuild.
pub const WORK_DIR: &str = "/run/paranoia";
pub const WANT_CIDR: &str = "172.20.240.15/24";
pub const WANT_NET: &str = "172.20.240.0/24";
pub const WANT_GW: &str = "172.20.240.254";
pub const WANT_DNS: &str = "9.9.9.9";
pub const AD_IP: &str = "172.20.240.100";
pub const AD_EXTRA_NAMES: &[&str] = &["ccdc.net"];
pub const LOCAL_ADMIN_ACCOUNTS: &[&str] = &["root", "sysadmin"];
pub const PURGE_PACKAGES: &[&str] = &[
    "telnet", "telnetd", "inetutils-telnetd", "telnetd-ssl", "rsh-client", "rsh-server",
    "rsh-redone-client", "rsh-redone-server", "xinetd", "openbsd-inetd", "inetutils-inetd",
    "tftpd", "tftpd-hpa", "atftpd", "vsftpd", "proftpd-basic", "pure-ftpd", "netcat",
    "netcat-openbsd", "netcat-traditional", "ncat", "socat", "tmate", "autossh", "sshfs",
    "tightvncserver", "x11vnc", "tigervnc-standalone-server", "tigervnc-scraping-server",
    "vino", "xrdp", "cockpit", "webmin", "samba", "nfs-kernel-server", "snmpd", "openvpn",
    "teamviewer", "anydesk",
];
// Fixes weakness 13: script only opened 22,25,80,110,143.
pub const ALLOWED_TCP: &[u16] = &[22, 25, 80, 110, 143, 443, 465, 587, 993, 995];
/// Auth-related packages verified in preflight.
pub const AUTH_PACKAGES: &[&str] = &["libpam-modules", "libpam-modules-bin", "libpam-runtime", "libpam0g", "libpam-krb5", "libpam-sss", "sudo", "login", "passwd", "openssh-server"];
pub const PAM_DIRS: &[&str] = &["/usr/lib/x86_64-linux-gnu/security", "/usr/lib/aarch64-linux-gnu/security", "/usr/lib/security", "/lib/security"];
pub const TTY_SNIFFERS: &[&str] = &["script", "ttyrec", "ttysnoop", "logkeys", "lkl", "keylogger"];
pub const APT_OPTS: &[&str] = &["-y", "-o", "DPkg::Lock::Timeout=1800", "-o", "Dpkg::Options::=--force-confold",
    "-o", "Acquire::Retries=0", "-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30"];
pub const REMOTE_UNITS: &[&str] = &["telnet.socket", "telnetd", "xinetd", "inetd", "vsftpd", "proftpd", "pure-ftpd", "tftpd-hpa",
    "smbd", "nmbd", "nfs-server", "snmpd", "xrdp", "vncserver", "x11vnc", "cockpit.socket", "cockpit", "webmin", "openvpn",
    "teamviewerd", "anydesk", "tmate", "autossh"];
pub const REMOTE_BINS: &[&str] = &["nc", "ncat", "netcat", "socat", "telnet", "tmate", "rsh", "rlogin", "rcp", "x11vnc", "vncserver",
    "xrdp", "anydesk", "teamviewer"];
pub const SCORED_SNAP_REGEX: &[&str] = &["postfix", "dovecot", "roundcube", "ssh", "krb5", "kerberos", "sssd", "php", "apache", "nginx", "mysql", "mariadb", "postgres"];
/// Packages worth a targeted security upgrade (prefix match). Other pending -security updates are only listed.
pub const THREAT_PREFIXES: &[&str] = &["linux-image", "linux-modules", "linux-headers", "linux-generic", "openssh", "openssl", "libssl", "sudo",
    "polkit", "pkexec", "libpolkit", "policykit", "libc6", "libc-bin", "systemd", "libsystemd", "udev", "libudev", "dbus", "libpam", "libnss",
    "libldap", "libsasl2", "libkrb5", "krb5", "libgssapi", "sssd", "postfix", "dovecot", "php", "libapache2-mod-php", "apache2", "nginx",
    "roundcube", "mariadb", "mysql", "libsqlite", "sqlite", "libcurl", "curl", "libxml2", "libexpat", "zlib1g", "libgnutls", "gnutls",
    "libgcrypt", "gnupg", "bash", "util-linux", "mount", "libmount", "login", "passwd", "libcap", "libseccomp", "git", "python3", "perl",
    "libperl", "vim", "tar", "cpio", "needrestart", "grub", "shim", "ca-certificates", "apt", "libapt"];
pub const BOOT_PREFIXES: &[&str] = &["grub", "shim", "linux-image", "linux-modules"];
pub const SCHED_PKGS: &[&str] = &["cron", "cron-daemon-common", "anacron", "at", "bcron", "bcron-run", "fcron", "dcron", "cronie", "incron", "systemd-cron", "cron-apt"];
pub const SCHED_SCORED: &[&str] = &["postfix", "dovecot", "roundcube", "ssh", "krb5", "kerberos", "sssd", "php", "apache", "nginx", "mysql", "mariadb", "postgres", "libpam", "sudo", "ldap", "nftables", "fish"];
pub const SCHED_PATHS: &[&str] = &["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.yearly",
    "/etc/cron.allow", "/etc/cron.deny", "/etc/anacrontab", "/etc/at.allow", "/etc/at.deny", "/etc/incron.d", "/etc/incron.allow", "/etc/incron.deny",
    "/etc/incron.conf", "/etc/fcron", "/etc/fcrontab", "/etc/fcron.conf", "/etc/fcron.allow", "/etc/fcron.deny", "/var/spool/cron", "/var/spool/at",
    "/var/spool/anacron", "/var/spool/incron", "/var/spool/fcron"];
pub const SCHED_UNITS: &[&str] = &["cron", "crond", "atd", "anacron", "anacron.timer", "fcron", "bcron", "incron", "incrond", "cronie"];
pub const SCHED_BINS: &[&str] = &["crontab", "at", "atq", "atrm", "batch", "atd", "cron", "crond", "anacron", "fcron", "fcrontab", "incrond", "incrontab"];
/// Weakness 14: these timers survive (masking ALL timers killed logrotate and friends).
pub const KEEP_TIMERS: &[&str] = &["logrotate.timer", "systemd-tmpfiles-clean.timer", "fstrim.timer"];
pub const CRITICAL_PACKAGES: &[&str] = &["openssh-server", "openssh-client", "openssh-sftp-server", "sudo", "login", "passwd", "util-linux", "coreutils",
    "bash", "libc6", "apt", "dpkg", "libpam-modules", "libpam-modules-bin", "libpam-runtime", "libpam0g", "libpam-krb5", "libpam-sss", "libnss-sss",
    "krb5-user", "libkrb5-3", "sssd", "sssd-common", "postfix", "postfix-ldap", "dovecot-core", "dovecot-imapd", "dovecot-pop3d", "dovecot-ldap", "systemd", "openssl"];
/// "module", "what it mitigates". sctp_diag precedes sctp so it unloads first. Temporary (cleared on reboot).
pub const LPE_MODULES: &[(&str, &str)] = &[
    ("algif_aead", "Copy Fail CVE-2026-31431"),
    ("esp4", "Dirty Frag CVE-2026-43284, Fragnesia CVE-2026-46300, DirtyClone CVE-2026-43503"),
    ("esp6", "Dirty Frag CVE-2026-43284, Fragnesia CVE-2026-46300, DirtyClone CVE-2026-43503"),
    ("rxrpc", "Dirty Frag CVE-2026-43500"),
    ("rds", "PinTheft CVE-2026-43494"),
    ("act_pedit", "pedit COW CVE-2026-46331"),
    ("ah6", "DirtyAH6 CVE-2026-80844"),
    ("tun", "TUNderflow CVE-2026-81000"),
    ("pppoe", "PPPoEject CVE-2026-68121"),
    ("ksmbd", "kernel SMB server RCE flaws, Oct 2026 (precaution)"),
    ("sctp_diag", "DiagSpill CVE-2026-74469"),
    ("sctp", "DiagSpill CVE-2026-74469"),
];
/// Paths a legitimate process never runs from.
pub const SUSPECT_EXE_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/"];
