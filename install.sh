#!/bin/bash

### Network updateSettings
interface="eth0"
ip="10.0.0.100"
netmask="255.255.255.0"
network="10.0.0.0"
broadcast="10.0.0.255"
gateway="10.0.0.1"


### Hostname and Domain Name
hostname="ispc"
domain="mydomain.com"


### SSL updateSettings
country="CH"    # Your country, 2-letter abbreviation
state="Kanton"      # Your state
city="Stadt"    # Your city
organization="Unternehmung"      # e.g. Organization, Company name or something
unit="Sektion"   # e.g. Organizational Unit, Section or something
commonname="" # Leave empty, then your FQDN will be used as sated above with hostname and domain name
email="user@mydomain.com"       # Your email address


### MySQL Settings
useUTF8="y"     # Set to 'y' run server by default as utf-8
mysqlpassword="mypassword"
bind="y"        # Set to 'y' for mysql to listen on all interfaces and not just localhost


### Apache Settings
webdav="y"      # Set to 'y' to enable WebDAV
ruby="y"        # Set to 'y' to enable ruby on webserver


### Mail Man
mailman="y"     # Set to 'y' to enable Mailman
mailmanemail="lists@mydomain.com"       # Set email of the person running the list
mailmanpassword="mypassword" 


### Jailkit
jailkit="y"     # Set to 'y' to enable Jailkit


# Detailed installation steps at http://www.howtoforge.com/perfect-server-debian-wheezy-apache2-bind-dovecot-ispconfig-3



##############################################################################
#                                                                            #
#                            BELOW BE DRAGONS                                #
#                                                                            #
##############################################################################



function updateSettings
{
        File="$1"
        Pattern="$2"
        Replace="$3"

        if grep "${Pattern}" "${File}" >/dev/null;
        then
                # Pattern found, replace line
                sed -i s/.*"${Pattern}".*/"${Replace}"/g "${File}"
                echo ""
        else
                # Pattern not found, append new
                echo "${Replace}" >> "${File}"
        fi
}



function configureNetwork
{
        echo "# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto ${interface}
iface ${interface} inet static
        address ${ip}
        netmask ${netmask}
        network ${network}
        broadcast ${broadcast}
        gateway ${gateway}" > "/etc/network/interfaces"

        echo "127.0.0.1       localhost.localdomain   localhost
${ip}   ${hostname}.${domain}     ${hostname}

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters" > "/etc/hosts"

    echo "${hostname}.${domain}" > "/etc/hostname"
    /etc/init.d/hostname.sh start

}



function preseeding
{
    echo "
dash    dash/sh boolean false
postfix postfix/root_address    string
postfix postfix/rfc1035_violation       boolean false
postfix postfix/mydomain_warning        boolean
postfix postfix/mynetworks      string  127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
postfix postfix/mailname        string  ${hostname}.${domain}
postfix postfix/tlsmgr_upgrade_warning  boolean
postfix postfix/recipient_delim string  +
postfix postfix/main_mailer_type        select  Internet Site
postfix postfix/destinations    string  ${hostname}.${domain} , localhost.mydomain.com, localhost
postfix postfix/retry_upgrade_warning   boolean
# Install postfix despite an unsupported kernel?
postfix postfix/kernel_version_warning  boolean
postfix postfix/not_configured  error
postfix postfix/sqlite_warning  boolean
postfix postfix/mailbox_limit   string  0
postfix postfix/relayhost       string
postfix postfix/procmail        boolean true
postfix postfix/bad_recipient_delimiter error
postfix postfix/protocols       select  all
postfix postfix/chattr  boolean false
mysql-server-5.5        mysql-server/root_password_again        password        ${mysqlpassword}
mysql-server-5.5        mysql-server/root_password      password        ${mysqlpassword}
mysql-server-5.5        mysql-server/error_setting_password     error
mysql-server-5.5        mysql-server-5.5/postrm_remove_databases        boolean false
mysql-server-5.5        mysql-server-5.5/start_on_boot  boolean true
mysql-server-5.5        mysql-server-5.5/nis_warning    note
mysql-server-5.5        mysql-server-5.5/really_downgrade       boolean false
mysql-server-5.5        mysql-server/password_mismatch  error
mysql-server-5.5        mysql-server/no_upgrade_when_using_ndb  error
phpmyadmin      phpmyadmin/app-password-confirm password
phpmyadmin      phpmyadmin/mysql/admin-pass     password
phpmyadmin      phpmyadmin/password-confirm     password
phpmyadmin      phpmyadmin/setup-password       password
# MySQL application password for phpmyadmin:
phpmyadmin      phpmyadmin/mysql/app-pass       password
phpmyadmin      phpmyadmin/remove-error select  abort
phpmyadmin      phpmyadmin/setup-username       string  admin
# MySQL username for phpmyadmin:
phpmyadmin      phpmyadmin/db/app-user  string
phpmyadmin      phpmyadmin/install-error        select  abort
phpmyadmin      phpmyadmin/reconfigure-webserver        multiselect     apache2
# Host name of the MySQL database server for phpmyadmin:
phpmyadmin      phpmyadmin/remote/host  select
# Configure database for phpmyadmin with dbconfig-common?
phpmyadmin      phpmyadmin/dbconfig-install     boolean false
phpmyadmin      phpmyadmin/remote/port  string
# Perform upgrade on database for phpmyadmin with dbconfig-common?
phpmyadmin      phpmyadmin/dbconfig-upgrade     boolean true
phpmyadmin      phpmyadmin/mysql/admin-user     string  root
phpmyadmin      phpmyadmin/internal/reconfiguring       boolean false
phpmyadmin      phpmyadmin/missing-db-package-error     select  abort
# Host running the MySQL server for phpmyadmin:
phpmyadmin      phpmyadmin/remote/newhost       string
phpmyadmin      phpmyadmin/upgrade-error        select  abort
# Reinstall database for phpmyadmin?
phpmyadmin      phpmyadmin/dbconfig-reinstall   boolean false
# MySQL database name for phpmyadmin:
phpmyadmin      phpmyadmin/db/dbname    string
# Database type to be used by phpmyadmin:
phpmyadmin      phpmyadmin/database-type        select  mysql
phpmyadmin      phpmyadmin/internal/skip-preseed        boolean true
# Do you want to back up the database for phpmyadmin before upgrading?
phpmyadmin      phpmyadmin/upgrade-backup       boolean true
# Deconfigure database for phpmyadmin with dbconfig-common?
phpmyadmin      phpmyadmin/dbconfig-remove      boolean
phpmyadmin      phpmyadmin/passwords-do-not-match       error
# Connection method for MySQL database of phpmyadmin:
phpmyadmin      phpmyadmin/mysql/method select  unix socket
# Do you want to purge the database for phpmyadmin?
phpmyadmin      phpmyadmin/purge        boolean false
mailman mailman/queue_files_present     select  abort installation
mailman mailman/default_server_language select  en
mailman mailman/site_languages  multiselect     en
mailman mailman/used_languages  string
mailman mailman/create_site_list        note
    " > "packages.preseed"
}


function installPackages
{

    echo "deb http://ftp.${country,,}.debian.org/debian/ wheezy main contrib non-free
deb-src http://ftp.${country,,}.debian.org/debian/ wheezy main contrib non-free

deb http://security.debian.org/ wheezy/updates main contrib non-free
deb-src http://security.debian.org/ wheezy/updates main contrib non-free

# wheezy-updates, previously known as 'volatile'
deb http://ftp.${country,,}.debian.org/debian/ wheezy-updates main contrib non-free
deb-src http://ftp.${country,,}.debian.org/debian/ wheezy-updates main contrib non-free" > "/etc/apt/sources.list"

    apt-get update

    apt-get -y install debconf-utils
    echo -e "debconf debconf/frontend select Noninteractive\ndebconf debconf/priority select critical" | debconf-set-selections
    preseeding
    cat packages.preseed | debconf-set-selections
    apt-get -y install openssh-server ntp ntpdate postfix postfix-mysql postfix-doc mysql-client mysql-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve sudo amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl apache2 apache2.2-common apache2-doc apache2-mpm-prefork apache2-utils libexpat1 ssl-cert libapache2-mod-php5 php5 php5-common php5-gd php5-mysql php5-imap phpmyadmin php5-cli php5-cgi libapache2-mod-fcgid apache2-suexec php-pear php-auth php5-mcrypt mcrypt php5-imagick imagemagick libapache2-mod-suphp libruby libapache2-mod-ruby libapache2-mod-python php5-curl php5-intl php5-memcache php5-memcached php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl memcached php5-xcache libapache2-mod-fastcgi php5-fpm expect pure-ftpd-common pure-ftpd-mysql quota quotatool bind9 dnsutils vlogger webalizer awstats geoip-database libclass-dbi-mysql-perl fail2ban

    dpkg-reconfigure dash
    update-rc.d -f spamassassin remove

}



function configureMySQL
{
    case "${useUTF8}" in
        y)  echo "Updating Mysql to UTF8"
            updateSettings "/etc/mysql/my.cnf" '\[client\]' "\[client\]\ncharacter_set=utf8\ndefault-character-set=utf8"
            updateSettings "/etc/mysql/my.cnf" '\[mysqld\]' "\[mysqld\]\ncharacter-set-server=utf8\ncollation_server=utf8_unicode_ci\ninit-connect='SET NAMES utf8'"
                ;;
        *)  echo ""
    esac
    case "${bind}" in
        y)  echo "Updating Mysql to allow all incoming connections"
                updateSettings "/etc/mysql/my.cnf" 'bind-address' '#bind-address       127.0.0.1'
                ;;
        *)  echo ""
    esac
    service mysql restart
}



function configurePostfix
{
    updateSettings "/etc/postfix/master.cf" 'submission inet n' "submission inet n       -       -       -       -       smtpd"
    updateSettings "/etc/postfix/master.cf" 'smtps     inet  n' "smtps     inet  n       -       -       -       -       smtpd"
    updateSettings "/etc/postfix/master.cf" 'syslog_name=postfix\/submission' "  -o syslog_name=postfix\/submission"
    updateSettings "/etc/postfix/master.cf" 'smtpd_tls_security_level=encrypt' "  -o smtpd_tls_security_level=encrypt"
    updateSettings "/etc/postfix/master.cf" 'smtpd_sasl_auth_enable=yes' "  -o smtpd_sasl_auth_enable=yes"
    updateSettings "/etc/postfix/master.cf" 'smtpd_client_restrictions=permit_sasl_authenticated,reject' "  -o smtpd_client_restrictions=permit_sasl_authenticated,reject"
    updateSettings "/etc/postfix/master.cf" 'smtpd_tls_wrappermode=yes' "  -o smtpd_tls_wrappermode=yes"
    updateSettings "/etc/postfix/master.cf" 'syslog_name=postfix\/smtps' "  -o syslog_name=postfix\/smtps"
}



function configureApache
{
    a2enmod suexec rewrite ssl actions include actions fastcgi alias
    case "${webdav}" in
        y)  echo "Enabling WebDAV on Apache2"
            a2enmod dav_fs dav auth_digest
                ;;
        *)  echo ""
    esac
    case "${ruby}" in
        y)  echo "Enabling Ruby on Apache2"
            updateSettings "/etc/mime.types" 'application\/x-ruby' "#application\/x-ruby                             rb"
                ;;
        *)  echo ""
    esac
}



function configureMailman
{
    case "${mailman}" in
        y)  echo "Installing Mailman"
            apt-get -y install mailman
            mailmanexpect=$(expect -c "
spawn newlist mailman
expect \"list:\"
send \"${mailmanemail}\r\"
expect \"password:\"
send \"${mailmanpassword}\r\"
expect \"...\"
send \"\r\"
")
            echo "${mailmanexpect}"
            echo '
## mailman mailing list
mailman:              "|/var/lib/mailman/mail/mailman post mailman"
mailman-admin:        "|/var/lib/mailman/mail/mailman admin mailman"
mailman-bounces:      "|/var/lib/mailman/mail/mailman bounces mailman"
mailman-confirm:      "|/var/lib/mailman/mail/mailman confirm mailman"
mailman-join:         "|/var/lib/mailman/mail/mailman join mailman"
mailman-leave:        "|/var/lib/mailman/mail/mailman leave mailman"
mailman-owner:        "|/var/lib/mailman/mail/mailman owner mailman"
mailman-request:      "|/var/lib/mailman/mail/mailman request mailman"
mailman-subscribe:    "|/var/lib/mailman/mail/mailman subscribe mailman"
mailman-unsubscribe:  "|/var/lib/mailman/mail/mailman unsubscribe mailman"' >> "/etc/aliases"
            newaliases
            ln -s "/etc/mailman/apache.conf" "/etc/apache2/conf.d/mailman.conf"
            service mailman start
            ;;
        *)  echo ""
    esac
}



function configurePureFTPd
{
    updateSettings "/etc/default/pure-ftpd-common" 'STANDALONE_OR_INETD=' "STANDALONE_OR_INETD=standalone"
    updateSettings "/etc/default/pure-ftpd-common" 'VIRTUALCHROOT=' "VIRTUALCHROOT=true"
    echo 1 > /etc/pure-ftpd/conf/TLS
    mkdir -p /etc/ssl/private/
    if [[ -z "${commonname}" ]]
    then
        commonname="${hostname}.${domain}"
    fi
    mkdir -p '/etc/ssl/private/'
    openssl req -x509 -nodes -days 7300 -newkey rsa:4096 -subj "/C=${country}/ST=${state}/L=${city}/O=${organization}/OU=${unit}/CN=${commonname}/emailAddress=${email}" -keyout "/etc/ssl/private/pure-ftpd.pem" -out "/etc/ssl/private/pure-ftpd.pem"
    chmod 600 /etc/ssl/private/pure-ftpd.pem
}



function configureQuota
{
    sed -i -e 's/errors=remount-ro/errors=remount-ro,usrjquota=quota.user,grpjquota=quota.group,jqfmt=vfsv0/g' /etc/fstab
    mount -o remount /
    quotacheck -avugm
    quotaon -avug
}



function configureAWstats
{
    sed -i '/r/ s/^/# /g' "/etc/cron.d/awstats"
}



function configureJailkit
{
    case "${jailkit}" in
        y)  echo "Installing Jailkit"
            apt-get -y install build-essential autoconf automake1.9 libtool flex bison debhelper binutils-gold
            cd /tmp
            wget http://olivier.sessink.nl/jailkit/jailkit-2.15.tar.gz
            tar xvfz jailkit-2.15.tar.gz
            cd jailkit-2.15
            ./debian/rules binary
            for file in /tmp/*.deb
            do
                dpkg -i "${file}"
            done
            ;;
        *)  echo ""
    esac
}



function configureFail2ban
{
    echo '
[dovecot-pop3imap]
enabled = true
filter = dovecot-pop3imap
action = iptables-multiport[name=dovecot-pop3imap, port="pop3,pop3s,imap,imaps", protocol=tcp]
logpath = /var/log/mail.log
maxretry = 5

[sasl]
enabled  = true
port     = smtp
filter   = sasl
logpath  = /var/log/mail.log
maxretry = 3' >> "/etc/fail2ban/jail.local"

    echo '[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =' > "/etc/fail2ban/filter.d/pureftpd.conf"

    echo '[Definition]
failregex = (?: pop3-login|imap-login): .*(?:Authentication failure|Aborted login \(auth failed|Aborted login \(tried to use disabled|Disconnected \(auth failed|Aborted login \(\d+ authentication attempts).*rip=(?P<host>\S*),.*
ignoreregex =' > "/etc/fail2ban/filter.d/dovecot-pop3imap.conf"

}


configureNetwork
installPackages
configureMySQL
configurePostfix
configureApache
configureMailman
configurePureFTPd
configureQuota
configureAWstats
configureJailkit
configureFail2ban





#### At the end make a reboot - to also use new network settings

#debconf-get-selections |grep PACKAGE
