#!/usr/bin/env bash

### Network Settings
interface="eth0"
ip="10.0.0.100"
netmask="255.255.255.0"
network="10.0.0.0"
broadcast="10.0.0.255"
gateway="10.0.0.1"


### Hostname and Domain Name
hostname="ispc"
domain="domain.tld"


### SSL Settings
country="CH"                            # Your country, 2-letter abbreviation
state="State"                           # Your state
city="Town"                             # Your city
organization="Company"                  # e.g. Organization, Company name or something
unit="Unit"                             # e.g. Organizational Unit, Section or something
commonname=""                           # Leave empty, then your FQDN will be used as sated above with hostname and domain name
email="user@domain.tld"               # Your email address


### MySQL Settings
useUTF8="y"                             # Set to 'y' run server by default as utf-8
mysqlpassword="mypassword"
bind="y"                                # Set to 'y' for mysql to listen on all interfaces and not just localhost


### Apache Settings
webdav="y"                              # Set to 'y' to enable WebDAV
ruby="y"                                # Set to 'y' to enable ruby on webserver


### Mail Man
mailman="y"                             # Set to 'y' to enable Mailman
mailmanemail="lists@domain.tld"       # Set email of the person running the list; email must be user@domain.com and can't be user@sub.domain.com
mailmanpassword="mypassword" 


### Jailkit
jailkit="y"                             # Set to 'y' to enable Jailkit


### ISPConfig
databasename="dbispconfig"              # Set ISPConfig Database Name
port="8080"                             # Set ISPConfig Port
ssl="y"                                 # Set to 'y' to use SSL to access ISPCConfig


### Horde
horde="y"                               # Set 'y' to install Horde
hordedatabase="horde"                   # Set Horde Databasename
hordeuser="horde"                       # Set MySQL Horde Username
hordepassword="mypassword"              # Set password for Horde Username
hordefilesystem="/var/www/horde"        # Set filesystem location for horde
hordeadmin="admin@domain.tld"             # Set existing mail user with administrator permissions
hordemysql="mysql"						# Set your perferred mysql driver, either "mysql" for mysql/pdo or "mysqli" for mysqli.
										# See discussion: http://lists.horde.org/archives/horde/Week-of-Mon-20130121/046301.html


### LogJam
logjam="y"                              # Set to 'y' to enalbe LogJam security measures - read more here: https://weakdh.org/
dhkeysize="4096"                        # Set keysize for Diffie-Hellman, at least 2048bit, 4096 will require a long time



# Detailed installation steps at https://www.howtoforge.com/tutorial/perfect-server-debian-8-jessie-apache-bind-dovecot-ispconfig-3




##############################################################################
#                                                                            #
#                            BELOW BE DRAGONS                                #
#                                                                            #
##############################################################################

curPath=$( pwd )

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
    cd "${curPath}"
    # Make backup of curent interfaces
    cp "/etc/network/interfaces" "/etc/network/interfaces.orig"
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
    cd "${curPath}"
    echo "
postfix postfix/mailname string ${hostname}.${domain}
postfix postfix/main_mailer_type select Internet Site
postfix postfix/destinations string ${hostname}.${domain}, localhost.${domain}, , localhost
mysql-server-5.5 mysql-server/root_password password ${mysqlpassword}
mysql-server-5.5 mysql-server/root_password seen true
mysql-server-5.5 mysql-server/root_password_again password ${mysqlpassword}
mysql-server-5.5 mysql-server/root_password_again seen true
phpmyadmin phpmyadmin/internal/reconfiguring boolean false
phpmyadmin phpmyadmin/missing-db-package-error select abort
phpmyadmin phpmyadmin/setup-username string admin
phpmyadmin phpmyadmin/install-error select abort
phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2
phpmyadmin phpmyadmin/upgrade-error select abort
phpmyadmin phpmyadmin/dbconfig-reinstall boolean false
phpmyadmin phpmyadmin/dbconfig-install boolean false
phpmyadmin phpmyadmin/database-type select mysql
phpmyadmin phpmyadmin/internal/skip-preseed boolean true
phpmyadmin phpmyadmin/dbconfig-upgrade boolean true
phpmyadmin phpmyadmin/upgrade-backup boolean true
phpmyadmin phpmyadmin/mysql/method select unix socket
phpmyadmin phpmyadmin/mysql/admin-user string root
phpmyadmin phpmyadmin/purge boolean false
mailman mailman/site_languages multiselect en
mailman mailman/queue_files_present select abort installation
mailman mailman/default_server_language select en
   " > "packages.preseed"
}


function installPackages
{
    cd "${curPath}"
    echo "deb http://ftp.${country,,}.debian.org/debian/ jessie main contrib non-free
deb-src http://ftp.${country,,}.debian.org/debian/ jessie main contrib non-free

deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free

# jessie-updates, previously known as 'volatile'
deb http://ftp.${country,,}.debian.org/debian/ jessie-updates main contrib non-free
deb-src http://ftp.${country,,}.debian.org/debian/ jessie-updates main contrib non-free" > "/etc/apt/sources.list"
    apt-get update
    apt-get -y upgrade
    apt-get -y install debconf-utils
    echo -e "debconf debconf/frontend select Noninteractive\ndebconf debconf/priority select critical" | debconf-set-selections
    preseeding
    cat packages.preseed | debconf-set-selections
    apt-get -y install openssh-server ntp ntpdate postfix postfix-mysql postfix-doc mariadb-client mariadb-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve dovecot-lmtpd sudo amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl apache2 apache2.2-common apache2-doc apache2-mpm-prefork apache2-utils libexpat1 ssl-cert libapache2-mod-php5 php5 php5-common php5-gd php5-mysql php5-imap phpmyadmin php5-cli php5-cgi libapache2-mod-fcgid apache2-suexec php-pear php-auth php5-mcrypt mcrypt php5-imagick imagemagick libruby libapache2-mod-python php5-curl php5-intl php5-memcache php5-memcached php5-pspell php5-recode php5-sqlite php5-tidy php5-xmlrpc php5-xsl memcached libapache2-mod-passenger php5-xcache libapache2-mod-fastcgi php5-fpm expect pure-ftpd-common pure-ftpd-mysql quota quotatool bind9 dnsutils vlogger webalizer awstats geoip-database libclass-dbi-mysql-perl fail2ban
    systemctl disable spamassassin

}



function configureMySQL
{
    cd "${curPath}"
    case "${useUTF8}" in
        y)  echo "Updating Mysql to UTF8"
            updateSettings "/etc/mysql/conf.d/mariadb.cnf" 'default-character-set' 'default-character-set = utf8'
            updateSettings "/etc/mysql/conf.d/mariadb.cnf" 'character-set-server' 'character-set-server  = utf8'
            updateSettings "/etc/mysql/conf.d/mariadb.cnf" 'character-set-server' 'collation-server      = utf8_general_ci'
            updateSettings "/etc/mysql/conf.d/mariadb.cnf" 'character_set_server' 'character_set_server   = utf8'
            updateSettings "/etc/mysql/conf.d/mariadb.cnf" 'collation_server' 'collation_server       = utf8_general_ci'
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
    cd "${curPath}"
    updateSettings "/etc/postfix/master.cf" 'submission inet n' 'submission inet n       -       -       -       -       smtpd'
    updateSettings "/etc/postfix/master.cf" 'syslog_name=postfix/submission' '  -o syslog_name=postfix/submission'
    updateSettings "/etc/postfix/master.cf" 'smtpd_tls_security_level' '  -o smtpd_tls_security_level=encrypt'
    updateSettings "/etc/postfix/master.cf" 'smtpd_sasl_auth_enable' "  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_client_restrictions=permit_sasl_authenticated,reject"
    updateSettings "/etc/postfix/master.cf" 'smtps     inet  n' 'smtps     inet  n       -       -       -       -       smtpd'
    updateSettings "/etc/postfix/master.cf" 'syslog_name=postfix/smtps' '  -o syslog_name=postfix/smtps'
    updateSettings "/etc/postfix/master.cf" 'smtpd_tls_wrappermode' '  -o smtpd_tls_wrappermode=yes'
}



function configureApache
{
    cd "${curPath}"
    a2enmod suexec rewrite ssl actions include cgi
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
    cd "${curPath}"
    case "${mailman}" in
        y)  echo "Installing Mailman"
            apt-get -y install mailman
            ./mailmanexpect "${mailmanemail}" "${mailmanpassword}"
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
            service postfix start
            service apache2 restart
            service mailman start
            ;;
        *)  echo ""
    esac
}



function configurePureFTPd
{
    cd "${curPath}"
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
    service pure-ftpd-mysql restart
}



function configureQuota
{
    cd "${curPath}"
    sed -i -e 's/errors=remount-ro/errors=remount-ro,usrjquota=quota.user,grpjquota=quota.group,jqfmt=vfsv0/g' /etc/fstab
    mount -o remount /
    quotacheck -avugm
    quotaon -avug
}



function configureAWstats
{
    cd "${curPath}"
    sed -i '/r/ s/^/# /g' "/etc/cron.d/awstats"
}



function configureJailkit
{
    cd "${curPath}"
    case "${jailkit}" in
        y)  echo "Installing Jailkit"
            apt-get -y install build-essential autoconf automake libtool flex bison debhelper binutils
            cd /tmp
            wget http://olivier.sessink.nl/jailkit/jailkit-2.17.tar.gz
            tar xvfz jailkit-2.17.tar.gz
            cd jailkit-2.17
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
    cd "${curPath}"
    echo '
[pureftpd]
enabled  = true
port     = ftp
filter   = pureftpd
logpath  = /var/log/syslog
maxretry = 3

[dovecot-pop3imap]
enabled = true
filter = dovecot-pop3imap
action = iptables-multiport[name=dovecot-pop3imap, port="pop3,pop3s,imap,imaps", protocol=tcp]
logpath = /var/log/mail.log
maxretry = 5

[postfix-sasl]
enabled  = true
port     = smtp
filter   = postfix-sasl
logpath  = /var/log/mail.log
maxretry = 3' >> "/etc/fail2ban/jail.local"

    echo '[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =' > "/etc/fail2ban/filter.d/pureftpd.conf"

    echo '[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =' > "/etc/fail2ban/filter.d/pureftpd.conf"

    echo '[Definition]
failregex = (?: pop3-login|imap-login): .*(?:Authentication failure|Aborted login \(auth failed|Aborted login \(tried to use disabled|Disconnected \(auth failed|Aborted login \(\d+ authentication attempts).*rip=(?P<host>\S*),.*
ignoreregex =' > "/etc/fail2ban/filter.d/dovecot-pop3imap.conf"

    echo 'ignoreregex =' >> /etc/fail2ban/filter.d/postfix-sasl.conf

}



function installISPConfig
{
    cd "${curPath}"
    if [[ -z "${commonname}" ]]
    then
        commonname="${hostname}.${domain}"
    fi
    wget "http://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz" -O "/tmp/ISPC.tgz"
    tar -xvzf "/tmp/ISPC.tgz" -C "/tmp/"
    ./ispcexpect "${mysqlpassword}" "${databasename}" "${country}" "${state}" "${city}" "${organization}" "${unit}" "${commonname}" "${email}" "${port}" "${ssl}" "${country}" "${state}" "${city}" "${organization}" "${unit}" "${email}"
}



function installHorde
{
    cd "${curPath}"
    case "${horde}" in
        y)  echo "Installing Horde"
            apt-get -y install php5-sasl php5-intl libssh2-php php5-curl php-http php5-xmlrpc php5-geoip php5-ldap php5-memcache php5-memcached php5-tidy
            pear channel-discover pear.horde.org
            pear install horde/horde_role
            ./horderoleexpect "${hordefilesystem}"
            pear install -a -B horde/webmail
            mysql -u root --password=${mysqlpassword} --batch --silent -e "CREATE DATABASE ${hordedatabase}; GRANT ALL ON ${hordedatabase}.* TO ${hordeuser}@localhost IDENTIFIED BY '${hordepassword}'; FLUSH PRIVILEGES;";
            ./hordewebmailexpect "${hordeuser}" "${hordepassword}" "${hordedatabase}" "${hordefilesystem}" "${hordeadmin}" "${hordemysql}"
            mkdir "${hordefilesystem}/phptmp/"
            chown -R www-data:www-data "${hordefilesystem}"
            pear install channel://pear.php.net/MDB2_Driver_mysql-1.5.0b4
            pear install channel://pear.php.net/HTTP_WebDAV_Server-1.0.0RC7
            pear install channel://pear.php.net/XML_Serializer-0.20.2
            pear install channel://pear.php.net/Date_Holidays-0.21.8
            pear install Net_LDAP
            pear install pear/HTTP_Request2
            pear install channel://pear.php.net/Console_Color2-0.1.2
            echo "Alias /Microsoft-Server-ActiveSync ${hordefilesystem}/rpc.php
Alias /horde ${hordefilesystem}
Alias /autodiscover/autodiscover.xml ${hordefilesystem}/rpc.php
Alias /Autodiscover/Autodiscover.xml ${hordefilesystem}/rpc.php
Alias /AutoDiscover/AutoDiscover.xml ${hordefilesystem}/rpc.php
<Directory ${hordefilesystem}>
           Options +FollowSymLinks
           AllowOverride All
           order allow,deny
           allow from all
           AddType application/x-httpd-php .php
           php_value include_path \".:/usr/share/php\"
           php_value open_basedir \"none\"
           php_value upload_tmp_dir \"${hordefilesystem}/phptmp/\"
</Directory>" > /etc/apache2/conf-available/horde.conf
            a2enconf horde
            updateSettings "/var/www/horde/.htaccess" 'RewriteEngine On' "    RewriteEngine On\n    RewriteBase \/horde"
            pear install -a -B horde/passwd
            chown -R www-data:www-data "${hordefilesystem}/passwd"
            cp -a "${hordefilesystem}/passwd/config/backends.php" "${hordefilesystem}/passwd/config/backends.local.php"
            echo "\$backends['sql'] = array (
  'disabled' => false,
  'name' => 'SQL Server',
  'preferred' => '',
  'policy' => array(
    'minLength' => 7,
    'maxLength' => 64,
    'maxSpace' => 0,
    'minNumeric' => 1,
  ),
  'driver' => 'Sql',
  'params' => array(
    'phptype' => 'mysql',
    'hostspec' => 'localhost',
    'username' => 'root',
    'password' => '${mysqlpassword}',
    'encryption' => 'crypt-md5',
    'database' => '${databasename}',
    'table' => 'mail_user',
    'user_col' => 'email',
    'pass_col' => 'password',
    'show_encryption' => false
    // The following two settings allow you to specify custom queries for
    // lookup and modify functions if special functions need to be
    // performed. In places where a username or a password needs to be
    // used, refer to this placeholder reference:
    // %d -> gets substituted with the domain
    // %u -> gets substituted with the user
    // %U -> gets substituted with the user without a domain part
    // %p -> gets substituted with the plaintext password
    // %e -> gets substituted with the encrypted password
    //
    // 'query_lookup' => 'SELECT user_pass FROM horde_users WHERE user_uid = %u',
   // 'query_modify' => 'UPDATE horde_users SET user_pass = %e WHERE user_uid = %u',
  ),
);" > "${hordefilesystem}/passwd/config/backends.local.php"
            ;;
        *)  echo ""
    esac
}



function applyLogJam
{
    cd "${curPath}"
    case "${logjam}" in
        y)  echo "Applying LogJam security measures"
            # Generate new DH cert
            openssl dhparam -out "/etc/ssl/private/dh-${dhkeysize}.pem" ${dhkeysize}
            updateSettings "/etc/apache2/mods-available/ssl.conf" 'SSLProtocol all' '        SSLProtocol             all -SSLv2 -SSLv3'
            # Secure Apache2
            updateSettings "/etc/apache2/mods-available/ssl.conf" 'SSLCipherSuite' '        SSLCipherSuite          ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA'
            updateSettings "/etc/apache2/mods-available/ssl.conf" 'SSLHonorCipherOrder' '        SSLHonorCipherOrder on'
                    # The SSLOpenSSLConfCmd DHParameters command isn't working on Jessie due to OpenSSL being v1.0.1 instead of v1.0.2
                    #            updateSettings "/etc/apache2/mods-available/ssl.conf" 'SSLStrictSNIVHostCheck On' "        #SSLStrictSNIVHostCheck On\n        SSLOpenSSLConfCmd DHParameters \"/etc/ssl/private/dh-${dhkeysize}.pem\""
            # Secure Postfix
            postconf -e "smtpd_tls_mandatory_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CDC3-SHA, KRB5-DE5, CBC3-SHA"
            postconf -e "smtpd_tls_dh1024_param_file = /etc/ssl/private/dh-${dhkeysize}.pem"
            # Secure Dovecot
            echo 'ssl_cipher_list=ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA' >> '/etc/dovecot/dovecot.conf'
            echo 'ssl_prefer_server_ciphers = yes' >> '/etc/dovecot/dovecot.conf'
            echo "ssl_dh_parameters_length = ${dhkeysize}" >> '/etc/dovecot/dovecot.conf'
            # PureFTPD -> The Wrapper Script is already fine, only the TLSCipherSuite needs adjustement
            echo 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA' > '/etc/pure-ftpd/conf/TLSCipherSuite'
            ;;
        *)  echo ""
    esac
}



# Set default shell to bash
echo "dash dash/sh boolean false" | debconf-set-selections
dpkg-reconfigure -f noninteractive dash > /dev/null 2>&1

# Run the individual functions
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
installISPConfig
installHorde
applyLogJam


if [[ "${ssl}" = "y" ]]
then
    s="s"
fi

clear

echo ""
echo ""
echo "Installation of Perfect Server, ISPConfig and - if selected - Horde Webmail complete."
echo "Please reboot server and connect to new IP if it was altered."
echo ""
echo "You can now access IPSConfig at http${s}://${ip}:${port} or http${s}://${hostname}.${domain}:${port}"
echo "and Horde can be access on any domain (or IP) as /horde e.g. http://${hostname}.${domain}/horde"
