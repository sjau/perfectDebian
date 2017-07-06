#!/usr/bin/env bash

# This is the main script. When first run, it will copy the config template to config.conf
# You will need then to edit the config.conf and set your values.
# Once done, you can re-run this script again and it will do the installation.


##############################################################################
#                                                                            #
#                            BELOW BE DRAGONS                                #
#                                                                            #
##############################################################################

curPath=$( pwd )

updateSettings () {
    File="$1"
    Pattern="$2"
    Replace="$3"
    if grep "${Pattern}" "${File}" >/dev/null; then
            # Pattern found, replace line
            sed -i s/.*"${Pattern}".*/"${Replace}"/g "${File}"
            echo ""
    else
            # Pattern not found, append new
            echo "${Replace}" >> "${File}"
    fi
}

confCheck () {
    # Check if file exists
    if [[ ! -f "config.conf" ]]; then
        echo '### Network Settings
interface="enp0s3"                      # Your network interface name
ip=""                                   # The IP(v4) for the network, e.g. "10.0.0.100"
netmask="255.255.255.0"                 # The netmask, e.g. "255.255.255.0"
network=""                              # The network, e.g. "10.0.0.0"
broadcast=""                            # The broadcast, e.g. "10.0.0.255"
gateway=""                              # The gateway, e.g. "10.0.0.1"


### Hostname and Domain Name
hostname=""                             # Your hostname, e.g. "ispc"
domain=""                               # Your domain name, e.g. "mydomain.tld"


### SSL Settings
country=""                              # Your country, 2-letter abbreviation, e.g. "CH"
state=""                                # Your state, e.g. "SG"
city=""                                 # Your city
organization=""                         # e.g. Organization, Company name or something
unit=""                                 # e.g. Organizational Unit, Section or something
commonname=""                           # Leave empty, then your FQDN will be used as sated above with hostname and domain name
email=""                                # Your email address


### MariaDB Settings
mariadbpassword=""                      # Your password for MariaDB
bind="y"                                # Set to "y" for MariaDB to listen on all interfaces and not just localhost


### Apache Settings
webdav="y"                              # Set to "y" to enable WebDAV


### Mailman
mailman="y"                             # Set to "y" to enable Mailman
mailmanemail=""                         # Set email of the person running the list; email must be user@domain.com and cannot be user@sub.domain.com
mailmanpassword=""                      # Set the mailman password


### Jailkit
jailkit="y"                             # Set to "y" to enable Jailkit


### UFW
ufw="y"                                 # Set to "y" to install ufw


### ISPConfig
databasename="dbispconfig"              # Set ISPConfig Database Name
port="8080"                             # Set ISPConfig Port
adminpassword=""                        # Set the ISPConfig Admin Password
ssl="y"                                 # Set to "y" to use SSL to access ISPConfig


### Horde
horde="y"                               # Set "y" to install Horde
hordedatabase="horde"                   # Set Horde Databasename
hordeuser="horde"                       # Set MariaDB Horde Username
hordepassword=""                        # Set password for Horde Username
hordefilesystem="/var/www/horde"        # Set filesystem location for horde
hordeadmin=""                           # Set existing mail user with administrator permissions
hordemariadb="mysql"                    # Set your perferred MariaDB driver, 
                                        # either "mysql" for mysql/pdo or "mysqli" for mysqli.
                                        # See discussion: http://lists.horde.org/archives/horde/Week-of-Mon-20130121/046301.html


### configureRoundCube
roundcube="y"                           # Set to "y" to install RoundCube


### LogJam
logjam="y"                              # Set to "y" to enalbe LogJam security measures - read more here: https://weakdh.org/
dhkeysize="4096"                        # Set keysize for Diffie-Hellman, at least 2048bit, 4096 will require a long time

### Config Version
confversion="2017062901"                # Do not alter manually!!!

# Detailed installation steps at https://www.howtoforge.com/tutorial/perfect-server-debian-9-stretch-apache-bind-dovecot-ispconfig-3-1/
' > "config.conf"
        echo "A default configuration file was generated as 'config.conf'"
        echo "You will need then to edit the config.conf and set your values, especially passwords."
        echo "Once done, you can re-run this script again and it will do the installation."
        exit
    else
        source "./config.conf"
    fi
    # Check if config file version is up-to-date
    if [[ "${confversion}" = "2017062901" ]]; then
        echo "Config is current. Proceeding with installation."
    else
        echo "Your config is out of date. Please remove it and re-run this script."
        exit
    fi
    # Check if necessary variables are set
    echo "Checking if all necessary config options were set."
    if [[ -z "${ip}" ]]; then echo "The variable 'ip' is not set."; missingVar=1; fi
    if [[ -z "${network}" ]]; then echo "The variable 'network' is not set."; missingVar=1; fi
    if [[ -z "${broadcast}" ]]; then echo "The variable 'broadcast' is not set."; missingVar=1; fi
    if [[ -z "${gateway}" ]]; then echo "The variable 'gateway' is not set."; missingVar=1; fi
    if [[ -z "${hostname}" ]]; then echo "The variable 'hostname' is not set."; missingVar=1; fi
    if [[ -z "${domain}" ]]; then echo "The variable 'domain' is not set."; missingVar=1; fi
    if [[ -z "${country}" ]]; then echo "The variable 'country' is not set."; missingVar=1; fi
    if [[ -z "${state}" ]]; then echo "The variable 'state' is not set."; missingVar=1; fi
    if [[ -z "${city}" ]]; then echo "The variable 'city' is not set."; missingVar=1; fi
    if [[ -z "${organization}" ]]; then echo "The variable 'organization' is not set."; missingVar=1; fi
    if [[ -z "${unit}" ]]; then echo "The variable 'unit' is not set."; missingVar=1; fi
    if [[ -z "${email}" ]]; then echo "The variable 'email' is not set."; missingVar=1; fi
    if [[ -z "${mariadbpassword}" ]]; then echo "The variable 'mariadbpassword' is not set."; missingVar=1; fi
    if [[ "${mailman}" = "y" && -z "${mailmanemail}" ]]; then echo "The variable 'mailmanemail' is not set."; missingVar=1; fi
    if [[ "${mailman}" = "y" && -z "${mailmanpassword}" ]]; then echo "The variable 'mailmanpassword' is not set."; missingVar=1; fi
    if [[ -z "${adminpassword}" ]]; then echo "The variable 'adminpassword' is not set."; missingVar=1; fi
    if [[ "${horde}" = "y" && -z "${hordepassword}" ]]; then echo "The variable 'hordepassword' is not set."; missingVar=1; fi
    if [[ "${horde}" = "y" && -z "${hordeadmin}" ]]; then echo "The variable 'hordeadmin' is not set."; missingVar=1; fi
    # Test if there was a missing var
    if [[ "${missingVar}" -eq 1 ]]; then
        echo "You need to fix those missing settings. Please enter according info and re-run this script."
        exit
    else
        echo "All necessary config options set. Proceeding with installation."
    fi
}

configureNetwork () {
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

    echo "${hostname}" > "/etc/hostname"
    # You can use sysctl call to set hostname so you don't have to reboot
    sysctl kernel.hostname=${hostname}
}

preseeding () {
    cd "${curPath}"
    echo "
postfix postfix/mailname string ${hostname}.${domain}
postfix postfix/main_mailer_type select Internet Site
postfix postfix/destinations string ${hostname}.${domain}, localhost.${domain}, , localhost
mariadb-server-10.0 mysql-server/root_password password ${mariadbpassword}
mariadb-server-10.0 mysql-server/root_password seen true
mariadb-server-10.0 mysql-server/root_password_again password ${mariadbpassword}
mariadb-server-10.0 mysql-server/root_password_again seen true
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
roundcube-core roundcube/dbconfig-upgrade boolean true
roundcube-core roundcube/database-type select mysql 
   " > "packages.preseed"
}

installPackages () {
    cd "${curPath}"
    echo "deb http://ftp.${country,,}.debian.org/debian/ stretch main contrib non-free
deb-src http://ftp.${country,,}.debian.org/debian/ stretch main contrib non-free

deb http://security.debian.org/ stretch/updates main contrib non-free
deb-src http://security.debian.org/ stretch/updates main contrib non-free

# stretch-updates, previously known as 'volatile'
deb http://ftp.${country,,}.debian.org/debian/ stretch-updates main contrib non-free
deb-src http://ftp.${country,,}.debian.org/debian/ stretch-updates main contrib non-free" > "/etc/apt/sources.list"
    apt-get update
    apt-get -y upgrade
    apt-get -y install debconf-utils
    echo -e "debconf debconf/frontend select Noninteractive\ndebconf debconf/priority select critical" | debconf-set-selections
    preseeding
    cat packages.preseed | debconf-set-selections
    apt-get -y install expect curl ssh openssh-server nano vim-nox ntp postfix postfix-mysql postfix-doc mariadb-client mariadb-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve dovecot-lmtpd sudo amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl postgrey apache2 apache2-doc apache2-utils libapache2-mod-php php7.0 php7.0-common php7.0-gd php7.0-mysql php7.0-imap phpmyadmin php7.0-cli php7.0-cgi libapache2-mod-fcgid apache2-suexec-pristine php-pear php7.0-mcrypt mcrypt imagemagick libruby libapache2-mod-python php7.0-curl php7.0-intl php7.0-pspell php7.0-recode php7.0-sqlite3 php7.0-tidy php7.0-xmlrpc php7.0-xsl memcached php-memcache php-imagick php-gettext php7.0-zip php7.0-mbstring libapache2-mod-passenger certbot php7.0-fpm php7.0-opcache php-apcu pure-ftpd-common pure-ftpd-mysql quota quotatool bind9 dnsutils haveged webalizer awstats geoip-database libclass-dbi-mysql-perl libtimedate-perl fail2ban
}

configureMariaDB () {
    cd "${curPath}"

    export HISTIGNORE="expect*"
    expect -c "
        spawn mysql_secure_installation
        while {1} {
            expect {
                -re {Enter current password .*}          {send \r}
                -re {Set root .*}                        {send y\r}
                -re {New .*}                             {send ${mariadbpassword}\r}
                -re {Re-enter new .*}                    {send ${mariadbpassword}\r}
                -re {Remove anonymous .*\[.*\]?}         {send y\r}
                -re {Disallow root login .*\[.*\]?}      {send y\r}
                -re {Remove test database .*\[.*\]?}     {send y\r}
                -re {Reload privilege tables .*\[.*\]?}  {send y\r}
                eof                                      {break}
            }
        }"
    export HISTIGNORE=""

    case "${bind}" in
        y)  echo "Updating MariaDB to allow all incoming connections"
                updateSettings "/etc/mysql/mariadb.conf.d/50-server.cnf" 'bind-address' "#bind-address       127.0.0.1\nsql-mode='NO_ENGINE_SUBSTITUTION'"
                ;;
        *)  updateSettings "/etc/mysql/mariadb.conf.d/50-server.cnf" 'bind-address' "bind-address       127.0.0.1\nsql-mode='NO_ENGINE_SUBSTITUTION'"
                ;;
    esac

    echo "update mysql.user set plugin = 'mysql_native_password' where user='root';" | mysql -u root
    updateSettings "/etc/mysql/debian.cnf" 'password' "password = ${mariadbpassword}"
    service mysql restart
}

configurePostfix () {
    cd "${curPath}"
    updateSettings "/etc/postfix/master.cf" 'submission inet n' 'submission inet n       -       -       -       -       smtpd'
    updateSettings "/etc/postfix/master.cf" 'syslog_name=postfix\/submission' '  -o syslog_name=postfix\/submission'
    updateSettings "/etc/postfix/master.cf" 'smtpd_tls_security_level' '  -o smtpd_tls_security_level=encrypt'
    updateSettings "/etc/postfix/master.cf" 'smtpd_sasl_auth_enable' "  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_client_restrictions=permit_sasl_authenticated,reject"
    updateSettings "/etc/postfix/master.cf" 'smtps     inet  n' 'smtps     inet  n       -       -       -       -       smtpd'
    updateSettings "/etc/postfix/master.cf" 'syslog_name=postfix\/smtps' '  -o syslog_name=postfix\/smtps'
    updateSettings "/etc/postfix/master.cf" 'smtpd_tls_wrappermode' '  -o smtpd_tls_wrappermode=yes'
}

configureAmavisdSpamassassinClamav () {
    cd "${curPath}"
    updateSettings "/etc/clamav/clamd.conf" 'AllowSupplementaryGroups' 'AllowSupplementaryGroups true'
    systemctl stop spamassassin
    systemctl disable spamassassin
}

configureApache () {
    cd "${curPath}"
    a2enmod suexec rewrite ssl actions include cgi headers
    case "${webdav}" in
        y)  echo "Enabling WebDAV on Apache2"
            a2enmod dav_fs dav auth_digest
                ;;
        *)  echo ""
    esac
    echo "<IfModule mod_headers.c>
    RequestHeader unset Proxy early
</IfModule>" > "/etc/apache2/conf-available/httpoxy.conf"
    a2enconf httpoxy
}

configureLetsEncrypt () {
    certbot --agree-tos
    systemctl restart apache2
}

configurePHPFPM () {
    cd "${curPath}"
    a2enmod actions proxy_fcgi alias
}

configureMailman () {
    cd "${curPath}"
    case "${mailman}" in
        y)  echo "Installing Mailman"
            apt-get -y install mailman
            export HISTIGNORE="expect*"
            expect -c "
                spawn newlist mailman
                while {1} {
                    expect {
                        -re {Enter the email .*:}          {send ${mailmanemail}\r}
                        -re {Initial mailman .*:}          {send ${mailmanpassword}\r}
                        -re {Hit enter to notify .*}       {send \r}
                        eof                                {break}
                    }
                }";
            export HISTIGNORE=""
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
            ln -s "/etc/mailman/apache.conf" "/etc/apache2/conf-enabled/mailman.conf"
            systemctl restart postfix
            systemctl restart apache2
            systemctl restart mailman
            ;;
        *)  echo ""
    esac
}

configurePureFTPd () {
    cd "${curPath}"
    updateSettings "/etc/default/pure-ftpd-common" 'STANDALONE_OR_INETD=' "STANDALONE_OR_INETD=standalone"
    updateSettings "/etc/default/pure-ftpd-common" 'VIRTUALCHROOT=' "VIRTUALCHROOT=true"
    echo 1 > "/etc/pure-ftpd/conf/TLS"
    mkdir -p "/etc/ssl/private/"
    if [[ -z "${commonname}" ]]; then
        commonname="${hostname}.${domain}"
    fi
    mkdir -p '/etc/ssl/private/'
    openssl req -x509 -nodes -days 7300 -newkey rsa:4096 -subj "/C=${country}/ST=${state}/L=${city}/O=${organization}/OU=${unit}/CN=${commonname}/emailAddress=${email}" -keyout "/etc/ssl/private/pure-ftpd.pem" -out "/etc/ssl/private/pure-ftpd.pem"
    chmod 600 "/etc/ssl/private/pure-ftpd.pem"
    systemctl restart pure-ftpd-mysql
}

configureQuota () {
    cd "${curPath}"
    sed -i -e 's/errors=remount-ro/errors=remount-ro,usrjquota=quota.user,grpjquota=quota.group,jqfmt=vfsv0/g' /etc/fstab
    mount -o remount /
    quotacheck -avugm
    quotaon -avug
}

configureAWstats () {
    cd "${curPath}"
    sed -i '/r/ s/^/# /g' "/etc/cron.d/awstats"
}

configureJailkit () {
    cd "${curPath}"
    case "${jailkit}" in
        y)  echo "Installing Jailkit"
            apt-get -y install build-essential autoconf automake libtool flex bison debhelper binutils
            cd /tmp
            wget http://olivier.sessink.nl/jailkit/jailkit-2.19.tar.gz
            tar xvfz jailkit-2.19.tar.gz
            cd jailkit-2.19
            echo 5 > debian/compat
            ./debian/rules binary
            for file in /tmp/*.deb
            do
                dpkg -i "${file}"
            done
            ;;
        *)  echo ""
    esac
}

configureFail2ban () {
    cd "${curPath}"
    echo '[pure-ftpd]
enabled = true
port = ftp
filter = pure-ftpd
logpath = /var/log/syslog
maxretry = 3

[dovecot]
enabled = true
filter = dovecot
logpath = /var/log/mail.log
maxretry = 5

[postfix-sasl]
enabled = true
port = smtp
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 3' >> "/etc/fail2ban/jail.local"

    systemctl restart fail2ban
}

configureUFW () {
    cd "${curPath}"
    case "${ufw}" in
        y)  echo "Installing UFW"
            apt-get -y install ufw
            ;;
        *)  echo ""
    esac
}

configureRoundCube () {
    cd "${curPath}"
    case "${roundcube}" in
        y)  echo "Installing RoundCube"
            apt-get -y install roundcube roundcube-core roundcube-mysql roundcube-plugins

            export HISTIGNORE="expect*"
            expect -c "
                spawn apt-get -y install roundcube roundcube-core roundcube-mysql roundcube-plugins
                while {1} {
                    expect {
                        -re {Configure database for .*:}        {send yes\r}
                        -re {MySQL application password .*:}    {send \r}
                        -re {Password for the database .*}      {send ${mariadbpassword}\r}
                        eof                                     {break}
                    }
                }";
            export HISTIGNORE=""
            updateSettings "/etc/roundcube/config.inc.php" 'default_host' '$config["default_host"] = "localhost";'
            updateSettings "/etc/roundcube/config.inc.php" 'smtp_server'  '$config["smtp_server"] = "localhost";'
            updateSettings "/etc/apache2/conf-available/roundcube.conf" 'Alias'  'Alias \/webmail \/var\/lib\/roundcube'
            systemctl restart apache2
            ;;
        *)  echo ""
    esac
}

installISPConfig () {
    cd "${curPath}"
    if [[ -z "${commonname}" ]]
    then
        commonname="${hostname}.${domain}"
    fi
    mkdir -p "/tmp/ISPC"
    curl -o "/tmp/ISPC.tgz" -O "https://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz"
    tar -xvzf "/tmp/ISPC.tgz" -C "/tmp/ISPC"
    mv "/tmp/ISPC/ispc"* "/tmp/ISPC/ispconfig"

            export HISTIGNORE="expect*"
            expect -c "
                spawn php -q /tmp/ISPC/ispconfig/install/install.php
                while {1} {
                    expect {
                        -re {Select language .*\[.*\]:}          {send \r}
                        -re {Installation mode .*\[.*\]:}        {send \r}
                        -re {Full qualified hostname .*\[.*\]:}  {send \r}
                        -re {MySQL server hostname .*\[.*\]:}    {send \r}
                        -re {MySQL server port .*\[.*\]:}        {send \r}
                        -re {MySQL root username .*\[.*\]:}      {send \r}
                        -re {MySQL root password .*\[.*\]:}      {send $mariadbpassword\r}
                        -re {MySQL database .*\[.*\]:}           {send $databasename\r}
                        -re {MySQL charset .*\[.*\]:}            {send \r}
                        -re {Country Name .*\[.*\]:}             {send $country\r}
                        -re {State or Province .*\[.*\]:}        {send $state\r}
                        -re {Locality Name .*\[.*\]:}            {send $city\r}
                        -re {Organization Name .*\[.*\]:}        {send $organization\r}
                        -re {Organizational Unit .*\[.*\]:}      {send $unit\r}
                        -re {Common Name .*\[.*\]:}              {send $commonname\r}
                        -re {Email Address .*\[.*\]:}            {send $email\r}
                        -re {ISPConfig Port .*\[.*\]:}           {send $port\r}
                        -re {Admin password .*\[.*\]:}           {send $adminpassword\r}
                        -re {Re-enter admin .*\[.*\]:}           {send $adminpassword\r}
                        -re {Do you want a secure .*\[.*\]:}     {send $ssl\r}
                        -re {A challenge password .*\[.*\]:}     {send \r}
                        -re {An optional company .*\[.*\]:}      {send \r}
                        eof                                      {break}
                    }
                }";
            export HISTIGNORE=""
}

installHorde () {
    cd "${curPath}"
    case "${horde}" in
        y)  echo "Installing Horde"
            apt-get -y install php-horde-webmail php-horde-passwd
            mysql -u root --password=${mariadbpassword} --batch --silent -e "CREATE DATABASE ${hordedatabase}; GRANT ALL ON ${hordedatabase}.* TO ${hordeuser}@localhost IDENTIFIED BY '${hordepassword}'; FLUSH PRIVILEGES;";
            export HISTIGNORE="expect*"
            expect -c "
                spawn webmail-install
                    while {1} {
                        expect {
                            -re {What database backend .*}          {send $hordemariadb\r}
                            -re {Username to connect .*}            {send $hordeuser\r}
                            -re {Password to connect .*}            {send $hordepassword\r}
                            -re {How should we connect .*}          {send unix\r}
                            -re {Location of UNIX socket .*}        {send \r}
                            -re {Database name .*}                  {send $hordedatabase\r}
                            -re {Internally used .*}                {send \r}
                            -re {Use SSL to connect .*}             {send 0\r}
                            -re {Certification Authority .*}        {send \r}
                            -re {Split reads to .*}                 {send false\r}
                            -re {Specify an .*}                     {send $hordeadmin\r}
                            eof                                     {break}
                        }
                    }";
            export HISTIGNORE=""
            cp -a '/etc/horde/passwd/backends.php' '/etc/horde/passwd/backends.local.php'
            echo "<?php
\$backends['sql'] = array(
    'disabled' => false,
    'name' => 'SQL Server',
    'driver' => 'Sql',
    'policy' => array(
        'minLength' => 7,
        'maxLength' => 64,
        'maxSpace' => 0,
        'minNumeric' => 1,
    ),
    'params' => array(
        'phptype' => 'mysql',
        'hostspec' => 'localhost',
        'username' => 'root',
        'password' => '${mariadbpassword}',
        'encryption' => 'crypt-md5',
        'database' => '${databasename}',
        'table' => 'mail_user',
        'user_col' => 'email',
        'pass_col' => 'password',
        'show_encryption' => false
    ),
);" > '/etc/horde/passwd/backends.local.php'
            echo '<?php
/* CONFIG START. DO NOT CHANGE ANYTHING IN OR AFTER THIS LINE. */
// $Id: afef93e939103554c1ec47b6cb4ae47e8ed5145b $
$conf["backend"]["backend_list"] = "shown";
$conf["user"]["change"] = true;
$conf["user"]["refused"] = array("root", "bin", "daemon", "adm", "lp", "shutdown", "halt", "uucp", "ftp", "anonymous", "nobody", "httpd", "operator", "guest", "diginext", "bind", "cyrus", "courier", "games", "kmem", "mailnull", "man", "mysql", "news", "postfix", "sshd", "tty", "www");
$conf["password"]["strengthtests"] = true;
/* CONFIG END. DO NOT CHANGE ANYTHING IN OR BEFORE THIS LINE. */' > '/etc/horde/passwd/conf.php'
            chown www-data '/etc/horde/passwd/backends.local.php'
            chown www-data '/etc/horde/passwd/conf.php'
            ;;
        *)  echo ""
    esac
}

applyLogJam () {
    cd "${curPath}"
    case "${logjam}" in
        y)  echo "Applying LogJam security measures"
            # Generate new DH cert
            openssl dhparam -out "/etc/ssl/private/dh-${dhkeysize}.pem" ${dhkeysize}
            # Secure Apache2
            updateSettings "/etc/apache2/mods-available/ssl.conf" 'SSLHonorCipherOrder' '        SSLHonorCipherOrder on'
            updateSettings "/etc/apache2/mods-available/ssl.conf" 'SSLStrictSNIVHostCheck On' "        #SSLStrictSNIVHostCheck On\n        SSLOpenSSLConfCmd DHParameters \"\/etc\/ssl\/private\/dh-${dhkeysize}.pem\""
            # Secure Postfix
            postconf -e "smtpd_tls_mandatory_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CDC3-SHA, KRB5-DE5, CBC3-SHA"
            postconf -e "smtpd_tls_dh1024_param_file = /etc/ssl/private/dh-${dhkeysize}.pem"
            # Secure Dovecot
            echo 'ssl_cipher_list=ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA' >> '/etc/dovecot/dovecot.conf'
            echo 'ssl_prefer_server_ciphers = yes' >> '/etc/dovecot/dovecot.conf'
            echo "ssl_dh_parameters_length = ${dhkeysize}" >> '/etc/dovecot/dovecot.conf'
            # PureFTPD -> The Wrapper Script is already fine, only the TLSCipherSuite needs adjustement
            echo 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA' > '/etc/pure-ftpd/conf/TLSCipherSuite'
            systemctl restart apache2
            systemctl restart postfix
            systemctl restart dovecot
            systemctl restart pure-ftpd-mysql
            ;;
        *)  echo ""
    esac
}

# Check for valid config file
confCheck


# Set default shell to bash
echo "dash dash/sh boolean false" | debconf-set-selections
dpkg-reconfigure -f noninteractive dash > /dev/null 2>&1

# Run the individual functions
configureNetwork
installPackages
configureMariaDB
configurePostfix
configureAmavisdSpamassassinClamav
configureApache
configureLetsEncrypt
configurePHPFPM
configureMailman
configurePureFTPd
configureQuota
configureAWstats
configureJailkit
configureFail2ban
configureUFW
configureRoundCube
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
echo "and Horde (if installed) can be access on any domain (or IP) as /horde e.g. http://${hostname}.${domain}/horde"
echo "and Roundcube (if installed) can be access on any domain (or IP) as /webmail, e.g. http://${hostname}.${domain}/webmail"
