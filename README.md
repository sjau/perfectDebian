perfectDebian
=============

An installer script to automate a "Perfect Debian Server" for ISPConfig according to till's instructions here:

Detailed installation steps at https://www.howtoforge.com/tutorial/perfect-server-debian-9-stretch-apache-bind-dovecot-ispconfig-3-1/



Howto Use
=============

1. Install a basic debian system

2. Install git: apt-get install git

3. Clone this repository: git clone https://github.com/sjau/perfectDebian.git

4. Go into the perfectDebian folder: cd perfectDebian

5. Run the script: ./install.sh

    --> it will create a "config.conf" file in the same location as the installer script.
    
6. Set according vars in the config.conf script

7. Run the script again:  ./install.sh



Limitations
=============

- This script is soley aimed to install ISPConfig, Roundcube and Horde on Debian Stretch

- This script supports only 1 ethernet device and only 1 static IPv4 address -> if you have more devices and IPs, configure them after running

- This script assumes that quota is only to be enabled on the root-partition. If you have multiple partitions you need to manually alter the fstab entry
