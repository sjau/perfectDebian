perfectDebian
=============

An installer script to automate a "Perfect Debian Server" for ISPConfig according to falko's instructions



Howto Use
=============

1. Install a basic debian system according to pages 1-2 here: http://www.howtoforge.com/perfect-server-debian-wheezy-apache2-bind-dovecot-ispconfig-3

2. Install git: apt-get install git

3. Clone this repository: git clone https://github.com/sjau/perfectDebian.git

4. Go into the perfectDebian folder: cd perfectDebian

5. Edit the install.sh file and set your settings

6. Run the script: ./install.sh



Limitations
=============

- This script is soley aimed to install ISPConfig on Debian Stable

- This script supports only 1 ethernet device and only 1 static IPv4 address -> if you have more devices and IPs, configure them after running

- This script assumes that quota is only to be enabled on the root-partition. If you have multiple partitions you need to manually alter the fstab entry