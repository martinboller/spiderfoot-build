#! /bin/bash

#####################################################################
#                                                                   #
# Author:       Martin Boller                                       #
#                                                                   #
# Email:        martin                                              #
# Last Update:  2021-11-10                                          #
# Version:      1.00                                                #
#                                                                   #
# Changes:      First version for arakno (1.00)                     #
#                                                                   #
#                                                                   #
#####################################################################

configure_locale() {
  echo -e "\e[32mconfigure_locale()\e[0m";
  echo -e "\e[36m-Configure locale (default:C.UTF-8)\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
 cat << __EOF__  > /etc/default/locale
# /etc/default/locale
LANG=C.UTF-8
LANGUAGE=C.UTF-8
LC_ALL=C.UTF-8
__EOF__
  update-locale;
  /usr/bin/logger 'configure_locale()' -t 'SpiderFoot';
}

configure_timezone() {
  echo -e "\e[32mconfigure_timezone()\e[0m";
  echo -e "\e[36m-Set timezone to Etc/UTC\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  rm /etc/localtime;
  echo 'Etc/UTC' > /etc/timezone;
  dpkg-reconfigure -f noninteractive tzdata;
  /usr/bin/logger 'configure_timezone()' -t 'SpiderFoot';
}

apt_install_prerequisites() {
    # Install prerequisites and useful tools
    export DEBIAN_FRONTEND=noninteractive;
    apt-get -y remove postfix*;
        sync \
        && apt-get update \
        && apt-get -y full-upgrade \
        && apt-get -y --purge autoremove \
        && apt-get autoclean \
        && sync;
        /usr/bin/logger 'install_updates()' -t 'SpiderFoot';
    sed -i '/dns-nameserver/d' /etc/network/interfaces;
    ifdown eth0; ifup eth0;
    # Remove memcached on vagrant box
    apt-get -y purge memcached;
    # copy relevant scripts
    /bin/cp /tmp/configfiles/Servers/*.sh /root/;
    /bin/cp /tmp/configfiles/Servers/*.cfg /root/;
    chmod +x /root/*.sh;
    /usr/bin/logger 'apt_install_prerequisites()' -t 'SpiderFoot';
}

install_ssh_keys() {
    # Echo add SSH public key for root logon
    export DEBIAN_FRONTEND=noninteractive;
    mkdir /root/.ssh;
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIHJYsxpawSLfmIAZTPWdWe2xLAH758JjNs5/Z2pPWYm" | tee -a /root/.ssh/authorized_keys;
    chmod 700 /root/.ssh;
    chmod 600 /root/.ssh/authorized_keys;
    /usr/bin/logger 'install_ssh_keys()' -t 'SpiderFoot';
}

create_htpasswd() {
    /usr/bin/logger 'create_htpasswd() finished' -t 'SpiderFoot';
    export ht_passwd="$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 32)"
    mkdir -p /mnt/backup/;
    htpasswd -cb /etc/nginx/.htpasswd  $HT_PASSWD;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    echo "Created password for Apache $HOSTNAME alerta:$ht_passwd"  >> /mnt/backup/readme-users.txt;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    /usr/bin/logger 'create_htpasswd() finished' -t 'SpiderFoot';
    systemctl restart nginx.service;
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    export DOMAINNAME=bollers.dk;
    # Core elements, always installs
    /usr/bin/logger '!!!!! Main routine starting' -t 'SpiderFoot';
    hostnamectl set-hostname $HOSTNAME.$DOMAINNAME;
    # Do not forget to add your own public SSH Key(s) instead of dummy in install_ssh_keys()
    install_ssh_keys;
    configure_timezone;
    apt_install_prerequisites;
    configure_locale;
    configure_timezone;

    # copy relevant scripts
    /bin/cp /tmp/configfiles/* /root/;
    chmod +x /root/*.sh;
    apt-get -y install --fix-policy;
    touch /root/Ready_2_Start_Install
    echo -e "\e[1;32m------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mYou can now run ./install_sf.sh to install SpiderFoot\e[0m"
    echo -e "\e[1;32mNote that the ROOT user will be disabled after that\e[0m"
    echo -e "\e[1;32mLogin as spiderfoot in the future\e[0m"
    echo -e "\e[1;32m-------------------------------------------------------------\e[0m";
 
    /usr/bin/logger 'installation finished (Main routine finished)' -t 'SpiderFoot'; 
    #su root -c '/root/install-sf.sh';
}

main;

exit 0
