#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin                                                      #
# Last Update:  2021-11-15                                                  #
# Version:      1.00                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
#                                                                           #
# Info:                                                                     #
#                                                                           #
#                                                                           #
# Instruction:  Run this script as root on a fully updated                  #
#               Debian 10 (Buster) or Debian 11 (Bullseye)                  #
#                                                                           #
#############################################################################


install_prerequisites() {
    /usr/bin/logger 'install_prerequisites' -t 'dradisce-2021-11-15';
    echo -e "\e[1;32m--------------------------------------------\e[0m";
    echo -e "\e[1;32mInstalling Prerequisite packages\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    /usr/bin/logger "Operating System: $OS Version: $VER" -t 'dradisce-2021-11-15';
    echo -e "\e[1;32mOperating System: $OS Version: $VER\e[0m";
  # Install prerequisites
    apt-get update;
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'dradisce-2021-11-15';
    #apt-get -y install --fix-policy;
    apt-get -y install adduser wget whois unzip apt-transport-https ca-certificates curl gnupg2 software-properties-common dnsutils \
        iptables mysql-server mysql-client libmysqlclient-dev libfontconfig libfontconfig-dev dirmngr --install-recommends;
    # Set correct locale
    locale-gen;
    update-locale;
    # Install other preferences and clean up APT
    /usr/bin/logger '....Install some preferences on Debian and clean up APT' -t 'dradisce-2021-11-15';
    apt-get -y install bash-completion sudo;
    # A little apt cleanup
    apt-get -y install --fix-missing;
    apt-get update;
    apt-get -y full-upgrade;
    apt-get -y autoremove --purge;
    apt-get -y autoclean;
    apt-get -y clean;
    /usr/bin/logger 'install_prerequisites finished' -t 'dradisce-2021-11-15';
}

install_nginx() {
    /usr/bin/logger 'install_nginx()' -t 'dradisce-2021-11-15';
    apt-get -y install nginx apache2-utils;
    /usr/bin/logger 'install_nginx() finished' -t 'dradisce-2021-11-15';
}

install_redis() {
    /usr/bin/logger 'install_redis()' -t 'dradisce-2021-11-15';
    apt-get -y install redis-server;
    /usr/bin/logger 'install_redis() finished' -t 'dradisce-2021-11-15';
}

install_dradis() {    
    /usr/bin/logger 'install_dradis()' -t 'dradisce-2021-11-15';
    echo -e "\e[1;32mPreparing Eramba Source files\e[0m";
    mkdir -p /opt/;
    cd /opt/;
    git clone https://github.com/dradis/dradis-ce.git
    cd dradis-ce;
    ./bin/setup;
    sync;   
    /usr/bin/logger 'install_dradis finished' -t 'dradisce-2021-11-15';
}

generate_certificates() {
    /usr/bin/logger 'generate_certificates()' -t 'dradisce-2021-11-15';
    mkdir -p /etc/nginx/certs/;

    # organization name
    # (see also https://www.switch.ch/pki/participants/)
    export ORGNAME=dradis-ce
    # the fully qualified server (or service) name, change if other servicename than hostname
    export FQDN=$HOSTNAME;
    # Local information
    export ISOCOUNTRY=DK;
    export PROVINCE=Denmark;
    export LOCALITY=Aabenraa
    # subjectAltName entries: to add DNS aliases to the CSR, delete
    # the '#' character in the ALTNAMES line, and change the subsequent
    # 'DNS:' entries accordingly. Please note: all DNS names must
    # resolve to the same IP address as the FQDN.
    export ALTNAMES=DNS:$HOSTNAME   # , DNS:bar.example.org , DNS:www.foo.example.org

    cat << __EOF__ > ./openssl.cnf
## Request for $FQDN
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
countryName         = $ISOCOUNTRY
stateOrProvinceName = $PROVINCE
localityName        = $LOCALITY
organizationName    = $ORGNAME
CN = $FQDN

[ req_ext ]
subjectAltName = $ALTNAMES
__EOF__
    sync;
    # generate Certificate Signing Request to send to corp PKI
    openssl req -new -config openssl.cnf -keyout /etc/nginx/certs/$HOSTNAME.key -out /etc/nginx/certs/$HOSTNAME.csr
    # generate self-signed certificate (remove when CSR can be sent to Corp PKI)
    openssl x509 -in /etc/nginx/certs/$HOSTNAME.csr -out /etc/nginx/certs/$HOSTNAME.crt -req -signkey /etc/nginx/certs/$HOSTNAME.key -days 365
    chmod 600 /etc/nginx/certs/$HOSTNAME.key
    /usr/bin/logger 'generate_certificates() finished' -t 'dradisce-2021-11-15';
}

prepare_nix() {
    /usr/bin/logger 'prepare_nix()' -t 'gse-21.4';
    echo -e "\e[1;32mCreating Users, configuring sudoers, and setting locale\e[0m";
    # set desired locale
    localectl set-locale en_US.UTF-8;
    # Create dradis user
    /usr/sbin/useradd --system -c "Dradis Community Edition User" --shell /bin/bash dradis;
    # Configure MOTD
    BUILDDATE=$(date +%Y-%m-%d)
    cat << __EOF__ >> /etc/motd
           
        $HOSTNAME
        
*******************************************
***                                     ***
***        Pentest Reporting            ***
***    ------------------------         ***          
***      Automated Install              ***
***   Dradis Community Edition          ***
***     Build date $BUILDDATE           ***
***                                     ***
********************||*********************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ
     Automated install v1.0
            2021-11-15

__EOF__
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd
    sync;
    /usr/bin/logger 'prepare_nix() finished' -t 'dradisce-2021-11-15';
}

start_services() {
    /usr/bin/logger 'start_services' -t 'dradisce-2021-11-15';
    # Load new/changed systemd-unitfiles
    systemctl daemon-reload;
    # Enable services
    systemctl enable nginx.service;
    systemctl enable dradisce.service;
    # Start
    systemctl restart dradisce.service;
    systemctl restart nginx;
    /usr/bin/logger 'start_services finished' -t 'dradisce-2021-11-15';
}

check_services() {
    /usr/bin/logger 'check_services' -t 'dradisce-2021-11-15';
    # Check status of critical services
    # Apache
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mChecking core daemons for Eramba......\e[0m";
    if systemctl is-active --quiet nginx.service;
        then
            echo -e "\e[1;32mnginx webserver started successfully";
            /usr/bin/logger 'nginx webserver started successfully' -t 'dradisce-2021-11-15';
        else
            echo -e "\e[1;31mnginx webserver FAILED!\e[0m";
            /usr/bin/logger 'nginx webserver FAILED' -t 'dradisce-2021-11-15';
    fi
    # dradisce.service.service
    if systemctl is-active --quiet redis-server.service;
        then
            echo -e "\e[1;32mredis service started successfully";
            /usr/bin/logger 'redis service started successfully' -t 'dradisce-2021-11-15';
        else
            echo -e "\e[1;31mredis service FAILED!\e[0m";
            /usr/bin/logger "redis service FAILED!" -t 'dradisce-2021-11-15';
    fi
    /usr/bin/logger 'check_services finished' -t 'dradisce-2021-11-15';
}


configure_nginx() {
    /usr/bin/logger 'configure_nginx()' -t 'dradisce-2021-11-15';
    # Change ROOTCA to point to correct cert when/if not using self signed cert.
    export ROOTCA=$HOSTNAME
    
    # TLS
    cat << __EOF__ > /etc/nginx/sites-available/default;
#
# Changed by: Martin Boller
#         secuuru.dk
# Email: martin.boller@secuuru.dk
# Last Update: 2021-11-16
#
# reverse proxy configuration for Dradis Community Edition
# Running Dradis on port 443 TLS
##

server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    client_max_body_size 32M;
    listen 443 ssl http2;
    ssl_certificate           /etc/nginx/certs/$HOSTNAME.crt;
    ssl_certificate_key       /etc/elasticsearch/certs/$HOSTNAME.key;
    ssl on;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
    ssl_prefer_server_ciphers on;
    # Enable HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    # Optimize session cache
    ssl_session_cache   shared:SSL:40m;
    ssl_session_timeout 4h;  # Enable session tickets
    ssl_session_tickets on;
    # Diffie Hellman Parameters
    ssl_dhparam /etc/nginx/dhparam.pem;

### Dradis on port 3000
    location / {
      # Access log for Dradis
      access_log            /var/log/nginx/dradis.access.log;
      proxy_set_header        Host $host;
      proxy_set_header        X-Real-IP $remote_addr;
      proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto $scheme;

      # Fix the “It appears that your reverse proxy set up is broken" error.
      proxy_pass          http://localhost:3000;
      proxy_read_timeout  90;

      proxy_redirect      http://localhost:3000 https://$HOSTNAME;
    }

## NGINX Server status on /server-status
    location /server-status {
                        stub_status on;
                        access_log   off;
                        auth_basic      "dradis Login";
                        auth_basic_user_file  /etc/nginx/.htpasswd;
                        allow all;
    }
  }
__EOF__
    /usr/bin/logger 'configure_nginx() finished' -t 'dradisce-2021-11-15';
}

configure_dradis() {
    /usr/bin/logger 'configure_dradis()' -t 'dradisce-2021-11-15';
    cat << __EOF__  >  /lib/systemd/system/dradisce.service
[Unit]
Description=Dradis Community Edition
Documentation=https://github.com/dradis/
Wants=network-online.target
After=network.target network-online.target
Requires=redis-server.service

[Service]
User=dradis
Group=dradis
ExecStart=/opt/dradis-ce/bin/rails server
WorkingDirectory=/opt/dradis-ce

[Install]
WantedBy=multi-user.target
__EOF__

    sync;
    systemctl daemon-reload;
    systemctl enable dradisCE.service;
    systemctl start dradisCE.service;
    /usr/bin/logger 'configure_dradis() finished' -t 'dradisce-2021-11-15';
}

configure_permissions() {
    /usr/bin/logger 'configure_permissions()' -t 'dradisce-2021-11-15';
    chown -R dradis:dradis /opt/dradis-ce/;
    /usr/bin/logger 'configure_permissions() finished' -t 'dradisce-2021-11-15';
}

configure_iptables() {
    /usr/bin/logger 'configure_iptables() started' -t 'bSIEM Step2';
    echo -e "\e[32mconfigure_iptables()\e[0m";
    echo -e "\e[32m-Creating iptables rules file\e[0m";
    cat << __EOF__  >> /etc/network/iptables.rules
##
## Ruleset for Eramba Server
##
## IPTABLES Ruleset Author: Martin Boller 2021-11-11 v1

*filter
## Dropping anything not explicitly allowed
##
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:LOG_DROPS - [0:0]

## DROP IP fragments
-A INPUT -f -j LOG_DROPS
-A INPUT -m ttl --ttl-lt 4 -j LOG_DROPS

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Allow everything on loopback
-A INPUT -i lo -j ACCEPT

## SSH, DNS, WHOIS, DHCP ICMP - Add anything else here needed for ntp, monitoring, dhcp, icmp, updates, and ssh
##
## SSH
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
## DNS
-A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 853 -j ACCEPT
## HTTP(S)
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
## NTP
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
-A OUTPUT -p udp -m udp --dport 123 -j ACCEPT
## DHCP
-A OUTPUT -p udp -m udp --dport 67 -j ACCEPT
## ICMP
-A OUTPUT -p icmp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
## Already established sessions
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## Logging
-A OUTPUT -j LOG_DROPS
## get rid of broadcast noise
-A LOG_DROPS -d 255.255.255.255 -j DROP
# Drop Broadcast to internal networks
-A LOG_DROPS -m pkttype --pkt-type broadcast -d 192.168.0.0/16 -j DROP
-A LOG_DROPS -p ip -m limit --limit 60/sec -j LOG --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit everything
COMMIT
__EOF__

    # Configure separate file for iptables logging
    cat << __EOF__  >> /etc/rsyslog.d/30-iptables-syslog.conf
:msg,contains,"iptables:" /var/log/iptables.log
& stop
__EOF__
    sync;
    systemctl restart rsyslog.service;

    # Configure daily logrotation (forward this log to log mgmt)
    cat << __EOF__  >> /etc/logrotate.d/iptables
/var/log/iptables.log {
  rotate 2
  daily
  compress
  create 640 root root
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__

# Apply iptables at boot
    echo -e "\e[36m-Script applying iptables rules\e[0m";
    cat << __EOF__  >> /etc/network/if-up.d/firewallrules
#! /bin/bash
iptables-restore < /etc/network/iptables.rules
exit 0
__EOF__
    sync;
    ## make the script executable
    chmod +x /etc/network/if-up.d/firewallrules;
    # Apply firewall rules for the first time
    #/etc/network/if-up.d/firewallrules;
    /usr/bin/logger 'configure_iptables() done' -t 'Firewall setup';
}

create_htpasswd() {
    /usr/bin/logger 'create_htpasswd()' -t 'eramba';
    export HT_PASSWD="$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 32)"
    mkdir -p /mnt/backup/;
    htpasswd -cb /etc/nginx/.htpasswd eramba $HT_PASSWD;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    echo "Created password for Apache $HOSTNAME     eramba:$ht_passwd"  >> /mnt/backup/readme-users.txt;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    /usr/bin/logger 'create_htpasswd() finished' -t 'eramba';
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    /usr/bin/logger 'Installing Dradis Community Edition.......' -t 'dradisce-2021-11-15';
     # install all required elements and generate certificates for webserver
    install_prerequisites;
    prepare_nix;
    generate_certificates;
    install_nginx;
    install_redis;
    install_dradis;
    # Configure components
    configure_nginx;
    configure_dradis;
    configure_iptables;
    create_htpasswd;
    start_services;
    configure_permissions;
    check_services;
    /usr/bin/logger 'Dradis Community Edition Installation complete' -t 'dradisce-2021-11-15';
}

main;

exit 0;

######################################################################################################################################
# Post install 
# 
#