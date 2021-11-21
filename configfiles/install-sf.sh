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
    /usr/bin/logger 'install_prerequisites' -t 'SpiderFoot-2021-11-21';
    echo -e "\e[1;32m--------------------------------------------\e[0m";
    echo -e "\e[1;32mInstalling Prerequisite packages\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    /usr/bin/logger "Operating System: $OS Version: $VER" -t 'SpiderFoot-2021-11-21';
    echo -e "\e[1;32mOperating System: $OS Version: $VER\e[0m";
  # Install prerequisites
    apt-get update;
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'SpiderFoot-2021-11-21';
    apt-get -y install adduser wget whois unzip apt-transport-https ca-certificates curl gnupg2 \
        software-properties-common dnsutils iptables libsqlite3-dev zlib1g-dev libfontconfig libfontconfig-dev \
        python2 dirmngr --install-recommends;
    # Set correct locale
    locale-gen;
    update-locale;
    # Install other preferences and clean up APT
    /usr/bin/logger '....Install some preferences on Debian and clean up APT' -t 'SpiderFoot-2021-11-21';
    apt-get -y install bash-completion sudo;
    # A little apt cleanup
    apt-get -y install --fix-missing;
    apt-get update;
    apt-get -y full-upgrade;
    apt-get -y autoremove --purge;
    apt-get -y autoclean;
    apt-get -y clean;
    /usr/bin/logger 'install_prerequisites finished' -t 'SpiderFoot-2021-11-21';
}

install_nginx() {
    /usr/bin/logger 'install_nginx()' -t 'SpiderFoot-2021-11-21';
    apt-get -y install nginx apache2-utils;
    /usr/bin/logger 'install_nginx() finished' -t 'SpiderFoot-2021-11-21';
}

install_spiderfoot() {
    /usr/bin/logger 'install_spiderfoot()' -t 'SpiderFoot-2021-11-21';
    cd /opt/;
    git clone https://github.com/smicallef/spiderfoot.git;
    cd /opt/spiderfoot/;
    python3 -m pip install -r requirements.txt; 
    /usr/bin/logger 'install_spiderfoot() finished' -t 'SpiderFoot-2021-11-21';
}

generate_certificates() {
    /usr/bin/logger 'generate_certificates()' -t 'SpiderFoot-2021-11-21';
    mkdir -p /etc/nginx/certs/;

    # organization name
    # (see also https://www.switch.ch/pki/participants/)
    export ORGNAME=spiderfoot-ce
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
    /usr/bin/logger 'generate_certificates() finished' -t 'SpiderFoot-2021-11-21';
}

prepare_nix() {
    /usr/bin/logger 'prepare_nix()' -t 'SpiderFoot-2021-11-21';
    echo -e "\e[1;32mCreating Users, configuring sudoers, and setting locale\e[0m";
    # set desired locale
    localectl set-locale en_US.UTF-8;
    # Create spiderfoot user
    /usr/sbin/useradd --system -c "SpiderFoot User" --home-dir /opt/spiderfoot-ce/ --shell /bin/bash spiderfoot;

    # Configure sudoers to allow spiderfoot
    cat << __EOF__ > /etc/sudoers.d/spiderfoot
spiderfoot     ALL = NOPASSWD: ALL
__EOF__

    # Configure MOTD
    BUILDDATE=$(date +%Y-%m-%d)
    cat << __EOF__ >> /etc/motd
           
        $HOSTNAME
        
*******************************************
***                                     ***
***             OSINT                   ***
***    ------------------------         ***          
***      Automated Install              ***
***         SpiderFoot                  ***
***     Build date $BUILDDATE           ***
***                                     ***
********************||*********************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ
     Automated install v1.0
            2021-11-21

__EOF__
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd
    sync;
    /usr/bin/logger 'prepare_nix() finished' -t 'SpiderFoot-2021-11-21';
}

start_services() {
    /usr/bin/logger 'start_services' -t 'SpiderFoot-2021-11-21';
    # Load new/changed systemd-unitfiles
    systemctl daemon-reload;
    # Enable services
    systemctl enable spiderfoot.service;
    systemctl enable nginx.service;
    # Start
    systemctl restart spiderfoot.service;
    systemctl restart nginx.service;
    /usr/bin/logger 'start_services finished' -t 'SpiderFoot-2021-11-21';
}

check_services() {
    /usr/bin/logger 'check_services' -t 'SpiderFoot-2021-11-21';
    # Check status of critical services
    echo -e;
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mChecking core daemons for SpiderFoot......\e[0m";
    if systemctl is-active --quiet nginx.service;
        then
            echo -e "\e[1;32mnginx webserver started successfully";
            /usr/bin/logger 'nginx webserver started successfully' -t 'SpiderFoot-2021-11-21';
        else
            echo -e "\e[1;31mnginx webserver FAILED!\e[0m";
            /usr/bin/logger 'nginx webserver FAILED' -t 'SpiderFoot-2021-11-21';
    fi
    # SpiderFoot.service.service
    if systemctl is-active --quiet spiderfoot.service;
        then
            echo -e "\e[1;32mSpiderFoot service started successfully";
            /usr/bin/logger 'SpiderFoot service started successfully' -t 'SpiderFoot-2021-11-21';
        else
            echo -e "\e[1;31mSpiderFoot service FAILED!\e[0m";
            /usr/bin/logger "SpiderFoot service FAILED!" -t 'SpiderFoot-2021-11-21';
    fi
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e;
   /usr/bin/logger 'check_services finished' -t 'SpiderFoot-2021-11-21';
}

configure_nginx() {
    /usr/bin/logger 'configure_nginx()' -t 'SpiderFoot-2021-11-21';
    # Change ROOTCA to point to correct cert when/if not using self signed cert.
    export ROOTCA=$HOSTNAME
    openssl dhparam -out /etc/nginx/dhparam.pem 2048
    # TLS
    cat << __EOF__ > /etc/nginx/sites-available/default;
#
# Changed by: Martin Boller
#         secuuru.dk
# Email: martin.boller@secuuru.dk
# Last Update: 2021-11-21
#
# reverse proxy configuration for SpiderFoot
# Running spiderfoot on port 443 TLS
##

server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    client_max_body_size 32M;
    listen 443 ssl http2;
    ssl_certificate           /etc/nginx/certs/$HOSTNAME.crt;
    ssl_certificate_key       /etc/nginx/certs/$HOSTNAME.key;
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

### SpiderFoot on port 5001
    location / {
      # Access log for spiderfoot
      access_log            /var/log/nginx/spiderfoot.access.log;
      proxy_set_header        Host \$host;
      proxy_set_header        X-Real-IP \$remote_addr;
      proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto \$scheme;

      # Fix the “It appears that your reverse proxy set up is broken" error.
      proxy_pass          http://localhost:5001;
      proxy_read_timeout  90;

      proxy_redirect      http://localhost:5001 https://$HOSTNAME;
    }

## NGINX Server status on /server-status
    location /server-status {
                        stub_status on;
                        access_log   off;
                        auth_basic      "spiderfoot Login";
                        auth_basic_user_file  /etc/nginx/.htpasswd;
                        allow all;
    }
  }
__EOF__
    /usr/bin/logger 'configure_nginx() finished' -t 'SpiderFoot-2021-11-21';
}

configure_spiderfoot() {
    /usr/bin/logger 'configure_spiderfoot()' -t 'SpiderFoot-2021-11-21';
    cat << __EOF__  >  /lib/systemd/system/spiderfoot.service
[Unit]
Description=Regular background program processing daemon
Documentation=None
After=networking.service
Requires=networking.service

[Service]
WorkingDirectory=/opt/spiderfoot/
ExecStart=-/usr/bin/python3 /opt/spiderfoot/sf.py -l 0.0.0.0:5001
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
__EOF__
    sync;
    systemctl daemon-reload;
    systemctl enable spiderfoot.service;
    systemctl start spiderfoot.service;
    /usr/bin/logger 'configure_spiderfoot() finished' -t 'SpiderFoot-2021-11-21';
}

configure_permissions() {
    /usr/bin/logger 'configure_permissions()' -t 'SpiderFoot-2021-11-21';
    chown -R spiderfoot:spiderfoot /opt/spiderfoot/;
    /usr/bin/logger 'configure_permissions() finished' -t 'SpiderFoot-2021-11-21';
}

configure_iptables() {
    /usr/bin/logger 'configure_iptables() started' -t 'bSIEM Step2';
    echo -e "\e[32mconfigure_iptables()\e[0m";
    echo -e "\e[32m-Creating iptables rules file\e[0m";
    cat << __EOF__  >> /etc/network/iptables.rules
##
## Ruleset for spiderfoot Server
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

## Allow access to port 5001
##-A OUTPUT -p tcp -m tcp --dport 5001 -j ACCEPT
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
    /usr/bin/logger 'create_htpasswd()' -t 'spiderfoot';
    export HT_PASSWD="$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 32)"
    mkdir -p /mnt/backup/;
    htpasswd -cb /etc/nginx/.htpasswd spiderfoot $HT_PASSWD;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    echo "Created password for Apache $HOSTNAME spiderfoot:$ht_passwd"  >> /mnt/backup/readme-users.txt;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    /usr/bin/logger 'create_htpasswd() finished' -t 'spiderfoot';
}

finish_reboot() {
    secs=30
    echo -e;
    echo -e "\e[1;32m--------------------------------------------\e[0m";
        while [ $secs -gt 0 ]; do
            echo -ne "\e[1;32mRebooting in (seconds): "
            echo -ne "\e[1;31m$secs\033[0K\r"
            sleep 1
            : $((secs--))
        done;
    sync;
    echo -e
    echo -e "\e[1;31mREBOOTING!\e[0m";
    /usr/bin/logger 'Rebooting!!' -t 'SpiderFoot-2021-11-21'
    reboot;
}

configure_users() {
    randompw=$(strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 64 | tr -d '\n');
    echo root:$randompw | chpasswd;
    usermod root --lock;
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    /usr/bin/logger 'Installing spiderfoot.......' -t 'SpiderFoot-2021-11-21';
     # install all required elements and generate certificates for webserver
    install_prerequisites;
    prepare_nix;
    generate_certificates;
    install_nginx;
    install_spiderfoot;
    # Configure components
    configure_nginx;
    configure_spiderfoot;
    configure_iptables;
    create_htpasswd;
    start_services;
    configure_permissions;
    check_services;
    /usr/bin/logger 'spiderfoot Installation complete' -t 'SpiderFoot-2021-11-21';
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mspiderfoot Installation complete\e[0m"
    echo -e "\e[1;32mNow restore your stored configuration to SpiderFoot or start\e[0m"
    echo -e "\e[1;32mconfiguring it from scratch\e[0m"
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    finish_reboot;
}

main;

exit 0;

######################################################################################################################################
# Post install 
# 
#