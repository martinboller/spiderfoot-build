# SpiderFoot Installation script

### Bash script automating the installation of SpiderFoot on Debian 11

## Vagrantfile and bootstrap.sh for use with Vagrant and Virtualbox

### Design principles:
  - Dedicated to SpiderFoot, nothing else
  - Use the defaults where possible
  - Least access

### Known issues:
  - Currently using self signed cert, but the CSR is there so send that to Issuing CA instead
  - ~~Not tested with anything else than Debian 11 (Bullseye)~~

### Latest changes 
#### 2021-11-21 - Initial version
  Version 1.00

Run the script /root/install-sf as root to install SpiderFoot on either the Vagrant lab Debian OS (see below) or any other Debian 11 platform.

>**Important: Do NOT use the process below for production, as Vagrant leaves some unfortunate security artifacts behind. The install-SpiderFoot.sh alone can be used on a known secure installation of Debian 11, or you could remove Vagrant artifacts (the former is preferred)**

## Quick installation - If you just want to get on with it
### Packages required
All that is needed to spin up test systems is:
 - VirtualBox https://www.virtualbox.org/
 - Vagrant https://www.vagrantup.com/downloads
 
### Installation
#### VirtualBox
 - Install VirtualBox on your preferred system (MacOS or Linux is preferred) as described on the VirtualBox website
 - Install the VirtualBox Extensions

Both software titles can be downloaded from https://www.virtualbox.org/
They can also be added to your package manager, which help with keeping them up-to-date. This can also easily be changed to run with VMWare.
 
#### Vagrant
 - Install Vagrant on your system as described on the Vagrant website

Vagrant is available at https://www.vagrantup.com/downloads
 
#### Testlab
Prerequisite: A DHCP server on the network, alternatively change the NIC to use a static or NAT within Vagrantfile.
 - Create a directory with ample space for Virtual Machines, e.g. /mnt/data/VMs
 - Configure VirtualBox to use that directory for Virtual Machines by default.
 - Change directory into /mnt/data/Environments/
 - Run git clone https://github.com/martinboller/sf-build.git
 - Change directory into /mnt/data/Environments/sf-build/
 - Execute vagrant up SpiderFoot and wait for the OS to install

hostname: arakno (can be changed in Vagrantfile)

You may have to select which NIC to use for this e.g. wl08p01
Logon to the website on the server https://arakno (if you have not changed the hostname and DNS works. If not, use the ip address)
 
The first install will take longer, as it needs to download the Vagrant box for Debian 11 (which this build is based on) first, however that’ll be reused in subsequent (re)installations.