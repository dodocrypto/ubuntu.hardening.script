# [ 0day (xc) Our ] WhiteHat Hacker Team And Dev 2021 
# Ubuntu Linux 20.04 LTS Hardening 
# 26/01/2021
# Author : dodocrypto
# 
# Contact : Discord https://discord.me/0dev
# 
# How To Run : python3 ./0dev.ubuntu.py and monitor log of /root/0dev.log
# Enough Said Coding time. Ubuntu Linux 20.04 LTS
# Warning : The Setup Might Be slow as it running configuration and stuff just live it with out canceling it

import subprocess
import re
import sys
import datetime
import glob

##### Check If User is root , abort if not ##### 

with subprocess.Popen(['id'] , stdout = subprocess.PIPE  , stderr = subprocess.STDOUT ) as process:
    stdout , stderr = process.communicate()
    result = stdout.decode('utf-8')
    root = re.search("^uid=0" , result)
    if root == None:
        print (" You need root to run this script ")
        sys.exit(1)


### Begin Hardening

### Structure of Hardening , Break into couple of step

def main():
    step1()
    step2()
    step3()

def step1():
    with open("/root/0dev.log" , "a+", buffering = 1) as step1:            
        
        ### Upgrading System
        step1.write("\n# Updating Server")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y update"
        with subprocess.Popen( ['/bin/sh' , '-c' , cmd ] , stdout=step1 , stderr = step1 ) as cramfs:
            stdout , stderr = cramfs.communicate()
        
        step1.write("\n# Upgrading Server")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y upgrade"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd ] , stdout=step1 , stderr = step1 ) as cramfs:
            stdout , stderr = cramfs.communicate()

        # 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
        step1.write("\n# Begin Hardening ")
        step1.write ("\n# 1 : Setup Hardening Initial Setup\n# 1.1 : Disabled Unused File System\n# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled\n")
        
        with open ("/etc/modprobe.d/cramfs.conf" , "w" , buffering = 1 ) as cramfs:
            cramfs.write("install cramfs /bin/true")
        
        cmd = "rmmod cramfs"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as cramfs:
            stdout , stderr = cramfs.communicate()
        
        # 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
        step1.write("# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled \n")
        with open ("/etc/modprobe.d/freevxfs.conf" , "w" , buffering = 1 ) as freevxfs:
            freevxfs.write("install freevxfs /bin/true")
        
        cmd = "rmmod freevxfs"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as freevxfs:
            stdout , stderr = freevxfs.communicate()

        #1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
        step1.write("# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled\n")
        with open ("/etc/modprobe.d/jffs2.conf" , "w" , buffering = 1 ) as process1:
            process1.write("install jffs2 /bin/true")
        
        cmd = "rmmod jffs2"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        #1.1.1.4 Ensure mounting of hfs filesystems is disabled
        step1.write("# 1.1.1.4 Ensure mounting of hfs filesystems is disabled\n")
        with open ("/etc/modprobe.d/hfs.conf" , "w" , buffering = 1 ) as process1:
            process1.write("install hfs /bin/true")
        
        cmd = "rmmod hfs"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        #1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
        step1.write("# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled\n")
        with open ("/etc/modprobe.d/hfsplus.conf" , "w" , buffering = 1 ) as process1:
            process1.write("install hfsplus /bin/true")
        
        cmd = "rmmod hfsplus"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.1.6 Ensure mounting of udf filesystems is disabled
        step1.write("# 1.1.1.6 Ensure mounting of udf filesystems is disabled\n")
        with open ("/etc/modprobe.d/udf.conf" , "w" , buffering = 1 ) as process1:
            process1.write("install udf /bin/true")
        
        cmd = "rmmod udf"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.1.7 Ensure mounting of FAT filesystems is limited
        step1.write("# 1.1.1.7 Ensure mounting of FAT filesystems is limited\n")
        with open ("/etc/modprobe.d/vfat.conf" , "w" , buffering = 1 ) as process1:
            process1.write("install vfat /bin/true")
        
        cmd = "rmmod vfat"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.2 Ensure /tmp is configured
        step1.write("# 1.1.2 Ensure /tmp is configured\n")
        with open ("/etc/fstab" , "r" , buffering = 1 ) as process1:
            result_tmp = process1.read()
            

        with open ("/etc/fstab" , "w" , buffering = 1 ) as process1:
            result_tmp = re.sub(".*/tmp.*" , "" ,  result_tmp)
            process1.write(result_tmp)
            process1.write("\ntmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0")
        
        # 1.1.3 Ensure nodev option set on /tmp partition
        step1.write("# 1.1.3 Ensure nodev option set on /tmp partition \n")
        cmd = "mount -o remount,nodev /tmp"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.4 Ensure nosuid option set on /tmp partition
        step1.write("# 1.1.4 Ensure nosuid option set on /tmp partition\n")
        cmd = "mount -o remount,nosuid /tmp"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.5 Ensure noexec option set on /tmp partition
        step1.write("# 1.1.5 Ensure noexec option set on /tmp partition\n")
        cmd = "mount -o remount,noexec /tmp"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.6 Ensure /dev/shm is configured
        step1.write("# 1.1.6 Ensure /dev/shm is configured\n")
        with open ("/etc/fstab" , "r" , buffering = 1 ) as process1:
            result_tmp = process1.read()
            result_tmp = re.sub(".*/dev/shm.*" , "" ,  result_tmp)

        with open ("/etc/fstab" , "w" , buffering = 1 ) as process1:
            process1.write(result_tmp)
            process1.write("\ntmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,size=2G 0 0")
        cmd = "mount -o remount,noexec,nodev,nosuid /dev/shm"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.7 Ensure nodev option set on /dev/shm partition
        step1.write("# 1.1.7 Ensure nodev option set on /dev/shm partition\n")
        cmd = "mount -o remount,nodev /dev/shm"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.8 Ensure nosuid option set on /dev/shm partition
        step1.write("# 1.1.8 Ensure nosuid option set on /dev/shm partition\n")
        cmd = "mount -o remount,nosuid /dev/shm"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        
        # 1.1.9 Ensure noexec option set on /dev/shm partition
        step1.write("# 1.1.9 Ensure noexec option set on /dev/shm partition\n")
        cmd = "mount -o remount,noexec /dev/shm"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        
        ##### We Skipped Configuring /home /var/tmp /var /var/log /var/audit. Please Do it yourself
        step1.write("# We Skipped Configuring /home /var /var/tmp /var/log /var/audit. Please Do it yourself\n")
        
        # 1.1.22 Ensure sticky bit is set on all world-writable directories
        step1.write("# 1.1.22 Ensure sticky bit is set on all world-writable directories\n")
        cmd =  "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'"
        with subprocess.Popen(['/bin/sh' , '-c', cmd], stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.1.23 Disable Automounting
        step1.write("# 1.1.23 Disable Automounting\n")
        cmd =  "systemctl --now mask autofs"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        
        # 1.1.24 Disable USB Storage
        step1.write("# 1.1.24 Disable USB Storage\n")
        with open ("/etc/modprobe.d/usb_storage.conf" , "w" , buffering = 1 ) as process1:
            process1.write("install usb-storage /bin/true")
        
        cmd = "rmmod usb-storage"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.3.1 Ensure sudo is installed
        step1.write("# 1.3.1 Ensure sudo is installed\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt  -y install sudo"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd ] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.3.2 Ensure sudo commands use pty
        step1.write("# 1.3.2 Ensure sudo commands use pty\n")
        with open ("/etc/sudoers" , "r" , buffering = 1 ) as process1:
            result_tmp = process1.read()
            

        with open ("/etc/sudoers" , "w" , buffering = 1 ) as process1:
            result_tmp = re.sub(".*use_pty.*" , "" ,  result_tmp)
            process1.write(result_tmp)
            process1.write("\nDefaults use_pty\n")
            
        # 1.3.3 Ensure sudo log file exists
        step1.write("# 1.3.3 Ensure sudo log file exists\n")
        with open ("/etc/sudoers" , "r" , buffering = 1 ) as process1:
            result_tmp = process1.read()
            

        with open ("/etc/sudoers" , "w" , buffering = 1 ) as process1:
            result_tmp = re.sub(".*logfile.*" , "" ,  result_tmp)
            process1.write(result_tmp)
            process1.write("\nDefaults logfile=\"/var/log/sudo.log\"\n")

        # 1.4.1 Ensure AIDE is installed
        step1.write("# 1.4.1 Ensure AIDE is installed\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt  -y install aide aide-common"
        with subprocess.Popen( ['/bin/sh' , '-c' , cmd ] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()


        #cmd = "aideinit"
        #with subprocess.Popen(['/bin/bash', '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
        #    stdout , stderr = process1.communicate()

        #cmd = "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
        #cmd = cmd.split()
        #with subprocess.Popen(cmd , stdout=step1 , stderr = step1 ) as process1:
        #    stdout , stderr = process1.communicate()



        # 1.4.2 Ensure filesystem integrity is regularly checked
        step1.write("# 1.4.2 Ensure filesystem integrity is regularly checked\n")
        cmd = "echo '0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check' > bash.aide.tmp"
        cmd2 = "crontab -u root bash.aide.tmp"
        cmd3 = "rm -rf bash.aide.tmp"
        
        with subprocess.Popen(['/bin/bash', '-c' , cmd], stdout=step1) as process1:
            stdout,stderr = process1.communicate()
        with subprocess.Popen(['/bin/bash', '-c' , cmd2], stdout=step1) as process1:
            stdout,stderr = process1.communicate()
        with subprocess.Popen(['/bin/bash', '-c' , cmd3], stdout=step1) as process1:
            stdout,stderr = process1.communicate()
        
        # 1.6.3 Ensure prelink is disabled
        step1.write("# 1.6.3 Ensure prelink is disabled\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt  -y purge prelink"
        with subprocess.Popen( ['/bin/sh' , '-c' , cmd ] , stdout=step1) as process1:
            stdout,stderr = process1.communicate()
        
        # 1.6.4 Ensure core dumps are restricted
        step1.write("# 1.6.4 Ensure core dumps are restricted\n")
        with open ("/etc/security/limits.conf" , "r" , buffering = 1 ) as process1:
            result_tmp = process1.read()
            

        with open ("/etc/security/limits.conf" , "w" , buffering = 1 ) as process1:
            result_tmp = re.sub(".*hard core.*" , "" ,  result_tmp)
            result_tmp = re.sub(".*fs.suid_dumpable.*" , "" ,  result_tmp)
            process1.write(result_tmp)
            process1.write("\n* hard core 0")
            process1.write("\nfs.suid_dumpable = 0\n")

        # 1.7.1.1 Ensure AppArmor is installed
        step1.write("# 1.7.1.1 Ensure AppArmor is installed\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt  -y install apparmor"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd ] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration
        step1.write("# 1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration\n")
        
        with open ("/etc/default/grub" , "r" , buffering = 1 ) as process1:
            result_tmp = process1.read()
            result_tmp = re.sub(".*GRUB_CMDLINE_LINUX=.*" , "GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"" ,  result_tmp)
            

        with open ("/etc/default/grub" , "w" , buffering = 1 ) as process1:
            process1.write(result_tmp)
        
        cmd = "update-grub"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd ] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        
        # 1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
        step1.write("# 1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode\n")
        
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y install apparmor-utils"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        

        cmd = "aa-enforce /etc/apparmor.d/*"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        
        
        # 1.8.1.1 Ensure message of the day is configured properly
        step1.write("# 1.8.1.1 remove /etc/motd \n")
        cmd = "rm -rf /etc/motd"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.8.1.2 Ensure local login warning banner is configured properly
        step1.write("# 1.8.1.2 Ensure local login warning banner is configured properly \n")
        with open ("/etc/issue" , "w" , buffering = 1 ) as process1:
            process1.write("Authorized uses only. All activity may be monitored and reported.\n")

        # 1.8.1.3 Ensure remote login warning banner is configured properly
        step1.write("# 1.8.1.2 Ensure local login warning banner is configured properly \n")
        with open ("/etc/issue.net" , "w" , buffering = 1 ) as process1:
            process1.write("Authorized uses only. All activity may be monitored and reported.\n")
        
        # 1.8.1.5 Ensure permissions on /etc/issue are configured
        step1.write("# 1.8.1.5 Ensure permissions on /etc/issue are configured\n")
        cmd = "chown root:root /etc/issue"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        cmd = "chmod u-x,go-wx /etc/issue"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        
        # 1.8.1.6 Ensure permissions on /etc/issue.net are configured 
        step1.write("# 1.8.1.6 Ensure permissions on /etc/issue.net are configured\n")
        cmd = "chown root:root /etc/issue.net"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()
        cmd = "chmod u-x,go-wx /etc/issue.net"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step1 , stderr = step1 ) as process1:
            stdout , stderr = process1.communicate()

        # 1.9 Ensure updates, patches, and additional security software are installed (Manual)
        step1.write("# 1.9 Updating and Upgrading Done Before , Skipping .\n")
        
        
def step2():
    with open("/root/0dev.log" , "a+", buffering = 1) as step2:    
        
        # 2.1.1 Ensure xinetd is not installed.
        step2.write("# 2.1.1 Ensure xinetd is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge xinetd"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.1.2 Ensure openbsd-inetd is not installed.
        step2.write("# 2.1.2 Ensure openbsd-inetd is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge openbsd-inetd"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.1.2 Ensure systemd-timesyncd is configured
        step2.write("# 2.2.1.2 Ensure systemd-timesyncd is configured.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge ntp"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge chrony"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        cmd = "DEBIAN_FRONTEND=noninteractive systemctl enable systemd-timesyncd.service"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        with open ("/etc/systemd/timesyncd.conf" , "r" , buffering = 1 ) as process2:
            result_tmp = process2.read()
            result_tmp = re.sub(".*NTP.*" , "" , result_tmp)
            result_tmp = re.sub(".*FallbackNTP.*" , "" , result_tmp)
            result_tmp = re.sub(".*RootDistanceMax.*", "" , result_tmp)
        
        with open ("/etc/systemd/timesyncd.conf" , "w" , buffering = 1 ) as process2:
            process2.write("\nNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org #Servers listed should be In Accordence With Local Policy")
            process2.write("\nFallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org #Servers listed should be In Accordence With Local Policy")
            process2.write("\nRootDistanceMax=1 #should be In Accordence With Local Policy\n")
            process2.write(result_tmp)
        
        cmd = "DEBIAN_FRONTEND=noninteractive systemctl start systemd-timesyncd.service"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        cmd = "DEBIAN_FRONTEND=noninteractive timedatectl set-ntp true"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.2.2 Ensure X Window System is not installed.
        step2.write("# 2.2.2 Ensure X Window System is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge xserver-xorg*"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        

        # 2.2.3 Ensure Avahi Server is not installed.
        step2.write("# 2.2.3 Ensure Avahi Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive systemctl stop avahi-daaemon.service"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        cmd = "DEBIAN_FRONTEND=noninteractive systemctl stop avahi-daemon.socket"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge avahi-daemon"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        
        # 2.2.4 Ensure CUPS is not installed.
        step2.write("# 2.2.4 Ensure CUPS is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge cups*"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.5 Ensure DHCP Server is not installed.
        step2.write("# 2.2.5 Ensure DHCP Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive apt -y purge isc-dhcp-server"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.6 Ensure LDAP server is not installed.
        step2.write("# 2.2.6 Ensure LDAP server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge slapd"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.2.7 Ensure NFS is not installed.
        step2.write("# 2.2.7 Ensure NFS is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge rpcbind"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.8 Ensure DNS Server is not installed.
        step2.write("# 2.2.8 Ensure DNS Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge bind9"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.9 Ensure FTP Server is not installed.
        step2.write("# 2.2.9 Ensure FTP Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge vsftpd"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.10 Ensure HTTP server is not installed.
        step2.write("# 2.2.10 Ensure HTTP server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge apache2"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.11 Ensure IMAP and POP3 server are not installed.
        step2.write("# 2.2.11 Ensure IMAP and POP3 server are not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge dovecot-imapd dovecot-pop3d"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.12 Ensure Samba is not installed.
        step2.write("# 2.2.12 Ensure Samba is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge  samba"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.13 Ensure HTTP Proxy Server is not installed.
        step2.write("# 2.2.13 Ensure HTTP Proxy Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge squid"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.14 Ensure SNMP Server is not installed.
        step2.write("# 2.2.14 Ensure SNMP Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge snmpd"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.2.15 Ensure mail transfer agent is configured for local-only mode.
        step2.write("# 2.2.15 Ensure mail transfer agent is configured for local-only mode.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge exim4"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        with open ("/etc/postfix/main.cf" , "r" , buffering = 1 ) as process2:
            result_tmp = process2.read()
            result_tmp = re.sub(".*inet_interfaces.*", "" , result_tmp)
        
        with open ("/etc/postfix/main.cf" , "w" , buffering = 1 ) as process2:
            process2.write(result_tmp)
            process2.write("\ninet_interfaces = 127.0.0.1")
            
        cmd = "DEBIAN_FRONTEND=noninteractive  /etc/init.d/postfix restart"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.2.16 Ensure rsync service is not installed.
        step2.write("# 2.2.16 Ensure rsync service is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge rsyncs"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.2.17 Ensure NIS Server is not installed.
        step2.write("# 2.2.17 Ensure NIS Server is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge nis"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.3.1 Ensure NIS Client is not installed.
        step2.write("# 2.3.1 Ensure NIS Client is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge nis"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()
        
        # 2.3.2 Ensure rsh client is not installed.
        step2.write("# 2.3.2 Ensure rsh client is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge rsh-client"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.3.3 Ensure talk client is not installed.
        step2.write("# 2.3.3 Ensure talk client is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge talk"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        
        # 2.3.4 Ensure telnet client is not installed.
        step2.write("# 2.3.4 Ensure telnet client is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge telnet"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.3.5 Ensure LDAP client is not installed.
        step2.write("# 2.3.5 Ensure LDAP client is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge ldap-utils"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

        # 2.3.6 Ensure RPC is not installed.
        step2.write("# 2.3.6 Ensure RPC is not installed.\n")
        cmd = "DEBIAN_FRONTEND=noninteractive  apt -y purge rpcbind"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step2 , stderr = step2 ) as process2:
            stdout , stderr = process2.communicate()

def step3():
    
    with open("/root/0dev.log" , "a+", buffering = 1) as step3:
        
        # 3.2.1 Ensure packet redirect sending is disabled
        with open ("/etc/sysctl.conf" , "r" , buffering = 1 ) as process3:
            result_tmp = process3.read()
            result_tmp = re.sub(".*net.ipv4.conf.all.send_redirects*", "" , result_tmp)
            result_tmp = re.sub(".*net.ipv4.conf.default.send_redirects*", "" , result_tmp)
            
        
        with open ("/etc/sysctl.conf" , "w" , buffering = 1 ) as process3:
            process3.write(result_tmp)
            process3.write("\nnet.ipv4.conf.all.send_redirects = 0")
            process3.write("\nnet.ipv4.conf.default.send_redirects = 0")
            
        cmd = "sysctl -w net.ipv4.conf.all.send_redirects=0"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step3 , stderr = step3 ) as process3:
            stdout , stderr = process3.communicate()

        cmd = "sysctl -w net.ipv4.conf.default.send_redirects=0"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step3 , stderr = step3 ) as process3:
            stdout , stderr = process3.communicate()

        cmd = "sysctl -w net.ipv4.route.flush=1"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step3 , stderr = step3 ) as process3:
            stdout , stderr = process3.communicate()

        # 3.2.2 Ensure IP forwarding is disabled

        
        

        with open ("/etc/sysctl.conf" , "r" , buffering = 1 ) as process3:
            result_tmp = process3.read()
            result_tmp = re.sub(".*net.ipv4.conf.all.send_redirects*", "" , result_tmp)
            result_tmp = re.sub(".*net.ipv4.conf.default.send_redirects*", "" , result_tmp)

        with open ("/etc/sysctl.conf" , "w" , buffering = 1 ) as process3:
            process3.write(result_tmp)
            process3.write("\nnet.ipv4.conf.all.send_redirects = 0")
            process3.write("\nnet.ipv4.conf.default.send_redirects = 0")
            
        cmd = "sysctl -w net.ipv4.conf.all.send_redirects=0"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step3 , stderr = step3 ) as process3:
            stdout , stderr = process3.communicate()

        cmd = "sysctl -w net.ipv4.conf.default.send_redirects=0"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step3 , stderr = step3 ) as process3:
            stdout , stderr = process3.communicate()

        cmd = "sysctl -w net.ipv4.route.flush=1"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd] , stdout=step3 , stderr = step3 ) as process3:
            stdout , stderr = process3.communicate()

        

main()
