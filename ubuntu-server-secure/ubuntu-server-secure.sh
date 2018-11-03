#!/bin/sh
sudo apt install zenity
sudo apt install gpasswd
sudo apt install pwgen
sudo add-apt-repository -y ppa:duggan/bats
sudo apt-get update
sudo apt-get install bats
sudo apt install dialog
sudo apt install nmap && nmap -p- localhost &> ./nmap_dmp
dialog --yesno "remove samba" 20 60 && sudo apt remove samba
dialog --yesno "remove telnet" 20 60 && sudo apt remove telnet
dialog --yesno "remove ftp-client (need to manually remove server)" 20 60 && sudo apt remove ftp
dialog --yesno "remove nmap" 20 60 && sudo apt remove nmap
dialog --yesno "remove hydra" 20 60 && sudo apt remove hydra
dialog --yesno "remove wireshark" 20 60 && sudo apt remove wireshark
echo
echo "* Ubuntu Server Secure script v0.1 alpha by The Fan Club - May 2012 mRmonotreme mod super bad..."
echo 
echo "DISCLAIMER: Use with care. This script is provided purely for alpha testing and can harm your system if used incorrectly"
echo "NOTE: This is a GUI installer script that depends on zenity."
echo "NOTE: Run this script with  gksudo sh /path/to/script/ubuntu-server-secure.sh"
TFCName="Ubuntu Server Secure"
TFCVersion="v0.1 alpha"
UserName=$(whoami)
LogDay=$(date '+%Y-%m-%d')
LogTime=$(date '+%Y-%m-%d %H:%M:%S')
LogFile=/var/log/uss_$LogDay.log
cut -d: -f1 /etc/passwd | grep -vFf keep_users | while read name ; do echo "Delete $name" ; dialog --yesno "Delete $name" 20 60 && dialog --yesno "u sure $name?" 20 60 && sudo userdel -r "$name" && sudo groupdel "$name" ; done
cut -d: -f1 /etc/passwd | grep -vFf keep_admin | while read name ; do echo "Revoke Admin $name" ; dialog --yesno "Revoke Admin $name" 20 60 && dialog --yesno "u sure $name?" && sudo gpasswd -d $name sudo && sudo deluser username sudo ; done
cut -d: -f1 /etc/passwd | while read -r line || [[ -n "$line" ]]; do
if [ -n "$line" ] && [ "$line" != "$(whoami)" ]
  then
    printf $line;
    printf "\t\t\t";
    pass="$(pwgen 50 1)";
    echo $pass;
    echo "$line:$pass" | sudo chpasswd;
fi
done
selection=$(zenity  --list  --title "$TFCName $TFCVersion" --text "Select the security features you require" --checklist --width 480 --height 550 \
--column "pick" --column "options" \
FALSE " 1. Secure shared memory - fstab" \
TRUE " 2. SSH - Disable root login and change port" \
TRUE " 3. Protect su by limiting access only to admin group" \
TRUE " 4. Harden network with sysctl settings" \
TRUE " 5. Disable Open DNS Recursion" \
TRUE " 6. Prevent IP Spoofing" \
FALSE " 7. Scan logs and ban suspicious hosts - DenyHosts" \
--separator=","); 


if [ ! "$selection" = "" ] 
  then
    # Start of Zenity Progress code 
    sudo echo "$LogTime uss: [$UserName] * $TFCName $TFCVersion - Install Log Started" 
    (
    echo "10" ; sleep 0.1
    # 2. secure shared memory
       option=$(echo $selection | grep -c "fstab")
       if [ "$option" -eq "1" ] 
         then
            echo "# 2. Secure shared memory."
            echo "$LogTime uss: [$UserName] 2. Secure shared memory." 
            echo "# Check if shared memory is secured"
            sudo echo "$LogTime uss: [$UserName] Check if shared memory is secured"            
            # Make sure fstab does not already contain a tmpfs reference
            fstab=$(grep -c "tmpfs" /etc/fstab)
            if [ ! "$fstab" -eq "0" ] 
              then
                 echo "# fstab already contains a tmpfs partition. Nothing to be done."
                 sudo echo "$LogTime uss: [$UserName] fstab already contains a tmpfs partition. Nothing to be done." 
            fi
            if [ "$fstab" -eq "0" ]
              then
                 echo "# fstab being updated to secure shared memory"
                 echo "$LogTime uss: [$UserName] fstab being updated to secure shared memory" 
                 sudo echo "# $TFCName Script Entry - Secure Shared Memory - $LogTime" >> /etc/fstab
                 sudo echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
                 echo "# Shared memory secured. Reboot required"
                 echo "$LogTime uss: [$UserName] Shared memory secured. Reboot required" 
          fi
       fi
    echo "15" ; sleep 0.1
    # 3. SSH Hardening - disable root login and change port
       option=$(echo $selection | grep -c "SSH")
       if [ "$option" -eq "1" ] 
         then
           echo "# 3. SSH Hardening - disable root login and change port"
           sudo echo "$LogTime uss: [$UserName] 3. SSH Hardening - disable root login and change port"  
           sshNewPort=$(zenity --entry --text "Select a new SSH port?" --title "SSH Hardening - $TFCName $TFCVersion" --entry-text "22")
           echo "# Updating SSH settings"
           echo "$LogTime uss: [$UserName] Updating SSH settings"  
           # Check if Port entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if Port entry exists comment out old entries"  
           sshconfigPort=$(grep -c "Port" /etc/ssh/sshd_config)
           if [ ! "$sshconfigPort" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/Port/#Port/g' /etc/ssh/sshd_config > /tmp/.sshd_config
                sudo mv /etc/ssh/sshd_config /etc/ssh/ssh_config.backup
                sudo mv /tmp/.sshd_config /etc/ssh/sshd_config
           fi
           # Check if Protocol entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if Protocol entry exists comment out old entries"             
           sshconfigProtocol=$(grep -c "Protocol" /etc/ssh/sshd_config)
           if [ ! "$sshconfigProtocol" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/Protocol/#Protocol/g' /etc/ssh/sshd_config > /tmp/.sshd_config
                sudo mv /etc/ssh/sshd_config /etc/ssh/ssh_config.backup
                sudo mv /tmp/.sshd_config /etc/ssh/sshd_config
           fi
           # Check if PermitRootLogin entry exists comment out old entries
        echo "$LogTime uss: [$UserName] Check if PermitRootLogin entry exists comment out old entries"             
           sshconfigPermitRoot=$(grep -c "PermitRootLogin" /etc/ssh/sshd_config)
           if [ ! "$sshconfigPermitRoot" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original 
                sudo sed 's/PermitRootLogin/#PermitRootLogin/g' /etc/ssh/sshd_config > /tmp/.sshd_config
                sudo mv /etc/ssh/sshd_config /etc/ssh/ssh_config.backup
                sudo mv /tmp/.sshd_config /etc/ssh/sshd_config
           fi
           echo "# Write new SSH configuration settings"             
           echo "$LogTime uss: [$UserName] Write new SSH configuration settings"             
           sudo echo "# $TFCName Script Entry - SSH settings $LogTime" >> /etc/ssh/sshd_config
           sudo echo "Port $sshNewPort" >> /etc/ssh/sshd_config
           sudo echo "Protocol 2" >> /etc/ssh/sshd_config
           sudo echo "PermitRootLogin no" >> /etc/ssh/sshd_config
           echo "# SSH settings update complete"
          echo "$LogTime uss: [$UserName] SSH settings update complete"             
           zenity --question --title "SSH Hardening - $TFCName $TFCVersion" --text "Open new SSH port $sshNewPort on UFW Firewall ?"
           if [ "$?" -eq "0" ]  
             then
                # open new port on UFW Firewall
                sudo ufw $sshNewPort
                echo "# Port $sshNewPort opened on UFW Firewall"
                echo "$LogTime uss: [$UserName] Port $sshNewPort opened on UFW Firewall"             
           fi 
           if [ ! "$sshNewPort" -eq "22" ] 
             then
              zenity --question --title "SSH Hardening - $TFCName $TFCVersion" --text "Close old SSH port 22 on UFW Firewall ?"
              if [ "$?" -eq "0" ]
                then
                # close old port on UFW Firewall
                  sudo ufw deny port 22
                  echo "# Port 22 closed on UFW Firewall"
                  echo "$LogTime uss: [$UserName] Port 22 closed on UFW Firewall"             
              fi 
           fi   
           zenity --question --title "SSH Hardening - $TFCName $TFCVersion" --text "Would you like to restart the SSH server now?"
           if [ "$?" -eq "0" ]
             then
                # restart SSHd
                sudo /etc/init.d/ssh restart
                echo "# SSH server restarted"
                echo "$LogTime uss: [$UserName] SSH server restarted"             
           fi 
       fi      
    echo "20" ; sleep 0.1
    # 4. Protect su by limiting access only to admin group
       option=$(echo $selection | grep -c "Protect[[:space:]]su")
       if [ "$option" -eq "1" ] 
         then
            echo "# 4. Protect su by limiting access only to admin group"
            echo "$LogTime uss: [$UserName] 4. Protect su by limiting access only to admin group"  
            # Get new admin group name 
            newAdminGroup=$(zenity --entry --title "Protect su - $TFCName $TFCVersion" --text "Select name of new admin group?"  --entry-text "admin")
            # Check if new group already exists
            echo "# Checking if Group: $newAdminGroup already exists"
            echo "$LogTime uss: [$UserName] Checking if Group: $newAdminGroup already exists"  
            groupCheck=$(grep -c -w "$newAdminGroup" /etc/group)
            if [ ! "$groupCheck" -eq "0" ] 
              then
                 # group already exists
                 echo "# Group: $newAdminGroup already exists. Group not added"
                 echo "$LogTime uss: [$UserName] Group: $newAdminGroup already exists. Group not added"      
            fi
            if [ "$groupCheck" -eq "0" ] 
              then
                 # group does not exist create new group
                 echo "# Group: $newAdminGroup does not exist"
                 echo "$LogTime uss: [$UserName] Group: $newAdminGroup does not exist"      
                 sudo groupadd  $newAdminGroup          
                 echo "# Group: $newAdminGroup added"
                 echo "$LogTime uss: [$UserName] Group: $newAdminGroup added"      
            fi
            # Add current administrator user to new admin group 
            addAdminUser=$(zenity --entry --title "Protect su - $TFCName $TFCVersion" --text "Which current user should be added to the new admin group?"  --entry-text "admin")
            # Check if user is already part of the admin group
            echo "# Checking if User: $addAdminUser is already part of the Group: $newAdminGroup"
            echo "$LogTime uss: [$UserName] Checking if User: $addAdminUser is already part of the Group: $newAdminGroup"  
            userCheck=$(groups $addAdminUser | grep -c -w "$newAdminGroup")
  
            if [ ! "$userCheck" -eq "0" ] 
              then
                 # user is already part of the admin group
                 echo "# User: $addAdminUser is already part of the Group: $newAdminGroup. User not added"
                 echo "$LogTime uss: [$UserName] User: $addAdminUser is already part of the Group: $newAdminGroup. User not added"      
            fi
            if [ "$userCheck" -eq "0" ] 
              then
                 # user is not part of admin group and needs to be added
                 echo "# User: $addAdminUser is not part of the Group: $newAdminGroup, adding user to group"
                 echo "$LogTime uss: [$UserName] User: $addAdminUser is not part of the Group: $newAdminGroup, adding user to group"      
                 sudo usermod -a -G $newAdminGroup $addAdminUser     
                 echo "# User: $addAdminUser added to the Group: $newAdminGroup"
                 echo "$LogTime uss: [$UserName] User: $addAdminUser added to the Group: $newAdminGroup"   
            fi
            # change su permission to limit access only to admin group
            echo "# Checking if dpkg state override aleady exists"
            echo "$LogTime uss: [$UserName] Checking if dpkg state override aleady exists"  
            dpkgCheck=$(sudo dpkg-statoverride --list | grep -c "4750[[:space:]]/bin/su")
            if [ ! "$dpkgCheck" -eq "0" ] 
              then
                 # dpkg state override already exists. do nothing
                 echo "# User: dpkg state override already exists. Override not set."
                 echo "$LogTime uss: [$UserName] dpkg state override already exists. Override not set."      
            fi
            if [ "$dpkgCheck" -eq "0" ] 
              then
                 echo "# Setting new dpkg state override"
                 echo "$LogTime uss: [$UserName] Setting new dpkg state override"  
                 sudo dpkg-statoverride --update --add root $newAdminGroup 4750 /bin/su
                 echo "# dpkg state override done. /bin/su only accessible by $newAdminGroup group members"
                 echo "$LogTime uss: [$UserName] dpkg state override done. /bin/su only accessible by $newAdminGroup group members"     
            fi
       fi    
    echo "25" ; sleep 0.1
    # 5. Harden network with sysctl settings
       option=$(echo $selection | grep -c "sysctl")
       if [ "$option" -eq "1" ] 
         then
           echo "# 5. Harden network with sysctl settings"
           echo "$LogTime uss: [$UserName] 5. Harden network with sysctl settings"  
           echo "# Updating sysctl network settings"
           echo "$LogTime uss: [$UserName] Updating sysctl network settings"  
           # Check if sysctl entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if net.ipv4.conf.default.rp_filter entry exists comment out old entries"  
           sysctlConfig1=$(sudo grep -c "net.ipv4.conf.default.rp_filter" /etc/sysctl.conf)
           if [ ! "$sysctlConfig1" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.conf.default.rp_filter/#net.ipv4.conf.default.rp_filter/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if net.ipv4.conf.all.rp_filter entry exists comment out old entries"             
           sysctlConfig2=$(sudo grep -c "net.ipv4.conf.all.rp_filter" /etc/sysctl.conf)
           if [ ! "$sysctlConfig2" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.conf.all.rp_filter/#net.ipv4.conf.all.rp_filter/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
        echo "$LogTime uss: [$UserName] Check if net.ipv4.icmp_echo_ignore_broadcasts entry exists comment out old entries"             
           sysctlConfig3=$(sudo grep -c "net.ipv4.icmp_echo_ignore_broadcasts" /etc/sysctl.conf)
           if [ ! "$sysctlConfig3" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.icmp_echo_ignore_broadcasts/#net.ipv4.icmp_echo_ignore_broadcasts/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if net.ipv4.tcp_syncookies entry exists comment out old entries"  
           sysctlConfig4=$(sudo grep -c "net.ipv4.tcp_syncookies" /etc/sysctl.conf)
           if [ ! "$sysctlConfig4" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.tcp_syncookies/#net.ipv4.tcp_syncookies/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if net.ipv4.conf.all.accept_source_route entry exists comment out old entries"             
           sysctlConfig5=$(sudo grep -c "net.ipv4.conf.all.accept_source_route" /etc/sysctl.conf)
           if [ ! "$sysctlConfig5" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.conf.all.accept_source_route/#net.ipv4.conf.all.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
        echo "$LogTime uss: [$UserName] Check if net.ipv6.conf.all.accept_source_route entry exists comment out old entries"             
           sysctlConfig6=$(sudo grep -c "net.ipv6.conf.all.accept_source_route" /etc/sysctl.conf)
           if [ ! "$sysctlConfig6" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv6.conf.all.accept_source_route/#net.ipv6.conf.all.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
                      # Check if sysctl entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if net.ipv4.conf.default.accept_source_route entry exists comment out old entries"  
           sysctlConfig7=$(sudo grep -c "net.ipv4.conf.default.accept_source_route" /etc/sysctl.conf)
           if [ ! "$sysctlConfig7" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.conf.default.accept_source_route/#net.ipv4.conf.default.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
           echo "$LogTime uss: [$UserName] Check if net.ipv6.conf.default.accept_source_route entry exists comment out old entries"             
           sysctlConfig8=$(sudo grep -c "net.ipv6.conf.default.accept_source_route" /etc/sysctl.conf)
           if [ ! "$sysctlConfig8" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv6.conf.default.accept_source_route/#net.ipv6.conf.default.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           # Check if sysctl entry exists comment out old entries
        echo "$LogTime uss: [$UserName] Check if net.ipv4.conf.all.log_martians entry exists comment out old entries"             
           sysctlConfig9=$(sudo grep -c "net.ipv4.conf.all.log_martians" /etc/sysctl.conf)
           if [ ! "$sysctlConfig9" -eq "0" ] 
             then
                # if entry exists use sed to search and replace - write to tmp file - move to original
                sudo sed 's/net.ipv4.conf.all.log_martians/#net.ipv4.conf.all.log_martians/g' /etc/sysctl.conf > /tmp/.sysctl_config
                sudo mv /etc/sysctl.conf /etc/sysctl.conf.backup
                sudo mv /tmp/.sysctl_config /etc/sysctl.conf
           fi
           echo "# Write new sysctl configuration settings"             
           echo "$LogTime uss: [$UserName] Write new sysctl configuration settings"             
           sudo echo "# $TFCName Script Entry - sysctl settings $LogTime" >> /etc/sysctl.conf
           sudo echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
           sudo echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
           sudo echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
           sudo echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
           sudo echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
           sudo echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
           sudo echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
           sudo echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
           sudo echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
           echo "# sysctl settings update complete"
           echo "$LogTime uss: [$UserName] sysctl settings update complete"             
           sudo sysctl -p
           echo "# sysctl settings reloaded"
           echo "$LogTime uss: [$UserName] sysctl settings reloaded"             
       fi    
    echo "30" ; sleep 0.1
    # 6. Disable Open DNS Recursion - BIND DNS Server
       option=$(echo $selection | grep -c "DNS")
       if [ "$option" -eq "1" ] 
         then
            echo "# 6. Disable Open DNS Recursion - BIND DNS Server"
            echo "$LogTime uss: [$UserName] 6. Disable Open DNS Recursion - BIND DNS Server" 
            # Make sure DNS recursion entry does not exist
            echo "# Check if DNS recursion option exists"
            echo "$LogTime uss: [$UserName] Check if DNS recursion option exists"            
            dnsRecur=$(sudo grep -c "recursion" /etc/bind/named.conf.options )
            if [ ! "$dnsRecur" -eq "0" ] 
              then
                 # if entry exists use sed to search and replace - write to tmp file - move to original 
                 echo "# DNS recursion entry exists. Commenting out old entries"
                 echo "$LogTime uss: [$UserName] DNS recursion entry exists. Commenting out old entries"             
                 sudo sed 's/recursion/#recursion/g' /etc/bind/named.conf.options > /tmp/.named_config
                 sudo mv /etc/bind/named.conf.options /etc/bind/_named.conf.options.backup
                 sudo mv /tmp/.named_config /etc/bind/named.conf.options
            fi
            # add DNS recursion option setting
            echo "# Add DNS recursion option setting"
            echo "$LogTime uss: [$UserName] Add DNS recursion option setting"          
            sudo sed 's/options[[:space:]]{/options { recursion no; # $TFCName Script /g' /etc/bind/named.conf.options > /tmp/.named_config
            sudo mv /etc/bind/named.conf.options /etc/bind/_named.conf.options.backup
            sudo mv /tmp/.named_config /etc/bind/named.conf.options       
            echo "# Restart bind9 DNS server"
            echo "$LogTime uss: [$UserName] Restart bind9 DNS server"           
            sudo /etc/init.d/bind9 restart
            echo "# DNS server restarted"
            echo "$LogTime uss: [$UserName] DNS server restarted"                    
       fi 
    echo "35" ; sleep 0.1
    # 7. Prevent IP Spoofing
       option=$(echo $selection | grep -c "Spoofing")
       if [ "$option" -eq "1" ] 
         then
            echo "# 7. Prevent IP Spoofing"
            echo "$LogTime uss: [$UserName] 7. Prevent IP Spoofing" 
            # Make sure IP Spoofing entry does not exist
            echo "# Check if IP Spoofing option exists"
            echo "$LogTime uss: [$UserName] Check if IP Spoofing option exists"            
            ipSpoof=$(grep -c "nospoof" /etc/host.conf )
            if [ ! "$ipSpoof" -eq "0" ] 
              then
                 # if entry exists use sed to search and replace - write to tmp file - move to original 
                 echo "# nospoof entry exists. Commenting out old entries"
                 echo "$LogTime uss: [$UserName] nospoof entry exists. Commenting out old entries"             
                 sudo sed 's/nospoof/#nospoof/g' /etc/host.conf > /tmp/.host_config
                 sudo mv /etc/host.conf /etc/host.conf.backup
                 sudo mv /tmp/.host_config /etc/host.conf
            fi
            # Make sure order entry does not exist
            echo "# Check if order entry exists"
            echo "$LogTime uss: [$UserName] Check if order option exists"            
            orderOp=$(grep -c "order" /etc/host.conf )
            if [ ! "$orderOp" -eq "0" ] 
              then
                 # if entry exists use sed to search and replace - write to tmp file - move to original 
                 echo "# order entry exists. Commenting out old entries"
                 echo "$LogTime uss: [$UserName] order entry exists. Commenting out old entries"             
                 sudo sed 's/order/#order/g' /etc/host.conf > /tmp/.host_config
                 sudo mv /etc/host.conf /etc/host.conf.backup
                 sudo mv /tmp/.host_config /etc/host.conf
            fi
            # add new order and nospoof option settings
            echo "# Write new host configuration settings"             
            echo "$LogTime uss: [$UserName] Write new host configuration settings"          
            sudo echo "# $TFCName Script Entry - IP nospoof settings $LogTime" >> /etc/host.conf
            sudo echo "order bind,hosts" >> /etc/host.conf
            sudo echo "nospoof on" >> /etc/host.conf
            echo "# host configuration settings update complete"
            echo "$LogTime uss: [$UserName] host configuration settings update complete"   
           echo "# Restart bind9 DNS server"
             echo "$LogTime uss: [$UserName] Restart bind9 DNS server"           
             sudo /etc/init.d/bind9 restart
            echo "# DNS server restarted"
             echo "$LogTime uss: [$UserName] DNS server restarted"                   
       fi 
    echo "55" ; sleep 0.1
    # 11. Scan logs and ban suspicious hosts - DenyHosts
       option=$(echo $selection | grep -c "DenyHosts")
       if [ "$option" -eq "1" ] 
         then
            echo "# 11. Scan logs and ban suspicious hosts - DenyHosts"
            echo "$LogTime uss: [$UserName] 11. Scan logs and ban suspicious hosts - DenyHosts" 
            echo "# Check if Denyhosts is installed..."
            echo "$LogTime uss: [$UserName] Check if Denyhosts is installed..." 
            if [ -f /usr/sbin/denyhosts ]
              then
                 # Denyhosts already installed
                 echo "# Denyhosts is already installed"
                 echo "$LogTime uss: [$UserName] Denyhosts is already installed" 
            fi
            if [ ! -f /usr/sbin/denyhosts ]
              then
                 # Install DenyHosts
                 echo "# Install DenyHosts"
                 echo "$LogTime uss: [$UserName] Install DenyHosts" 
                 sudo apt-get install -y denyhosts 2>&1 | sed -u 's/.* \([0-9]\+%\)\ \+\([0-9.]\+.\) \(.*\)/\1\n# Downloading at \2\/s, ETA \3/' | zenity --progress --title="Downloading File..." --text="Installing DenyHosts" --auto-close
           fi           
            # Enter Email address to receive notifications from DenyHosts
            echo "# Enter Email address to receive notifications from DenyHosts"
            echo "$LogTime uss: [$UserName] Enter Email address to receive notifications from DenyHosts"      
            denyhostEmail=$(zenity --entry --text "Enter the email for DenyHosts notifications" --title "DenyHosts - $TFCName $TFCVersion" --entry-text "root@localhost")
            denyhostFrom=$(zenity --entry --text "Enter the email from field for DenyHosts notifications" --title "DenyHosts - $TFCName $TFCVersion" --entry-text "DenyHosts <nobody@localhost>")
            # Make sure ADMIN_EMAIL entry does not exist
            echo "# Check if ADMIN_EMAIL option exists"
            echo "$LogTime uss: [$UserName] Check if ADMIN_EMAIL option exists"            
            adminEmail=$(grep -c "ADMIN_EMAIL" /etc/denyhosts.conf )
            if [ ! "$adminEmail" -eq "0" ] 
              then
                 # if entry exists use sed to search and replace - write to tmp file - move to original 
                 echo "# ADMIN_EMAIL entry exists. Commenting out old entries"
                 echo "$LogTime uss: [$UserName] ADMIN_EMAIL entry exists. Commenting out old entries"             
                 sudo sed 's/ADMIN_EMAIL/#ADMIN_EMAIL/g' /etc/denyhosts.conf > /tmp/.denyhosts_config
                 sudo mv /etc/denyhosts.conf /etc/denyhosts.conf.backup
                 sudo mv /tmp/.denyhosts_config /etc/denyhosts.conf
            fi
            # Make sure order entry does not exist
            echo "# Check if SMTP_FROM entry exists"
            echo "$LogTime uss: [$UserName] Check if SMTP_FROM option exists"            
            smtpFrom=$(grep -c "SMTP_FROM" /etc/denyhosts.conf )
            if [ ! "$smtpFrom" -eq "0" ] 
              then
                 # if entry exists use sed to search and replace - write to tmp file - move to original 
                 echo "# SMTP_FROM entry exists. Commenting out old entries"
                 echo "$LogTime uss: [$UserName] SMTP_FROM entry exists. Commenting out old entries"             
                 sudo sed 's/SMTP_FROM/#SMTP_FROM/g' /etc/denyhosts.conf > /tmp/.denyhosts_config
                 sudo mv /etc/denyhosts.conf /etc/denyhosts.conf.backup
                 sudo mv /tmp/.denyhosts_config /etc/denyhosts.conf
            fi
            # write new DenyHosts settings
            echo "# Write new DenyHosts configuration settings"             
            echo "$LogTime uss: [$UserName] Write new DenyHosts configuration settings"          
            sudo echo "# $TFCName Script Entry - DenyHosts settings $LogTime" >> /etc/denyhosts.conf
            sudo echo "ADMIN_EMAIL = $denyhostEmail" >> /etc/denyhosts.conf
            sudo echo "SMTP_FROM = $denyhostFrom" >> /etc/denyhosts.conf
            echo "# DenyHosts configuration settings update complete"
            echo "$LogTime uss: [$UserName] DenyHosts configuration settings update complete"   
            echo "# Restart DenyHosts service"
            echo "$LogTime uss: [$UserName] Restart DenyHosts service"           
            sudo /etc/init.d/denyhosts restart
            echo "# DenyHosts service restarted"
            echo "$LogTime uss: [$UserName] DenyHosts service restarted"                   
       fi 
     echo "65" ; sleep 0.1
     echo "# Installation Complete" ; sleep 0.1
     # End of Zenity Progress code
     ) |
     zenity --progress \
            --title="$TFCName $TFCVersion" \
            --text="Configuring security features..." \
            --width 500 \
            --percentage=0

     if [ "$?" = -1 ] ; then
        zenity --error \
          --text="Installation canceled."
     fi
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
echo "# 12. Intrusion Detection - PSAD"
echo "$LogTime uss: [$UserName] Intrusion Detection - PSAD" 
echo "# Check if PSAD is installed..."
echo "$LogTime uss: [$UserName] Check if PSAD is installed..." 
echo "# Install PSAD"
echo "$LogTime uss: [$UserName] Install PSAD" 
sudo apt-get install -y psad
echo "# Enter Email address to receive notifications from PSAD"
echo "$LogTime uss: [$UserName] Enter Email address to receive notifications from PSAD"      
psadEmail="root@localhost"
echo "# Check if EMAIL_ADDRESSES option exists"
echo "$LogTime uss: [$UserName] Check if EMAIL_ADDRESSES option exists"            
psadAdminEmail=$(grep -c "EMAIL_ADDRESSES" /etc/psad/psad.conf )
if [ ! "$psadAdminEmail" -eq "0" ] 
  then
     echo "# EMAIL_ADDRESSES entry exists. Commenting out old entries"
     echo "$LogTime uss: [$UserName] EMAIL_ADDRESSES entry exists. Commenting out old entries"             
     sudo sed 's/EMAIL_ADDRESSES/#EMAIL_ADDRESSES/g' /etc/psad/psad.conf > /tmp/.psad_config
     sudo mv /etc/psad/psad.conf /etc/psad/psad.conf.backup
     sudo mv /tmp/.psad_config /etc/psad/psad.conf
fi
echo "# Check if ENABLE_AUTO_IDS entry exists"
echo "$LogTime uss: [$UserName] Check if ENABLE_AUTO_IDS option exists"            
psadIdsEmail=$(grep -c "ENABLE_AUTO_IDS_EMAILS" /etc/psad/psad.conf )
if [ ! "$psadIdsEmail" -eq "0" ] 
  then
     echo "# ENABLE_AUTO_IDS entry exists. Commenting out old entries"
     echo "$LogTime uss: [$UserName] ENABLE_AUTO_IDS entry exists. Commenting out old entries"             
     sudo sed 's/ENABLE_AUTO_IDS_EMAILS/#ENABLE_AUTO_IDS_EMAILS/g' /etc/psad/psad.conf > /tmp/.psad_config
     sudo mv /etc/psad/psad.conf /etc/psad/psad.conf.backup
     sudo mv /tmp/.psad_config /etc/psad/psad.conf
fi
echo "# Write new PSAD configuration settings"             
echo "$LogTime uss: [$UserName] Write new PSAD configuration settings"          
sudo echo "# $TFCName Script Entry - DenyHosts settings $LogTime" >> /etc/psad/psad.conf
sudo echo "EMAIL_ADDRESSES  $psadEmail;" >> /etc/psad/psad.conf
sudo echo "ENABLE_AUTO_IDS_EMAILS Y;" >> /etc/psad/psad.conf
echo "# PSAD configuration settings update complete"
echo "$LogTime uss: [$UserName] PSAD configuration settings update complete"   
echo "# Update iptables to add log rules for PSAD"
echo "$LogTime uss: [$UserName] Update iptables to add log rules for PSAD"     
sudo iptables -A INPUT -j LOG
sudo iptables -A FORWARD -j LOG
sudo ip6tables -A INPUT -j LOG
sudo ip6tables -A FORWARD -j LOG    
echo "# Update and Restart PSAD service"
echo "$LogTime uss: [$UserName] Update and Restart PSAD service"           
sudo psad -R
sudo psad --sig-update
sudo psad -H
echo "# PSAD service updated and restarted"
echo "$LogTime uss: [$UserName] PSAD service updated restarted"                   
sudo chmod +x ./hardening/ubuntu.sh && cd ./hardening && sudo bash ubuntu.sh
cd ./tests && sudo bats .
cd ../..
echo "$LogTime uss: [$UserName] Check for rootkits - RKHunter"
echo "# Check for rootkits - RKHunter"
echo "# Check if RKHunter is installed..."
echo "$LogTime uss: [$UserName] Check if RKHunter is installed..." 
echo "# RKHunter NOT installed, installing..."
echo "$LogTime uss: [$UserName] RKHunter installing..." 
sudo apt-get install -y rkhunter
echo "# Updating RKHunter"
echo "$LogTime uss: [$UserName] Updating RKHunter"                              
sudo rkhunter --update
sudo rkhunter --propupd
echo "# RKHunter installed and updated"
echo "$LogTime uss: [$UserName] RKHunter installed and updated"    
echo "# Running RKHunter check"
echo "$LogTime uss: [$UserName] Running RKHunter check"  
sudo rkhunter --check --skip-keypress
echo "# RKHunter check done"
echo "$LogTime uss: [$UserName] RKHunter check done"     
sudo echo "$LogTime uss: [$UserName] 1. Install and configure Firewall - ufw" 
echo "# 1. Install and configure :Firewall - ufw"
echo "# Check if ufw Firewall is installed..."
sudo echo "$LogTime uss: [$UserName] Check if ufw Firewall is installed..." 
echo "# ufw Firewall installing..."
echo "$LogTime uss: [$UserName] ufw Firewall NOT installed, installing..." 
sudo apt-get install -y ufw 
sudo ufw enable
echo "# ufw Firewall installed and enabled"
echo "$LogTime uss: [$UserName] ufw Firewall installed and enabled"                
sudo ufw allow ssh
sudo ufw allow http
echo "# ufw Firewall ports for SSH and Http configured"
echo "$LogTime uss: [$UserName] ufw Firewall ports for SSH and Http configured" 
echo "$LogTime uss: [$UserName] SELinux - Apparmor" 
echo "# 16. SELinux - Apparmor"
echo "# Check if Apparmor is installed..."
echo "$LogTime uss: [$UserName] Check if Apparmor is installed..." 
echo "# Apparmor installing..."
echo "$LogTime uss: [$UserName] Apparmor installing..." 
sudo apt-get install -y apparmor apparmor-profiles
echo "# Apparmor installed"
echo "$LogTime uss: [$UserName] Apparmor installed"    
echo "# Check Apparmor status"
echo "$LogTime uss: [$UserName] Check Apparmor status"  
sudo apparmor_status
echo "# Apparmor status check done"
echo "$LogTime uss: [$UserName] Apparmor status check done" 
echo "$LogTime uss: [$UserName] Analyse system LOG files - LogWatch" 
echo "# 15. Analyse system LOG files - LogWatch"
echo "# Check if LogWatch is installed..."
echo "$LogTime uss: [$UserName] Check if LogWatch is installed..." 
echo "# LogWatch NOT installed, installing..."
echo "$LogTime uss: [$UserName] LogWatch NOT installed, installing..." 
sudo apt-get install -y logwatch libdate-manip-perl
echo "# LogWatch installed"
echo "$LogTime uss: [$UserName] LogWatch installed"    
echo "# Running LogWatch scan"
echo "$LogTime uss: [$UserName] Running LogWatch scan"      
sudo logwatch
echo "# LogWatch scan done"
echo "$LogTime uss: [$UserName] LogWatch scan done"
echo "$LogTime uss: [$UserName] Audit your system security - Tiger" 
echo "# 17. Audit your system security - Tiger"
echo "# Check if Tiger is installed..."
echo "$LogTime uss: [$UserName] Check if Tiger is installed..." 
echo "# Tiger installing..."
echo "$LogTime uss: [$UserName] Tiger NOT installed, installing..." 
sudo apt-get install -y tiger 
echo "# Tiger installed"
echo "$LogTime uss: [$UserName] Tiger installed"    
echo "# Run Tiger system audit"
echo "$LogTime uss: [$UserName] Run Tiger system audit"   
sudo tiger -e 
echo "# Tiger system audit done"
echo "$LogTime uss: [$UserName] Tiger system audit done" 
     exit;
   fi
exit;