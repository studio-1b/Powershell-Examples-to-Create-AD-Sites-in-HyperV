# Powershell-Examples-to-Create-AD-Sites-in-HyperV
Powershell scripts to create your very own Hyper-V sites with Active Directory Domain Controllers

Execute in this order
1. create_router_vm.ps1
2. create_win_forest.ps1
3. add_site_dc.ps1

You may have to change these variables in the scripts for your computer:
1. $ISO, stores where you keep your Windows 2022 ISO.  Any version is fine, as long as the powershell commands are supported
2. $VM[=c:\VM], stores where the VM files such as the hard drive and virtual machine configuration is located.  It will create c:\VM otherwise, if it doesnt exist
3. $ISPName[=Default Switch], stores which switch has access to the internet.  This switch should be connected to DHCP, which returns IP address and default gateway which to access internet.  It can be the the Switch with NAT, or a switch bridged to physical NIC.

All the scripts create the VM, but waits until you install the Windows OS, and sets the local Administrator password to "Pa$$w0rd", then resumes install once it is able to create remote Powershell session to the VM using that username/password.

For example, to create 4 sites in Vancouver, Toronto, Calgary, and Montreal, each with 2x DC, with one domain named "Jomaboch.ca", the machines are prefixed with JMBC-<site><machinename>, that are inter-networked with each other:
1. update "create_router_vm.ps1", change $ISO, leave $VM alone, your VM NAT switch is already "Default Switch" so you leave $ISPName alone
2. update "create_win_forest.ps1", change $ISO, leave $VM alone, $ISPName doesn't exist
3. update "add_site_dc.ps1", change $ISO, leave $VM alone, $ISPName doesn't exist

4. run "./create_router_vm.ps1 JMBC-Van=192.168.200.254/24=10.0.7.1/24=JoMaBoCh,JMBC-Tor=192.168.150.254/24=10.0.7.4/24=JoMaBoCh,JMBC-Mon=192.168.100.254/24=10.0.7.3/24=JoMaBoCh,JMBC-Cal=192.168.50.254/24=10.0.7.2/24=JoMaBoCh"
   (This will create 4 stub network for each site, each with it's own "Internal" switch, and one Windows Router on each switch.  This router will have 3 NICs, 1 to the site's switch, 1 to internet, and another to a shared switch called "WAN".  The sites are interconnected via the WAN switch, which acts as a proxy for a WAN provider, and any future machines in each site should be able to route to any machine, in any of the site switches)

5. then run "./create_win_forest.ps1 JMBC-Van  192.168.200.254/24  Tor=192.168.150.0/24,Mon=192.168.100.0/24,Cal=192.168.50.0/24  JoMaBoCh"
   (This creates the 1st and 2nd Domain Controllers (JMBC-VanDC1, JMBC-VanDC1) in Vancouver, which is effectively the start of the new Windows Active Domain Forest named "JoMaBoCh".  And creates a administrator named "admin" in "Domain Admins", so  you don't have a login with fully qualified domain administrator account username.  Creates a reverse DNS zone for the Vancouver subnet.  Creates a DHCP scope for Vancouver subnet.  And establishes failover for DHCP.  And anticipates DC being created in 3 other subnets)

6. then run "/add_site_dc.ps1 JMBC-Tor  192.168.150.254/24  JoMaBoCh 192.168.200.1"
   (this creates 2x Domain Controllers in Toronto, which connects to Vancouver DC(192.168.200.1) intially for DNS, and then to replicate AD directory database.  It also creates a reverse DNS zone for the toronto subnet.  Creates a DHCP scope for toronto subnet.  And establishes failover for DHCP.)

7. then run "./add_site_dc.ps1 JMBC-Mon  192.168.100.254/24  JoMaBoCh 192.168.200.1"
8. then run "./add_site_dc.ps1 JMBC-Cal   192.168.50.254/24   JoMaBoCh 192.168.200.1"

At end, you should have 4 subnets, interconnected by 4 windows servers acting as routers which forwards traffic either to the internet or to one of the other routers, and 2 Domain Controllers in each site (8 total), all replicating from the Vancouver site, to share active directory database (usernames, passwords, joined computers, registered services, etc).

Notes:

-AND NO, it doesnt actually create the servers in those cities.  We are just pretending, creating a simulation of a network on your computer(with hopefully at least 32GB of RAM) with Hyper-V, using actual software. 

-Hyper-V exists, even in Windows 10 PROFESSIONAL/EDUCATION.  You just need to activate it, as part of "Featured software".  But if you install Hyper-V, other VM such as VMWare stops working.  This is b/c after you install Hyper-V, windows itself is running inside a VM.  And VM software needs to know if it is running inside another VM.

-You need to get your own copy of Windows Server 2022 ISO and Product Key.  Yes, this is the annoying part, if you don't want to spend money on MSDN developer subscription.  Or take a course for educational evaluation version.

-No, I'm pretty sure the router is usually NOT windows, but is an appliance specialized for networking layer 3 and 4.  No one ever asks this question about Linux servers.  Linux people just assume linux can do anything, other devices do.

-I assume you know how to change the security level of Powershell script execution.  I do remote signed (https://pureinfotech.com/change-execution-policy-run-scripts-powershell/), but it makes no difference if you just disable script security, if you just sign the script without understanding what the script does.  So just disable script security, and run.  And re-enable the script security after you're done, so you don't accidentally run some malicious scripts.

-The purpose of this project is to share understanding the value-add of (THE BASIC) Windows Server networking services, which many other real-work software such as databases and web servers and Exchange Mail and applications use.

-The script installs 4x DHCP servers.  Fortunately, you can test them b/c an HOST adapter for each internal VM switch is created, and each will get a DHCP address once the DHCP server is live in that network.  UNFORTUNATELY, the DHCP server returns a default gateway value to each adapter, to it's own network's router.  This confuses the HOST, and all your networking to internet (aka, route 0.0.0.0/0) will stop working (maybe it splits each packet in round robin between all the routes for 0.0.0.0).  So to get your host internet back, you need to release the DHCP address for each of the Internal Switch host adapters (vEthernet (Vancouver-SwitchName), vEthernet (Vancouver-SwitchName),vEthernet (Toronto-SwitchName),vEthernet (Montreal-SwitchName), etc).  This might still be the case, even if the DHCP servers are not live, b/c windows remembers the last DHCP address it was given and reuses it until lease is up. 

-Ignore the problem with being able to ping the gateway address of another subnet.  This seems to be a bug in windows routing.  It doesn't seem to understand, the packet was intended for itself, and to respond to it, on another interface.  Pinging DC to Dc works fine.
