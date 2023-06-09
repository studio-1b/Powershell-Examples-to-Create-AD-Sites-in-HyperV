<#
Creates Hyper-V guests for a LAN, the switch, the router, and starts OS installation

There is 2 arguments, 1st is delimited list of arguments:

1st parameter = site prefix, like Vancouver, which will be added to all VM and servernames
                VancouverRouter
                VancouverDC1
                VancouverDC2
2nd parameter = subnet cidr for site, 192.168.1.1/24 
3rd parameter = WAN address to router, 10.0.1.1/16
4th parameter = other WAN router address
5th parameter = DomainName
6th parameter = delimiter

2nd argument is optional "--confirm", to show message of what it is going to do, before starting
#>

$arglen=$($args.length)
if($arglen -lt 1) {
    Write-Host "Needs to run as administrator."
    Write-Host ""
   #Write-Host "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789|123456789 123456789 123456789"
    Write-Host "                              Prefix=Gateway/subnet=WANIP=Domain"
    Write-Host "                              ------    --------------      -----        ------"
    Write-Host "Usage: ./create_router_vm.ps1 JMBC-Van=192.168.200.254/24=10.0.7.1/24=JoMaBoCh, _"
    Write-Host "                              JMBC-Tor=192.168.150.254/24=10.0.7.4/24=JoMaBoCh, _"
    Write-Host "                              JMBC-Mon=192.168.100.254/24=10.0.7.3/24=JoMaBoCh, _"
    Write-Host "                              JMBC-Cal=192.168.50.254/24=10.0.7.2/24=JoMaBoCh"
    Write-Host "Usage: ./create_router_vm.ps1 JMBC-Van=192.168.200.254/24=10.0.7.1/24=JoMaBoCh,JMBC-Tor=192.168.150.254/24=10.0.7.4/24=JoMaBoCh,JMBC-Mon=192.168.100.254/24=10.0.7.3/24=JoMaBoCh,JMBC-Cal=192.168.50.254/24=10.0.7.2/24=JoMaBoCh"

    exit 1
}
# sign script as administrator
# $codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=ATA Authenticode Bob"}
# Set-AuthenticodeSignature -FilePath ./create_router_vm.ps1 -Certificate $codeCertificate -TimeStampServer http://timestamp.digicert.com






function Create-Credential {
    param (
        $Resource,
        $Username,
        $PlaintextPassword
    )
    $u=$Resource+"\"+$Username
    $password = ConvertTo-SecureString $PlaintextPassword -AsPlainText -Force
    $cred= New-Object System.Management.Automation.PSCredential ($u, $password )
    return $cred
}

#https://www.altaro.com/hyper-v/how-to-create-a-hyper-v-vm-from-an-iso-using-powershell/
#Get-VM $RouterName | Add-VMNetworkAdapter -Name "WAN" -SwitchName $WanName
function Create-VM-Guest {
    param (
        $VmName,
        $ISO,
        $RAM,
        $HD,
        $SwitchName
    )
    Write-Host "Creating VM $VmName"
    Write-Host "Please use Administrator/Pa`$`$w0rd during Windows install"
    #New-VM -Name $VmName -MemoryStartupBytes 2GB -BootDevice VHD -NewVHDPath .\VM\$RouterName.vhdx -Path .\VMData -NewVHDSizeBytes 150GB -Generation 2 -Switch $SwitchName
    New-VM -Name $VmName -MemoryStartupBytes $RAM -BootDevice VHD -NewVHDPath C:\VM\$VmName.vhdx -Path C:\VM\Data -NewVHDSizeBytes $HD -Generation 2 -Switch $SwitchName
    Set-VMProcessor -VMname $VmName -count 4
    Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $VmName
    Get-VMIntegrationService -VMName $VmName
    
    #Set-VMDvdDrive -VMName $VmName -Path $ISO
    Add-VMDvdDrive -VMName $VmName -Path $ISO
    $bootdevice=Get-VMDvdDrive -VMName $VmName
    Set-VMFirmware $VmName -FirstBootDevice $bootdevice
    
    Start-VM -Name $VmName
    VMConnect.exe localhost "$VmName"
}

function Wait-For-Session {
    param (
        $server,
        $logincred,
        $waitmessage
    )
    Write-Host "trying to connect to $server"

    $session=New-PSSession -VMName $server -credential $logincred
    while( -not $? ) {
        Write-Host " ...connect to $server failed... $waitmessage ...trying again in 1sec"
        Start-Sleep -Seconds 1;
        $session=New-PSSession -VMName $server -credential $logincred
    }
    Write-Host "$server connected!!!" -ForegroundColor Black

    return $session
}
function ExtractIP {
    param (
        $cidr
    )

    $parts=$cidr -split "/"

    return $parts[0]
}
function ExtractPrefixLen {
    param (
        $cidr
    )

    $parts=$cidr -split "/"

    return $parts[1]
}
function Get-Mask-As-IPObject {
    param (
        $len
    )

    $subnet = [ipaddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $len))-1)

    return $subnet
}
function Get-Network-Address {
    param (
        $cidr
    )

    $ip = [ipaddress]$(ExtractIP -cidr $cidr)
    $len = ExtractPrefixLen -cidr $cidr
    $subnet = [ipaddress]$(Get-Mask-As-IPObject -len $len)
    $netid = [ipaddress]($ip.address -band $subnet.address)

    return $netid.IPAddressToString
}
function MergeUsingOr-Network-Addresses {
    param (
        $IP1,
        $IP2
    )

    $ipobject1 = [ipaddress]$IP1
    $ipobject2 = [ipaddress]$IP2
    $netid = [ipaddress]($ipobject1.address -bor $ipobject2.address)

    return $netid.IPAddressToString
}

function Set-StaticIP-on-Guest {
    param (
        $Session,
        $IP4,
        $GatewayIPwCIDR,
        $DnsIP,
        $ComputerName
    )
    # https://powershellexplained.com/2016-08-28-PowerShell-variables-to-remote-commands/
    Write-Host "Settin [$ComputerName] to $IP4" -ForegroundColor Yellow
    $GatewayIP=ExtractIP -cidr $GatewayIPwCIDR
    $LanPrefixLen=ExtractPrefixLen -cidr $GatewayIPwCIDR
    $ArgumentList = $IP4, $LanPrefixLen, $GatewayIP, $DnsIP, $ComputerName
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock { 
        $ip4=$args[0]
        $len=$args[1]
        $gateway=$args[2]
        $dns=$args[3]
        $computername=$args[4]

        if($env:computername -eq $computername) { return $false } # this was already complete
        else { Write-Host "Computer name doesnt match[actual:$env:computername][expected:$computername], updating IP addresses" }

        $ifindex=$($(get-netadapter ethernet).ifindex)
        if($($gateway.length) -eq 0) {
            New-NetIPAddress -InterfaceIndex $ifindex -IPAddress $ip4 -PrefixLength $len
        } else{
            New-NetIPAddress -InterfaceIndex $ifindex -IPAddress $ip4 -PrefixLength $len -DefaultGateway $gateway
        }
        #New-NetIPAddress -InterfaceIndex 12 -IPAddress 192.168.0.1
        #Set-NetIPAddress -InterfaceIndex 12 -IPAddress 192.168.0.1 -PrefixLength 24
        Set-DnsClientServerAddress -InterfaceIndex $ifindex -ServerAddresses $dns

        Rename-Computer -NewName $computername -Restart
        # DNS
        # Gateway

        Restart-Computer

        return $true
    }
    Write-Host "[$rc]"
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if($rc) {
        Checkpoint-VM -Name $ComputerName -SnapshotName "Middle-of-Restart-after-LAN-static-IP"
    }
    Write-Host "$ComputerName is restarting, if static address updated..." -ForegroundColor Green
}

function Rename-LAN-NIC {
    param (
        $VMName,
        $Session
    )

    Write-Host "Checking if original NIC was renamed to [LAN]..." -ForegroundColor Yellow
    $rc=Invoke-Command -Session $Session -ScriptBlock { 
        Get-NetAdapter LAN
        if($?) { return $true }

        #Rename default NIC
        Get-NetAdapter Ethernet
        if($?) {
            Rename-NetAdapter -Name "Ethernet" -NewName "LAN"
        }
        Get-NetAdapter LAN
        if($?) { return $true }
        else { return $false }
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) { 
        Write-Output "Cannot find NIC [LAN].  Aborting!!!"
        exit 1
    }
    Write-Host "LAN NIC exists..." -ForegroundColor Green
}

function Install-Internet-NIC {
    param (
        $VMName,
        $Session,
        $reconnectcred
    )

    Write-Host "Checking for internet..." -ForegroundColor Yellow
    $rc=Invoke-Command -Session $Session -ScriptBlock { 
        Get-NetAdapter Internet
        if($?) { return $false } #Abort if Internet NIC exists
        else { Write-Host "Error was expected, finding the internet NIC..." }
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) { 
        Write-Output "Internet exists!"
        return
    }

    Rename-LAN-NIC  -VMName $VMName  -Session $Session
    if(-not $?)  { exit 1}

    Write-Output "Verifying NIC to $VMName to $IspName exists..."
    Get-VM $VMName
    if(-not $?)  {
        Write-Output "Cannot find $VMName to install NIC and NAT.  Aborting!"        
        exit 1
    }
    Get-VMNetworkAdapter -VMName $VMName -Name "InternetNIC"
    if(-not $?) {
        Write-Output "Error was expected, adding NIC connected to [$IspName]..."
        Add-VMNetworkAdapter -VMName $VMName -Name "InternetNIC" -SwitchName $IspName
        if(-not $?) {
            Write-Output "Error in process installing NIC in $VMName .  Aborting!"        
            exit 1
        }
        Start-Sleep -Seconds 5
        $Session=Wait-For-Session -server $($Session.ComputerName) -logincred $reconnectcred -waitmessage "... "
    }
    
    Write-Output "Changing name of added NIC to Internet..."
    $rc=Invoke-Command -Session $Session -ScriptBlock {
        $counter = 30
        Get-NetAdapter Ethernet
        while(-not $?) {
            if($counter-- -le 0) { return $false }
            Start-Sleep 1
            Get-NetAdapter Ethernet
        }
        Rename-NetAdapter -Name "Ethernet" -NewName "Internet"
        Get-NetAdapter Internet
        if(-not $?) { return $false }
        
        Restart-Computer -Force
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) { 
        Write-Output "Error in process installing Internet NIC in $VMName .  Aborting!"        
        exit 1
    } else {
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "NIC for internet Added"
    }
    Write-Host "$VMName is restarting, after Internet NIC was installed..." -ForegroundColor Green

    #Add-VMNetworkAdapter -VMName Redmond -Name "Redmond NIC1"
    #Add-VMNetworkAdapter -VMName Test -SwitchName Network
    #Get-VM Test | Add-VMNetworkAdapter -IsLegacy $true -Name Bootable
    #Add-VMNetworkAdapter -ManagementOS -Name Secondary
}

function Install-WAN-NIC {
    param (
        $VMName,
        $Session,
        $reconnectcred,
        $WanIP
    )

    Write-Host "Checking for WAN..." -ForegroundColor Yellow
    $rc=Invoke-Command -Session $Session -ScriptBlock { 
        Get-NetAdapter WAN
        if($?) { return $false } #Abort if WAN NIC exists
        else { Write-Host "Error was expected, finding the WAN NIC..." }
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) { 
        Write-Output "WAN exists!"
        return
    }

    Rename-LAN-NIC  -VMName $VMName  -Session $Session
    if(-not $?)  { exit 1}

    # start adding NIC
    Write-Output "Adding NIC to $VMName to $IspName..."
    Get-VM $VMName
    if(-not $?)  {
        Write-Output "Cannot find $VMName to install NIC and NAT.  Aborting!"        
        exit 1
    }
    Get-VMNetworkAdapter -VMName $VMName -Name "WanNIC"
    if(-not $?) {
        Write-Output "Error was expected, adding WAN NIC connected to [$IspName]..."
        Write-Output "NIC VMName[$VMName] Name[WanNIC] SwitchName[$WanName]"
        Add-VMNetworkAdapter -VMName $VMName -Name "WanNIC" -SwitchName $WanName
        if(-not $?) {
            Write-Output "Error in process installing NIC in $VMName .  Aborting!"        
            exit 1
        }
    
        Start-Sleep -Seconds 5
        $Session=Wait-For-Session -server $($Session.ComputerName) -logincred $reconnectcred -waitmessage "... "
    }
    
    $rc=Invoke-Command -Session $Session -ArgumentList $WanIP -ScriptBlock {
        $wanip=$args[0]
        $parts=$wanip -split "/"
        $ip4=$parts[0]
        $len=$parts[1]
        $counter = 30
        Start-Sleep -Seconds 5
        Get-NetAdapter Ethernet
        while(-not $?) {
            Start-Sleep 1
            Get-NetAdapter Ethernet
            if($counter-- -le 0) { return $false }
        }
        Rename-NetAdapter -Name "Ethernet" -NewName "WAN"
        $nic=Get-NetAdapter WAN
        if(-not $?) { return $false}
        
        New-NetIPAddress -InterfaceIndex $($nic.ifindex) -IPAddress $ip4 -PrefixLength $len
        
        Restart-Computer -Force
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Output "Error in process installing WAN NIC in $VMName .  Aborting!"        
        exit 1
    } else {
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "NIC for WAN Added"
    }
    Write-Host "$VMName is restarting, after WAN NIC was installed..." -ForegroundColor Green

    #Add-VMNetworkAdapter -VMName Redmond -Name "Redmond NIC1"
    #Add-VMNetworkAdapter -VMName Test -SwitchName Network
    #Get-VM Test | Add-VMNetworkAdapter -IsLegacy $true -Name Bootable
    #Add-VMNetworkAdapter -ManagementOS -Name Secondary
}

# this is only useful if the VM guest is on internal switch
function Wait-for-IP {
    param (
        $IP
    )

    ping -n 1 $IP
    while($?) { ping -n 1 $IP }
}

function Install-DNS-Cache  {
    param (
        $VMName,
        $Session
    )

    $rc=Invoke-Command -Session $Session -ScriptBlock {
        Install-WindowsFeature -Name DNS -IncludeManagementTools

        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Output "Error in process installing WAN NIC in $VMName .  Aborting!"        
        exit 1
    } else {
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "Routing and Remote Access Installed"
    }
    Write-Host "$VMName DNS Installed!" -ForegroundColor Green

}

function Install-Routing-Software {
    param (
        $VMName,
        $Session
    )

    $rc=Invoke-Command -Session $Session -ScriptBlock {
        Install-WindowsFeature Routing -IncludeManagementTools
        Set-NetFirewallRule -DisplayName "Core Networking Diagnostics - ICMP Echo Request (ICMPv6-In)" -enabled 1
        Set-NetFirewallRule -DisplayName "Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)" -enabled 1

        Restart-Computer -Force
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Output "Error in process installing WAN NIC in $VMName .  Aborting!"        
        exit 1
    } else {
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "Routing and Remote Access Installed"
    }
    Write-Host "$VMName Routing and Remote Access Installed!" -ForegroundColor Green

}

Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}
Function IBAnd($a, $b, $Right, $Wrong) {If ($a -band $b) {$Right} Else {$Wrong}}


function Show-Progress {
    param (
        $all
    )

    $gatewaylist=$all -split ","
    $alllan = $gatewaylist | % {$(ExtractIP -cidr ($_ -split "=")[1]) }
    $allwan = $gatewaylist | % {$(ExtractIP -cidr ($_ -split "=")[2]) }
    if ($all -eq "") {
        Write-Host "Shared networks"
        Write-Host "[ ] host: Get-VMSwitch $ISPName" -ForegroundColor Red
        Write-Host "[ ] host: Get-VMSwitch $WANName" -ForegroundColor Red

        foreach($lan in $gatewaylist) {
            $site=$lanargs[0]
            $cidr=$lanargs[1]
            $wanip=$lanargs[2]
            $domain=$lanargs[3]
            Write-Host "Guest stub network: $site"

            $LANgatewayIP=ExtractIP -cidr $cidr
            $LANprefixlen=ExtractPrefixLen -cidr $cidr
            $LANnetwork=Get-Network-Address -cidr $cidr
            $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
            $WANprefixlen=ExtractPrefixLen -cidr $wanip
            $WANnetwork=Get-Network-Address -cidr $wanip
            $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
            $WANgatewayIP=ExtractIP -cidr $wanip
            $domainca=$domain+".ca"
            $SwitchName=$site+"LAN"
            $VMName=$site+"Router"

            Write-Host "LAN config confirmation"
            Write-Host "[ ] guest: get-NetAdapter $SwitchName"                                                        -ForegroundColor Red
            Write-Host "[ ] guest: get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP"                     -ForegroundColor Red

            Write-Host "Internet config confirmation"
            Write-Host "[ ] guest: get-NetAdapter Internet"                                                           -ForegroundColor Red
            Write-Host "[ ] guest: netsh routing ip nat show interface Internet"                                      -ForegroundColor Red
            Write-Host "[ ] guest: netsh routing ip nat show interface LAN"                                           -ForegroundColor Red
            Write-Host "[ ] guest: Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where {$_.InterfaceAlias -eq Internet}"   -ForegroundColor Red
            Write-Host "[ ] guest: ping 8.8.8.8"                                                                      -ForegroundColor Red
            Write-Host "[ ] guest: nslookup www.google.ca"                                                            -ForegroundColor Red

            Write-Host "WAN config confirmation"
            Write-Host "[ ] guest: get-NetIPAddress -InterfaceAlias WAN -IPAddress 10...."                   -ForegroundColor Red
            foreach($wan in $allwan) {
                Write-Host "[ ] guest: ping $wan"                                                                     -ForegroundColor Red
            }

            foreach($lan in $alllan) {
                if ($lan -eq $LANgatewayIP) {
                    Write-Host "[ ] guest: Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq LAN}" -ForegroundColor Red
                } else {
                    Write-Host "[ ] guest: Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq WAN}" -ForegroundColor Red
                }
            }
            foreach($lan in $alllan) {
                Write-Host "[ ] guest: ping $lan"                                                                     -ForegroundColor Red
            }
        }
        return
    }

    Write-Host "Shared networks" -BackgroundColor white -Foregroundcolor black 
    Get-VMSwitch $ISPName  2>&1 > $null 
    Write-Host "[$?] host: Get-VMSwitch $ISPName" -ForegroundColor (IIf $? "Green" "Red")
    Get-VMSwitch $WANName   2>&1 > $null 
    Write-Host "[$?] host: Get-VMSwitch $WANName" -ForegroundColor (IIf $? "Green" "Red")

    $gatewaylist=$all -split ","
    $alllan = $gatewaylist | % {$(ExtractIP -cidr $_.split('=')[1]) }
    $allwan = $gatewaylist | % {$(ExtractIP -cidr $_.split('=')[2]) }
    foreach($lan in $gatewaylist) {
        $lanargs=$lan -split "="
        # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

        $site=$lanargs[0]
        $cidr=$lanargs[1]
        $wanip=$lanargs[2]
        $domain=$lanargs[3]
        Write-Host "Guest stub network: $site"  -BackgroundColor darkgray

        $LANgatewayIP=ExtractIP -cidr $cidr
        $LANprefixlen=ExtractPrefixLen -cidr $cidr
        $LANnetwork=Get-Network-Address -cidr $cidr
        $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
        $WANprefixlen=ExtractPrefixLen -cidr $wanip
        $WANnetwork=Get-Network-Address -cidr $wanip
        $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
        $WANgatewayIP=ExtractIP -cidr $wanip
        $domainca=$domain+".ca"
        $SwitchName=$site+"LAN"
        $VMName=$site+"Router"

        Write-Host "LAN config confirmation"  -BackgroundColor darkgray
        Get-VMSwitch $SwitchName  2>$null 1>$null 
        Write-Host "[$?] host: Get-VMSwitch $SwitchName" -ForegroundColor (IIf $? "Green" "Red")
        Get-VM $VMName  2>$null 1>$null 
        Write-Host "[$?] host: Get-VM $VMName" -ForegroundColor (IIf $? "Green" "Red")

        Get-VM $VMName 2> $null
        if ($?) {
            $Session=Wait-For-Session -server $VMName -logincred $localcred -waitmessage "" 2> $null
        }
        $rc=0
        if ($Session -ne $null) {
            $remoteargs=@($LANgatewayIP,$WANgatewayIP,$allwan,$alllan)
            $rc=Invoke-Command -Session $Session -ArgumentList $remoteargs  -ScriptBlock {
                Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}
                Function IBAnd($a, $b, $Right, $Wrong) {If ($a -band $b) {$Right} Else {$Wrong}}


		$LANgatewayIP=$args[0]
		$WANgatewayIP=$args[1]
		$allwan=$args[2]
		$alllan=$args[3]
#Write-host '=========='
#Write-host $args
#Write-host $args.GetType().Name
#Write-host $args.length
#Write-host $LANgatewayIP
#Write-host $WANgatewayIP
#Write-host $allwan
#Write-host $alllan
#Write-host '=========='
                $code=0
                $flag=1

                get-NetAdapter LAN
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetAdapter LAN"                                                               -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

        Write-Host "Internet config confirmation"  -BackgroundColor darkgray

                get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP"                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                get-NetAdapter Internet
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetAdapter Internet"                                                          -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                netsh routing ip nat show interface Internet | findstr "Mode              : Address and Port Translation"
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: netsh routing ip nat show interface Internet"                                     -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                netsh routing ip nat show interface LAN | findstr "Mode              : Address and Port Translation"
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: netsh routing ip nat show interface LAN"                                          -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                Find-NetRoute -RemoteIPAddress "8.8.8.8" | Where {$_.InterfaceAlias -eq "Internet"} | findstr "InterfaceAlias     : Internet"
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where {`$_.InterfaceAlias -eq Internet}" -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                ping -n 1 8.8.8.8
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: ping 8.8.8.8"                                                                     -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                Resolve-DNSName www.google.ca
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Resolve-DNSName www.google.ca"                                                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

        Write-Host "WAN config confirmation"  -BackgroundColor darkgray

                get-NetIPAddress -InterfaceAlias WAN -IPAddress $WANgatewayIP
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetIPAddress -InterfaceAlias WAN -IPAddress $WANgatewayIP"                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                foreach($wan in $allwan) {
                    ping -n 1 $wan
                    $code=$code + (IIf $? $flag 0)
                    Write-Host "[$(IBAnd $code $flag "X" " ")] guest: ping $wan"                                                                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                    $flag=$flag*2
                }
                foreach($lan in $alllan) {
                    if ($lan -eq $LANgatewayIP) {
                        Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq "LAN"} | findstr "InterfaceAlias     : LAN"
                        $code=$code + (IIf $? $flag 0)
                        Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress $lan | Where {`$_.InterfaceAlias -eq LAN}" -ForegroundColor (IBAnd $code $flag "Green" "Red")
                        $flag=$flag*2
                    } else {
                        Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq "WAN"} | findstr "InterfaceAlias     : WAN"
                        $code=$code + (IIf $? $flag 0)
                        Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress $lan | Where {`$_.InterfaceAlias -eq WAN}" -ForegroundColor (IBAnd $code $flag "Green" "Red")
                        $flag=$flag*2
                    }
                }
                foreach($lan in $alllan) {
                    ping -n 1 $lan
                    $code=$code + (IIf $? $flag 0)
                    Write-Host "[$(IBAnd $code $flag "X" " ")] guest: ping $lan"                                                                     -ForegroundColor (IBAnd $code $flag "Green" "Red")
                    $flag=$flag*2
                }

                return $code

            }  2>$null 1>$null
            Write-Host "rc=$rc"
            if($rc -eq $null) {$rc=0}
            $tp=$rc.GetType().Name
            if($tp -eq "Object[]") { $rc=$rc[-1] }
        }
        Write-Host $rc

<# commented code, put in above script block
            $flag=1
            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP"                   -ForegroundColor (IBAnd $rc 4 "Green" "Red")
            $flag=$flag*2

        Write-Host "Internet config confirmation" -foregroundcolor darkgray

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: get-NetAdapter Internet"                                                           -ForegroundColor (IBAnd $rc 1 "Green" "Red")
            $flag=$flag*2

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: netsh routing ip nat show interface LAN"                                         -ForegroundColor (IBAnd $rc 256 "Green" "Red")
            $flag=$flag*2

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: netsh routing ip nat show interface Internet"                                    -ForegroundColor (IBAnd $rc 512 "Green" "Red")
            $flag=$flag*2

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where {`$_.InterfaceAlias -eq Internet}" -ForegroundColor (IBAnd $rc 1024 "Green" "Red")
            $flag=$flag*2

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: ping 8.8.8.8"                                                                      -ForegroundColor (IBAnd $rc 8 "Green" "Red")
            $flag=$flag*2

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: nslookup www.google.ca"                                                           -ForegroundColor (IBAnd $rc 16 "Green" "Red")
            $flag=$flag*2

        Write-Host "WAN config confirmation"

            Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: get-NetIPAddress -InterfaceAlias WAN -IPAddress $WANgatewayIP"                   -ForegroundColor (IBAnd $rc 2 "Green" "Red")
            $flag=$flag*2

            foreach($wan in $allwan) {
                Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: ping $wan"                                                             -ForegroundColor (IBAnd $rc 64 "Green" "Red")
                $flag=$flag*2
            }

            foreach($lan in $alllan) {
                if ($lan -eq $LANgatewayIP) {
                    Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress $lan | Where {`$_.InterfaceAlias -eq LAN}" -ForegroundColor (IBAnd $rc 2048 "Green" "Red")
                    $flag=$flag*2
                } else {
                    Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress $lan | Where {`$_.InterfaceAlias -eq WAN}" -ForegroundColor (IBAnd $rc 2048 "Green" "Red")
                    $flag=$flag*2
                }
            }
            foreach($lan in $alllan) {
                Write-Host "[$(IBAnd $rc $flag "X" " ")] guest: ping $lan"                                                             -ForegroundColor (IBAnd $rc 64 "Green" "Red")
                $flag=$flag*2
            }
#>
    }
}




# START (switches)


# $ip = [IPAddress] "192.168.33.21"
$BridgedHostAdapter="Wi-Fi"  #Intel(R) Wi-Fi 6 AX201 160MHz"
$ISO="C:\Users\Bob\Downloads\Windows Server Datacenter ISO\en-us_windows_server_2022_x64_dvd_620d7eac.iso"
$ISPName="Default Switch"
$WanName="WAN"
$plaintext="Pa`$`$w0rd"
$localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext
if($args[1] -eq "--confirm") {
    $answer = Read-Host "Location of Windows 2022 ISO [$ISO]"
    if($answer -ne "") {
        $ISO = $answer
    }
    $answer = Read-Host "Password for Windows Local Administrator [$plaintext]"
    if($answer -ne "") {
        $plaintext = $answer
    }
    $answer = Read-Host "Switch Name Representing ISP Network [$ISPName]"
    if($answer -ne "") {
        $ISPName = $answer
    }
    $answer = Read-Host "Physical Adapter to use for ISP Network [$BridgedHostAdapter]"
    if($answer -ne "") {
        $BridgedHostAdapter = $answer
    }
    $answer = Read-Host "Switch Name Representing WAN Network [$WanName]"
    if($answer -ne "") {
        $WanName = $answer
    }

    $all=$args[0]
    $gatewaylist=$all -split ","
    foreach($lan in $gatewaylist) {
        $lanargs=$lan -split "="
        # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

        $site=$lanargs[0]
        $cidr=$lanargs[1]
        $wanip=$lanargs[2]
        $domain=$lanargs[3]

        $LANgatewayIP=ExtractIP -cidr $cidr
        $LANprefixlen=ExtractPrefixLen -cidr $cidr
        $LANnetwork=Get-Network-Address -cidr $cidr
        $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
        $WANprefixlen=ExtractPrefixLen -cidr $wanip
        $WANnetwork=Get-Network-Address -cidr $wanip
        $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
        $domainca=$domain+".ca"

        Write-Host "Switch Name Representing Stub LAN for $site... : [$site]LAN"
        Write-Host "Internal Gateway address of stub network...... : [$cidr]"
        Write-Host "  Implied internet subnet network address..... : [$LANnetworkcidr]"
        Write-Host "External address of Router to stub network.... : [$wanip]"
        Write-Host "  WAN on 1 subnet, bc no routing ............. : [$WANnetworkcidr]"
        Write-Host "Planned Windows domain name for network....... : [$domain]"
        Write-Host "Planned domain for network.................... : [$domainca]"
        Write-Host "Windows Router Hostname....................... : [$site]Router"

        $answer = Read-Host "Are the above parameters correct? [Yes]:"
        if($answer -ne "") {
            Write-Host "The values above are generated based on the input parameters." -ForegroundColor Red
            Write-Host "Please update the parameters (below) submitted to this command." -ForegroundColor Yellow
            
            $withspaces=" $all "
            $halves=$withspaces -split $lan
            Write-Host "Parameters :" -NoNewline
            Write-Host $halves[0] -NoNewline
            Write-Host $lan       -ForegroundColor Yellow -NoNewline
            Write-Host $halves[1] 
            Exit 1
        }
    }
    Write-Host "Tests"
    Write-Host "====="
    Show-Progress -all $args[0]
    Write-Host "Above are the tests, at end of script"
    $answer = Read-Host "Press enter to start [Ok]:"
}



# $ISO="C:\Users\Bob\Downloads\Windows Server Datacenter ISO\en-us_windows_server_2022_x64_dvd_620d7eac.iso"
if(-not $(Test-Path -Path $ISO -PathType Leaf)) {
    write-Error "Cannot find $ISO, if Windows Server ISO is located elsewhere, change the `$ISO variable in this file to true location of ISO"
    exit 1
}
$VMPATH="c:\VM"
if(-not $(Test-Path -Path $VMPATH)) {
    Write-Warning "Creating $VMPATH for VM files..."
    New-Item -Path "c:\" -Name "VM" -ItemType "directory"
}
Get-NetAdapter $BridgedHostAdapter
if(-not $?) {
    Write-Error "Cannot find the Host NIC [$BridgedHostAdapter] for bridging VM to internet.  Run [Get-NetAdapter] on Host for VMs and replace the `$BridgedHostAdapter= with the adapter that has internet access."
    exit 1
}

# Creating switches
# $ISPName="vEthernet (Default Switch)" #"ISPExternal" #"Default Switch"
Get-VMSwitch $ISPName
if( -not $? )
{
    Write-Host "Creating vswitch $ISPName"
    New-VMSwitch -Name "$ISPName" -NetAdapterName $BridgedHostAdapter -AllowManagementOS:$true
}

# $WanName="WAN"
Get-VMSwitch $WanName
if( -not $? )
{
    Write-Host "Creating vswitch $WanName"
    New-VMSwitch -SwitchName "$WanName" -SwitchType Internal
}



# START (gateways)

$all=$args[0]
$gatewaylist=$all -split ","
foreach($lan in $gatewaylist) {
    $lanargs=$lan -split "="
    # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

    $site=$lanargs[0]
    $cidr=$lanargs[1]
    $wanip=$lanargs[2]
    $domain=$lanargs[3]

    $LANgatewayIP=ExtractIP -cidr $cidr
    $LANprefixlen=ExtractPrefixLen -cidr $cidr
    $LANnetwork=Get-Network-Address -cidr $cidr
    $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
    $WANprefixlen=ExtractPrefixLen -cidr $wanip
    $WANnetwork=Get-Network-Address -cidr $wanip
    $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
    $domainca=$domain+".ca"

    $SwitchName=$site+"LAN"
    Get-VMSwitch $SwitchName
    if( -not $? )
    {
        Write-Host "Creating vswitch $SwitchName"
        New-VMSwitch -SwitchName "$SwitchName" -SwitchType Internal
    }

    # Creating VM
    #Get-VMSwitch * | Format-Table Name
    # New-VM -Name <Name> -MemoryStartupBytes <Memory> -BootDevice <BootDevice> -VHDPath <VHDPath> -Path <Path> -Generation <Generation> -Switch <SwitchName>
    $RouterName=$site+"Router"
    Get-VM $RouterName
    if( -not $? )
    {
        Create-VM-Guest -VmName $RouterName -ISO $ISO -RAM 2GB -HD 150GB -SwitchName $SwitchName
    }
}

Write-Host "Configuring IP addresses..." -ForegroundColor Yellow

foreach($lan in $gatewaylist) {
    $lanargs=$lan -split "="
    # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

    $site=$lanargs[0]
    $cidr=$lanargs[1]
    $wanip=$lanargs[2]
    $domain=$lanargs[3]

    $LANgatewayIP=ExtractIP -cidr $cidr
    $LANprefixlen=ExtractPrefixLen -cidr $cidr
    $LANnetwork=Get-Network-Address -cidr $cidr
    $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
    $WANprefixlen=ExtractPrefixLen -cidr $wanip
    $WANnetwork=Get-Network-Address -cidr $wanip
    $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
    $domainca=$domain+".ca"

    #$session=New-PSSession -VMName Unicomm-srvdc1 -credential $localcred
    
    $RouterName=$site+"Router"
    Write-Host "Waiting until $RouterName is installed with Windows..."
    Write-Host "Script will continue once it detects the VM is installed with windows..."
    Write-Host "Hyper-V connect windows should already be opened"

    # $plaintext="Pa`$`$w0rd"
    # $password = ConvertTo-SecureString $plaintext -AsPlainText -Force
    # $localcred= New-Object System.Management.Automation.PSCredential (".\Administrator", $password )
    $localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext

    # installing hostname and IP on router
    $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "Please complete Windows install on $RouterName.  Please set Administrator password to $plaintext "
    $nogateway="/"+$LANprefixlen
    Set-StaticIP-on-Guest -Session $RouterSession  -IP4 $LANgatewayIP  -GatewayIPwCIDR $nogateway  -DnsIP 127.0.0.1  -ComputerName $RouterName




    Start-Sleep -Seconds 5




    # installing router (add second network card, add routing services, dhcp, dns)
    $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "... "
    Install-WAN-NIC  -VMName $RouterName -Session $RouterSession -reconnectcred $localcred -WanIP $WanIP
    Start-Sleep -Seconds 5

    $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "... "
    $test=Install-Internet-NIC  -VMName $RouterName -Session $RouterSession -reconnectcred $localcred
    Start-Sleep -Seconds 5 

    $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "..."
    Install-DNS-Cache -VMName $RouterName -Session $RouterSession

    $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "..."
    Install-Routing-Software  -VMName $RouterName -Session $RouterSession

    # $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "... "
    # Install-NAT -VMName $RouterName -Session $RouterSession -lannetworkwithcidr $lannetworkcidr
    Write-Warning "I disabled install NAT and routing bc it disables the UI"

    
    # Close all remote powershell sessions
    Remove-PSSession -Session $RouterSession
    #Remove-PSSession -Session $Dc1Session
    #Remove-PSSession -Session $Dc2Session
}

foreach($lan in $gatewaylist) {
    $lanargs=$lan -split "="
    # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

    $site=$lanargs[0]
    $cidr=$lanargs[1]
    $wanip=$lanargs[2]
    $domain=$lanargs[3]

    $LANgatewayIP=ExtractIP -cidr $cidr
    $LANprefixlen=ExtractPrefixLen -cidr $cidr
    $LANnetwork=Get-Network-Address -cidr $cidr
    $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
    $WANprefixlen=ExtractPrefixLen -cidr $wanip
    $WANnetwork=Get-Network-Address -cidr $wanip
    $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
    $domainca=$domain+".ca"
    Write-Host "Static NAT for $site Router" -ForegroundColor Green -BackgroundColor Black

    
    foreach($other in $gatewaylist) {
        if($other -ne $lan) {
            $lanargs=$other -split "="
            # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

            $site=$lanargs[0]
            $cidr=$lanargs[1]
            $wanip=$lanargs[2]
            $domain=$lanargs[3]

            $LANgatewayIP=ExtractIP -cidr $cidr
            $LANprefixlen=ExtractPrefixLen -cidr $cidr
            $LANnetwork=Get-Network-Address -cidr $cidr
            $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
            $hopIP=ExtractIP -cidr $wanip
            $WANprefixlen=ExtractPrefixLen -cidr $wanip
            $WANnetwork=Get-Network-Address -cidr $wanip
            $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
            $domainca=$domain+".ca"

            Write-Host "  subnet $LANnetworkcidr nexthop $hopIP" -ForegroundColor Green -BackgroundColor Black
        }
    }
}


Write-Host "Routing and Remote Access has to be configured, before trying to add routes!" -ForegroundColor Green
$Server = Read-Host -Prompt 'Press [enter], to try to install routes on servers'
foreach($lan in $gatewaylist) {
    Write-Host "lan=[$lan]"
    $topargs=$lan -split "="
    # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh
    $site=$topargs[0]
    $RouterName=$site+"Router"
    Write-Host "lan=[$RouterName]"

    $routelist=@()
    foreach($other in $gatewaylist) {
        if($other -ne $lan) {
            $lanargs=$other -split "="
            # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

            $site=$lanargs[0]
            $cidr=$lanargs[1]
            $wanip=$lanargs[2]
            $domain=$lanargs[3]

            $LANgatewayIP=ExtractIP -cidr $cidr
            $LANprefixlen=ExtractPrefixLen -cidr $cidr
            $LANnetwork=Get-Network-Address -cidr $cidr
            $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
            $hopIP=ExtractIP -cidr $wanip
            $WANprefixlen=ExtractPrefixLen -cidr $wanip
            $WANnetwork=Get-Network-Address -cidr $wanip
            $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
            $domainca=$domain+".ca"

            Write-Host "  subnet $LANnetworkcidr nexthop $hopIP" -ForegroundColor Green -BackgroundColor Black
            # $parts=$gatewayIP -split "/"
            $len=$LANprefixlen
            $mask = [ipaddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $len))-1)
            $subnet_mask=$mask.IPAddressToString

            $routelist+=,($LANnetwork,$subnet_mask,$hopIP)
        }
    }
    Write-Host "[$routelist]"
    Write-Host "$localcred"
    Write-Host "$localcred"
    Write-Host "$RouterName"
    
    $RouterSession=Wait-For-Session -server $RouterName -logincred $localcred -waitmessage "... "
    Write-Host "$RouterSession"
    $rc=Invoke-Command -Session $RouterSession  -ArgumentList $routelist -ScriptBlock {
        # route add $destination_network MASK $subnet_mask  $ip 200
        # https://serverfault.com/questions/693053/scripting-static-routes-in-routing-and-remote-access
        foreach($item in $args) {
            $destsubnet=$item[0]
            $subnet_mask=$item[1]
            $hopIP=$item[2]
            Write-Host "    routing dest[$destsubnet] mask[$subnet_mask] nhop[$hopIP]"
            Write-Host "netsh routing ip add persistentroute dest=$destsubnet mask=$subnet_mask name="WAN" nhop=$hopIP proto=NONDOD metric=256 view=both"
            Write-Host "netsh routing ip set persistentroute dest=$destsubnet mask=$subnet_mask name="WAN" nhop=$hopIP proto=NONDOD metric=256 view=both"
            netsh routing ip add persistentroute dest=$destsubnet mask=$subnet_mask name="WAN" nhop=$hopIP proto=NONDOD metric=256 view=both
            netsh routing ip set persistentroute dest=$destsubnet mask=$subnet_mask name="WAN" nhop=$hopIP proto=NONDOD metric=256 view=both
        }
        return $true
    }
    Write-Host "Testing..."
    foreach($other in $gatewaylist) {
        if($other -ne $lan) {
            $lanargs=$other -split "="
            # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

            $site=$lanargs[0]
            $cidr=$lanargs[1]
            $wanip=$lanargs[2]
            $domain=$lanargs[3]

            $LANgatewayIP=ExtractIP -cidr $cidr
            $LANprefixlen=ExtractPrefixLen -cidr $cidr
            $LANnetwork=Get-Network-Address -cidr $cidr
            $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
            $hopIP=ExtractIP -cidr $wanip
            $WANprefixlen=ExtractPrefixLen -cidr $wanip
            $WANnetwork=Get-Network-Address -cidr $wanip
            $WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen
            $domainca=$domain+".ca"
            Write-Host $LANgatewayIP
            $rc=Invoke-Command -Session $RouterSession  -ArgumentList $LANgatewayIP -ScriptBlock {
                ping $args[0]
                Write-Host "    $args[0][$?]"
            }
        }
    }
}
Write-Host "Routes added!" -ForegroundColor Green
Write-Host ""

Show-Progress -all $all
Write-Host "Finished!  Check test result above.  Sometimes a step fails, and this script didnt catch it."  -ForegroundColor Green

