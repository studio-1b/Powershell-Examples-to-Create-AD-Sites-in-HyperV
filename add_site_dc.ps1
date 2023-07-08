<#
has to be run as administrator!  Check the script, if you like

Creates Hyper-V guests that creates Domain Controllers for new site, and waits for OS installation

1st parameter = site prefix, like Vancouver, which will be added to all VM and servernames
                VancouverRouter
                VancouverDC1
                VancouverDC2
2nd parameter = subnet cidr for site, 192.168.1.1/24 
3rd parameter = DomainName

#>

$arglen=$($args.length)
if($arglen -lt 4) {
    Write-Host "Run once, at a Site, to start a AD Forest...  To install other sites to join this domain, run join script"
   #Write-Host "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789|123456789 123456789 123456789"
    Write-Host "                         Prefix    Gateway/subnet      Domain   Forest-DNS"
    Write-Host "                         ------    --------------      ------   ----------"
    Write-Host "Usage: ./add_site_dc.ps1 JMBC-Tor  192.168.150.254/24  JoMaBoCh 192.168.200.1"
    Write-Host "and    ./add_site_dc.ps1 JMBC-Mon  192.168.100.254/24  JoMaBoCh 192.168.200.1"
    Write-Host "and    ./add_site_dc.ps1 JMBC-Cal  192.168.50.254/24   JoMaBoCh 192.168.200.1"
    Write-Host "If you chose another site as the forest start..."
    Write-Host "or     ./add_site_dc.ps1 Vancouver 192.168.200.254/24  JoMaBoCh <IP address of 1st DC>"

    exit 1
}

$site=$args[0]
$firstsite=$site
$cidr=$args[1]
$domain=$args[2]
$dc_dns=$args[3]




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

        Set-NetFirewallRule -DisplayName "Core Networking Diagnostics - ICMP Echo Request (ICMPv6-In)" -enabled 1
        Set-NetFirewallRule -DisplayName "Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)" -enabled 1

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
        Write-Host "Checkpoint"
    }
    Write-Host "$ComputerName is restarting, if static address updated..." -ForegroundColor Green
}

function Add-AD-on-Guest {
    param (
        $Session,
        $DomainName,
        $DomainPlaintextPassword
    )

    Write-Host "New DC in Domain [$DomainName] " -ForegroundColor Yellow
    # 
    $ArgumentList=$DomainName,$DomainPlaintextPassword
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $DomainName=$args[0]
        $DomainPlaintextPassword=$args[1]
        $FullyQualifiedDomainDnsName=$DomainName+".ca"

        ping $FullyQualifiedDomainDnsName
        if(-not $?) { return $false } else { Write-Host "pinged [$FullyQualifiedDomainDnsName]..." }

        Get-ADComputer $ENV:COMPUTERNAME
        if($?) { return $true }else { Write-Host "Error was expected.  Adding[$ENV:COMPUTERNAME] to [$FullyQualifiedDomainDnsName]..." }

        $password = ConvertTo-SecureString $DomainPlaintextPassword -AsPlainText -Force
        $domainuser=$DomainName+"\Administrator"
        $domaincred= New-Object System.Management.Automation.PSCredential ($domainuser, $password )
        Write-Host "Adding computer [$FullyQualifiedDomainDnsName] to domain with [$domainuser]/[$DomainPlaintextPassword]..."
        add-computer -domainname $FullyQualifiedDomainDnsName -Credential $domaincred -restart
        if(-not $?) { return $false }
        return $true
    }
    if(-not $rc) { 
        Write-Error "There is something wrong.  The computer cannot reach the domain controller.  It cannot resolve the [$($DomainName + ".ca")] or domain credentials are wrong"
        exit 1 
    }

    Start-Sleep -Seconds 15

    $DCName=$($session.ComputerName)    
    $domaincred= Create-Credential -Resource $DomainName -Username "Administrator" -PlaintextPassword $plaintext
    $Session=Wait-For-Session -server $DCName -logincred $domaincred -waitmessage "..."

    $ArgumentList=$DCName,$DomainName,$DomainPlaintextPassword
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $itself=$args[0]
        $DomainName=$args[1]
        $DomainPlaintextPassword=$args[2]

        Get-ADDomainController
        if(-not $?) { 
            Write-Host "That was expected.  No problem. Installing AD..." 
            Add-WindowsFeature AD-Domain-Services -IncludeManagementTools
        }

        Get-ADDomainController $itself
        if($?) { return $false } else { Write-Host "That was expected.  Promoting to Domain controller..." }

        # Install-ADDSForest -DomainName $DomainName -InstallDNS
        $password = ConvertTo-SecureString $DomainPlaintextPassword -AsPlainText -Force
        $domainuser=$DomainName + "\Administrator"
        $domaincred= New-Object System.Management.Automation.PSCredential ($domainuser, $password )
        Write-Host "Promoting [$itself] to domain controller with [$domainuser]/[$DomainPlaintextPassword]..."
        #Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath C:\Windows\NTDS -DomainMode WinThreshold -DomainName $DomainName -DomainNetbiosName $DomainName -ForestMode WinThreshold -InstallDns:$true -LogPath C:\Windows\NTDS -NoRebootOnCompletion:$true -SafeModeAdministratorPassword $Password -SysvolPath C:\Windows\SYSVOL -Force:$true
        Install-ADDSDomainController -DomainName $DomainName -InstallDns:$true -SafeModeAdministratorPassword $password -Credential $domaincred -Force
        
        Restart-Computer -Force
        return $true
    }
    Write-Host "[$rc]"
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if($rc) {
        Checkpoint-VM -Name "Finished add Domain Controller" -SnapshotName "Domain Controller Added to domain"
        Write-Host "Checkpoint"
        Start-Sleep -Seconds 60
    }
    Write-Host "Finished add Domain Controller [$($Session.ComputerName)] to [$DomainName]... is restarting..." -ForegroundColor Green
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
        Write-Host "Cannot find NIC [LAN].  Aborting!!!"
        exit 1
    }
    Write-Host "LAN NIC exists..." -ForegroundColor Green
}

# this is only useful if the VM guest is on internal switch
function Wait-for-IP {
    param (
        $IP
    )

    ping -n 1 $IP
    while($?) { ping -n 1 $IP }
}




function Install-DNS-Reverse-Zone {
    param (
        $VMName,
        $Session,
        $LANsubnetWithCIDR
    )

    Write-Host "Configuring DNS subnet Reverse Zone on $VMName" -ForegroundColor Yellow
    Get-VM $VMName
    if(-not $?)  {
        Write-Host "Cannot find $VMName to configure DNS subnet Reverse Zone.  Aborting!"        
        exit 1
    }
    # $network=Get-Network-Address -cidr $LANsubnetWithCIDR
    # $len=ExtractPrefixLen -cidr $LANsubnetWithCIDR
    # $subnet=$network+$len
    $network=ExtractIP -cidr $LANsubnetWithCIDR
    $octets=$network -split "\."
    $reverseZone=$octets[2]+"."+$octets[1]+"."+$octets[0]+".in-addr.arpa"

    $ArgumentList=$LANsubnetWithCIDR,$reverseZone
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $subnetreversezone=$args[0]
        $zoneID=$args[1]

        Get-DnsServerZone $zoneID
        if($?) { return $true }

        # $parts=$subnetreversezone -split "/"
        # Set-DnsServerForwarder -IPAddress $parts[0] -PassThru

        #Domain controller already have DNS
        # Install-WindowsFeature -Name DNS -IncludeManagementTools

        # New-NetIPAddress -IPAddress 10.0.0.3 -InterfaceAlias "Ethernet" -DefaultGateway 10.0.0.1 -AddressFamily IPv4 -PrefixLength 24
        #Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.2

        Set-DnsServerScavenging -ScavengingState $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -ScavengingInterval 7.00:00:00 -Verbose -PassThru
        Set-DnsServerResourceRecordAging -ZoneName $zoneID -Force -Recurse
        Write-Warning "Aging for Scavenging needs to be set in the zone"
        Write-Warning "Scavenging needs to be also checked in properties >advanced"

        # Add-DnsServerPrimaryZone -NetworkID "192.168.1.0/24" -ReplicationScope Domain 
        # https://www.readandexecute.com/how-to/server-2016/dns/configure-reverse-lookup-zone-with-powershell-windows-server-core-2016/
        Add-DnsServerPrimaryZone -NetworkID $subnetreversezone -ReplicationScope Domain 
        Get-DnsServerZone $zoneID
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Host "Error in process installing DNS in $VMName .  Aborting!"        
        exit 1
    }
    
    Write-Host "$VMName DNS install is complete" -ForegroundColor Green
}



function Install-DHCP-Scope {
    param (
        $VMName, 
        $Session,
        $FullyQualifiedDomainName,
        $DhcpIP,
        $DnsIP,
        $GatewayIP,
        $LANsubnetWithCIDR
    )

    Write-Host "Configuring DHCP Scope on $VMName..." -ForegroundColor Yellow
    Get-VM $VMName
    if(-not $?)  {
        Write-Host "Cannot find $VMName to configure DHCP Scope.  Aborting!"        
        exit 1
    }

    $DhcpDomainName=$VMName+"."+$FullyQualifiedDomainName
    $network=Get-Network-Address -cidr $LANsubnetWithCIDR
    
    $len=ExtractPrefixLen -cidr $LANsubnetWithCIDR
    $network=ExtractIP -cidr $LANsubnetWithCIDR
    $subnet=$network
    $start=MergeUsingOr-Network-Addresses -ip1 $network -ip2 0.0.0.1
    $end=MergeUsingOr-Network-Addresses -ip1 $network -ip2 0.0.0.254
    $mask=$(Get-Mask-As-IPObject -len $len).IPAddressToString
    $excl1=MergeUsingOr-Network-Addresses -ip1 $network -ip2 0.0.0.1
    $excl2=MergeUsingOr-Network-Addresses -ip1 $network -ip2 0.0.0.30
    $excl3=MergeUsingOr-Network-Addresses -ip1 $network -ip2 0.0.0.241
    $excl4=MergeUsingOr-Network-Addresses -ip1 $network -ip2 0.0.0.254


    $ArgumentList=$DhcpDomainName,$DhcpIP,$GatewayIP,$dnsIP,$FullyQualifiedDomainName,$subnet,$mask,$start,$end,$excl1,$excl2,$excl3,$excl4
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $dnsname=$args[0]
        $ip=$args[1]
        $gateway=$args[2]
        $dnsIP=$args[3]
        $domain=$args[4]
        
        $subnet=$args[5]
        $mask=$args[6]
        $start=$args[7]
        $end=$args[8]

        Get-DhcpServerv4Scope $subnet
        return $?
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if($rc) {
        Write-Host "Scope exists!"        
        return
    } else {
        Write-Host "Scope NOT found!"        
    }

    $ArgumentList=$DhcpDomainName,$DhcpIP,$GatewayIP,$dnsIP,$FullyQualifiedDomainName,$subnet,$mask,$start,$end,$excl1,$excl2,$excl3,$excl4
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $dnsname=$args[0]
        $ip=$args[1]
        $gateway=$args[2]
        $dnsIP=$args[3]
        $domain=$args[4]
        
        $subnet=$args[5]
        $mask=$args[6]
        $start=$args[7]
        $end=$args[8]
        
        Get-DhcpServerv4Scope
        if(-not $?) { 
            Write-Host "Error was expected.  Installing DHCP now..." 
            Install-WindowsFeature DHCP -IncludeManagementTools
            Restart-Service dhcpserver    
            
            Add-DhcpServerInDC -DnsName $dnsname -IPAddress $ip
            if(-not $?) { return $false }
        }

        Get-DhcpServerv4Scope $subnet
        if($?) { return $true } else { Write-Host "Error was expected.  Configuring DHCP scope..." }

        Write-Host "Scope Name[$subnet] StartRange[$start] EndRange[$end] SubnetMask[$mask]"
        Add-DhcpServerv4Scope -Name $subnet -StartRange $start -EndRange $end -SubnetMask $mask
        if(-not $?) { return $false }
        $scope=Get-DhcpServerv4Scope $subnet
        if(-not $?) { return $false }
        
        # scopeid is never actually specified.  It seems to auto-calculated be the network of the range.
        # which makes sense in a demented programmer sort of way bc dhcp pools have to be on non-overlapping subnets, in order to identify the right pool, based on the incoming DHCP request on a unicast source IP or interface IP of the broadcast.  Neither of which is going to be in the reservation.  but it has to exist in same pool cidr block to receive the 1st DORA packet.
        $scopeID=$scope.ScopeID
        Write-Host "Options computer[$dnsname] ScopeId[$scopeID] DnsServer[$dnsIP] DnsDomain[$domain] Router[$gateway]"
        Set-DhcpServerv4OptionValue -ComputerName $dnsname -ScopeId $scopeID -DnsServer $dnsIP -DnsDomain $domain -Router $gateway
        if(-not $?) { return $false }

        $count=$($args.Length)
        if($count -ge 10) {
            $excl1start=$args[9]
            $excl1end=$args[10]
            Add-Dhcpserverv4ExclusionRange -ScopeId $scopeID -StartRange $excl1start -EndRange $excl1end
            if(-not $?) { return $false }
        }
        if($count -ge 12) {
            $excl2start=$args[11]
            $excl2end=$args[12]
            Add-Dhcpserverv4ExclusionRange -ScopeId $scopeID -StartRange $excl2start -EndRange $excl2end
            if(-not $?) { return $false }
        }
        return $true

        #Add-DhcpServerInDC -DnsName DHCP1.corp.contoso.com -IPAddress 10.0.0.3
        #Get-DhcpServerInDC

        #Add-DhcpServerv4Scope -name "Corpnet" -StartRange 10.0.0.1 -EndRange 10.0.0.254 -SubnetMask 255.255.255.0 -State Active
        #Add-DhcpServerv4ExclusionRange -ScopeID 10.0.0.0 -StartRange 10.0.0.1 -EndRange 10.0.0.15
        #Set-DhcpServerv4OptionValue -OptionID 3 -Value 10.0.0.1 -ScopeID 10.0.0.0 -ComputerName DHCP1.corp.contoso.com
        #Set-DhcpServerv4OptionValue -DnsDomain corp.contoso.com -DnsServer 10.0.0.2

        #Add-DhcpServerv4Scope -name "Corpnet2" -StartRange 10.0.1.1 -EndRange 10.0.1.254 -SubnetMask 255.255.255.0 -State Active
        #Add-DhcpServerv4ExclusionRange -ScopeID 10.0.1.0 -StartRange 10.0.1.1 -EndRange 10.0.1.15
        #Set-DhcpServerv4OptionValue -OptionID 3 -Value 10.0.1.1 -ScopeID 10.0.1.0 -ComputerName DHCP1.corp.contoso.com        
    }
    Write-Host "[$rc]"
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Host "Error in process installing DHCP in $VMName .  Aborting!"        
        exit 1
    } else {
        Write-Host "Checkpoint"
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "DHCP configured"
    }
    
    Write-Host "$VMName DHCP install and scope is complete!!!" -ForegroundColor Green
}


function Install-DHCP {
    param (
        $VMName,
        $Session,
        $FullyQualifiedDomainName,
        $DhcpIP
    )

    Write-Host "Configuring DHCP services on $VMName" -ForegroundColor Yellow
    Get-VM $VMName
    if(-not $?)  {
        Write-Host "Cannot find $VMName to install DHCP services.  Aborting!"        
        exit 1
    }

    $rc=Invoke-Command -Session $Session -ScriptBlock {
        Get-DhcpServerv4Scope
        return $?
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if($rc) {
        Write-Host "DHCP services already defined"        
        return
    } else {
        Write-Host "Didnt find existing DHCP services"        
    }

    $FullDhcpName=$VMName+"."+$FullyQualifiedDomainName
    $ArgumentList=$FullDhcpName,$DhcpIP
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $dnsname=$args[0]
        $dhcpIP=$args[1]

        Get-DhcpServerv4Scope
        if(-not $?) { 
            Write-Host "Error was expected.  Installing DHCP now..." 
            Install-WindowsFeature DHCP -IncludeManagementTools
            Restart-Service dhcpserver    

            Write-Host "Authorize DnsName[$dnsname] IPAddress[$dhcpIP]"
            Add-DhcpServerInDC -DnsName $dnsname -IPAddress $dhcpIP
            if(-not $?) { return $false }
        }

        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Host "Error in process config DHCP service in $VMName .  Aborting!"        
        exit 1
    } else {
        Write-Host "Checkpoint"
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "DHCP service configured"
    }
    
    Write-Host "$VMName DHCP service is complete!!!" -ForegroundColor Green
}



function Install-DHCP-Failover {
    param (
        $VMName,
        $Session,
        $FullyQualifiedDomainName,
        $DhcpIP,
        $ScopeID
    )

    Write-Host "Configuring DHCP failover on $VMName" -ForegroundColor Yellow
    Get-VM $VMName
    if(-not $?)  {
        Write-Host "Cannot find $VMName to install DHCP failover.  Aborting!"        
        exit 1
    }
    $FullDhcpName=$VMName+"."+$FullyQualifiedDomainName
    $ArgumentList=$FullDhcpName,$DhcpIP,$ScopeID
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $dnsname=$args[0]
        $dhcpIP=$args[1]
        $scopeIP=$args[2]
        $name=$scopeIP+"-failover"

        Get-DhcpServerv4Failover $name
        return $?
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if($rc) {
        Write-Host "Existing failover found"        
        return
    } else {
        Write-Host "Failover NOT found"
    }


    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $dnsname=$args[0]
        $dhcpIP=$args[1]
        $scopeIP=$args[2]
        $name=$scopeIP+"-failover"

        Get-DhcpServerv4Failover $name
        if($?) { return $true } else { Write-Host "Error was expected.  Configuring DHCP failover..." }

        #Add-DhcpServerv4Failover -Name $name -PartnerServer $name -ServerRole Standby -ScopeId $dhcpIP
        Write-Host "Failover Name[$name] PartnerServer[$dhcpIP] ScopeId[$scopeIP]"
        Add-DhcpServerv4Failover -Name $name -PartnerServer $dhcpIP -ScopeId $scopeIP -ReservePercent 10 -MaxClientLeadTime 2:00:00 -AutoStateTransition $True -StateSwitchInterval 2:00:00
        if(-not $?) { return $false}
        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Host "Error in process config DHCP failover in $VMName .  Aborting!"        
        exit 1
    } else {
        Write-Host "Checkpoint"
        Checkpoint-VM -Name $($Session.ComputerName) -SnapshotName "DHCP failover configured"
    }
    
    Write-Host  "$VMName DHCP failover is complete!!!" -ForegroundColor Green
}

function Install-Site-Subnet {
    param (
        $VMName,
        $Session,
        $FullyQualifiedDomainName,
        $Subnet,
        $SiteName
    )

    Write-Host "Configuring DHCP failover on $VMName" -ForegroundColor Yellow
    Get-VM $VMName
    if(-not $?)  {
        Write-Host "Cannot find $VMName to install DHCP failover.  Aborting!"        
        exit 1
    }
    
    $ArgumentList=$firstsite,$Subnet,$SiteName
    $rc=Invoke-Command -Session $Session -ArgumentList $ArgumentList -ScriptBlock {
        $first=$args[0]
        $Subnet2=$args[1]
        $SiteName2=$args[2]

        Write-Host ">>> $first >>> $Subnet2 , >>> $SiteName2"

#New-ADReplicationSubnet -Name "192.168.57.0/24"
        
        Get-ADReplicationSite -identity $SiteName2
        if (! $?) {
            New-ADReplicationSite -Name $SiteName2
            if(-not $?) { return $false}
        } else {
            Write-Host "site [$SiteName2] created already"
        }

        get-ADReplicationSubnet -Filter "Name -eq `'$Subnet2`'" | findstr "$Subnet2"
        if (! $?) {
            New-ADReplicationSubnet -Name $Subnet2 -Site $SiteName2
            if(-not $?) { return $false}
        } else { 
            Write-Host "subnet [$Subnet2] created already"
        }

        $linkname="default-to-$SiteName2"
        get-ADReplicationSiteLink -filter "Name -eq `'$linkname`'" | findstr "$linkname"
        if (! $?) {
            New-ADReplicationSiteLink -Name "$linkname" -SitesIncluded Default-First-Site-Name,$SiteName2
            if(-not $?) { return $false}
        } else { 
            Write-Host "site link [$linkname] created already"
        }

        return $true
    }
    $tp=$rc.GetType().Name
    if($tp -eq "Object[]") { $rc=$rc[-1] }
    if(-not $rc) {
        Write-Host "Error in process config New Site/Subnet in $VMName .  Aborting!"        
        exit 1
    }
    
    Write-Host  "$VMName New site/subnet $SiteName/$Subnet is complete!!!" -ForegroundColor Green
}

Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}
function Test-Installation {
    param (
        $FullyQualifiedDomainName
    )
    # this is only function that uses global variables bc I got lazy

    $LANgatewayIP=ExtractIP -cidr $cidr
    $LANprefixlen=ExtractPrefixLen -cidr $cidr
    $LANnetwork=Get-Network-Address -cidr $cidr
    $LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen
    $domainca=$domain+".ca"

    $SwitchName=$firstsite+"LAN"
    $RouterName=$firstsite+"Router"
    $Dc1Name=$firstsite+"DC1"
    $Dc2Name=$firstsite+"DC2"
    $plaintext="Pa`$`$w0rd"
    $localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext
    # $Dc1Session=Wait-For-Session -server $Dc1Name -logincred $localcred -waitmessage "Please complete Windows install on $Dc1Name. Please set Administrator password to $plaintext"
    $Dc1IP=MergeUsingOr-Network-Addresses -ip1 $lannetwork -ip2 0.0.0.1
    # $Dc2Session=Wait-For-Session -server $Dc2Name -logincred $localcred -waitmessage "Please complete Windows install on $Dc2Name. Please set Administrator password to $plaintext"
    $Dc2IP=MergeUsingOr-Network-Addresses -ip1 $lannetwork -ip2 0.0.0.2


    Get-VM $Dc1Name 2>$null 1>$null
    Write-Host "[$?] host: Get-VM $Dc1Name"                                                                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

    $domaincred= Create-Credential -Resource $domain -Username "Administrator" -PlaintextPassword $plaintext
    $Dc1Session=Wait-For-Session -server $Dc1Name -logincred $domaincred -waitmessage "."  
    Write-Host "[($($Dc1Session -ne $null))] host: New-PSSession -VMName $Dc1Name -credential (New-Object PSCredential ($u, ConvertTo-SecureString($password)))"                    -ForegroundColor $(iif ($Dc1Session -ne $null) "Green" "Red") 

    if($Dc1Session -ne $null) {
        $ArgumentList=$DC1Name,$DC2Name,$FullyQualifiedDomainName,$lannetwork,$dc_dns,$Dc1IP,$Dc2IP,$firstsite
        $rc=Invoke-Command -Session $Dc1Session -ArgumentList $ArgumentList -ScriptBlock {
            Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}

            $DC1Name2=$args[0]
            $DC2Name2=$args[1]
            $FullyQualifiedDomainName2=$args[2]
            $lannetwork2=$args[3]
            $dc_dns2=$args[4]
            $Dc1IP2=$args[5]
            $Dc2IP2=$args[6]
            $sitename=$args[7]

            ping -n 1 8.8.8.8
            Write-Host "[$?] guest: ping 8.8.8.8"  -ForegroundColor $(iif $? "Green" "Red") 

            ping -n 1 $dc_dns2
            Write-Host "[$?] guest: ping -n 1 $dc_dns2"  -ForegroundColor $(iif $? "Green" "Red") 

            Write-Host "(below uses Resolve-DNSName, instead of nslookup, b/c nslookup still returns $true exit code despite unable to find DNS record)"
            Resolve-DNSName  $DC1Name2
            Write-Host "[$?] guest: Resolve-DNSName  $DC1Name2"                                                                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $DC2Name2
            Write-Host "[$?] guest: Resolve-DNSName  $DC2Name2"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 
            Write-Host "(above on DC1 uses $dc_dns2 as DNS, below uses itself as DNS)"

            Resolve-DNSName $DC1Name2 -server 127.0.0.1
            Write-Host "[$?] guest: Resolve-DNSName $DC1Name2 -server 127.0.0.1"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName $DC2Name2 -server 127.0.0.1
            Write-Host "[$?] guest: Resolve-DNSName $DC2Name2 -server 127.0.0.1"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2, for list of domain controllers"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 | findstr $Dc1IP2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc1IP2"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 | findstr $Dc2IP2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc2IP2"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Get-DhcpServerv4Scope $lannetwork2
            Write-Host "[$?] guest: Get-DhcpServerv4Scope $lannetwork2"                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

            Get-DhcpServerv4Failover -ComputerName "$Dc1Name2" -Name "$lannetwork2-failover"
            Write-Host "[$?] guest: Get-DhcpServerv4Failover -ComputerName '$Dc1Name2' -Name '$lannetwork2-failover'"                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

            Get-ADReplicationSite -identity $sitename
            Write-Host "[$?] guest: Get-ADReplicationSite -identity $sitename"   -ForegroundColor $(iif $? "Green" "Red") 

            Get-ADReplicationSubnet -Identity "$lannetwork2/24"
            Write-Host "[$?] guest: Get-ADReplicationSubnet -Identity $lannetwork2/24"   -ForegroundColor $(iif $? "Green" "Red") 

            get-ADReplicationSiteLink -filter "Name -eq 'default-to-$sitename'" | findstr "default-to-$sitename"
            Write-Host "[$?] guest: get-ADReplicationSiteLink -filter Name -eq 'default-to-$sitename' | findstr Default-to-$sitename"   -ForegroundColor $(iif $? "Green" "Red") 
        }
    }




    Get-VM $Dc2Name 2>$null 1>$null
    Write-Host "[$?] host: Get-VM $Dc2Name"     -ForegroundColor $(iif $? "Green" "Red") 

    $Dc2Session=Wait-For-Session -server $Dc2Name -logincred $domaincred -waitmessage ""
    Write-Host "[($($Dc2Session -ne $null))] host: New-PSSession -VMName $Dc2Name -credential (New-Object PSCredential ($u, ConvertTo-SecureString($password)))"                    -ForegroundColor $(iif ($Dc2Session -ne $null) "Green" "Red") 

    if($Dc2Session -ne $null) {
        $ArgumentList=$DC1Name,$DC2Name,$FullyQualifiedDomainName,$lannetwork,$dc_dns,$Dc1IP,$Dc2IP,$firstsite
        $rc=Invoke-Command -Session $Dc2Session -ArgumentList $ArgumentList -ScriptBlock {
            Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}

            $DC1Name2=$args[0]
            $DC2Name2=$args[1]
            $FullyQualifiedDomainName2=$args[2]
            $lannetwork2=$args[3]
            $dc_dns2=$args[4]
            $Dc1IP2=$args[5]
            $Dc2IP2=$args[6]
            $sitename=$args[7]

            ping -n 1 8.8.8.8
            Write-Host "[$?] guest: ping 8.8.8.8"  -ForegroundColor $(iif $? "Green" "Red") 

            ping -n 1 $dc_dns2
            Write-Host "[$?] guest: ping -n 1 $dc_dns2"  -ForegroundColor $(iif $? "Green" "Red") 

            Write-Host "(below uses Resolve-DNSName, instead of nslookup, b/c nslookup still returns $true exit code despite unable to find DNS record)"
            Resolve-DNSName  $DC1Name2
            Write-Host "[$?] guest: Resolve-DNSName  $DC1Name1"                                                                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $DC2Name2
            Write-Host "[$?] guest: Resolve-DNSName  $DC2Name2"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 
            Write-Host "(above on DC1 uses $dc_dns2 as DNS, below uses itself as DNS)"

            Resolve-DNSName $DC1Name2 -server 127.0.0.1
            Write-Host "[$?] guest: Resolve-DNSName $DC1Name2 -server 127.0.0.1"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName $DC2Name2 -server 127.0.0.1
            Write-Host "[$?] guest: Resolve-DNSName $DC2Name2 -server 127.0.0.1"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2, for list of domain controllers"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 | findstr $Dc1IP2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc1IP2"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 | findstr $Dc2IP2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc2IP2"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Get-DhcpServerv4Scope $lannetwork2
            Write-Host "[$?] guest: Get-DhcpServerv4Scope $lannetwork2"                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

            Get-DhcpServerv4Failover -ComputerName "$Dc2Name2" -Name "$lannetwork2-failover"
            Write-Host "[$?] guest: Get-DhcpServerv4Failover -ComputerName '$Dc2Name2' -Name '$lannetwork2-failover'"                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

            Get-ADReplicationSite -identity $sitename
            Write-Host "[$?] guest: Get-ADReplicationSite -identity $sitename"   -ForegroundColor $(iif $? "Green" "Red") 

            Get-ADReplicationSubnet -Identity "$lannetwork2/24"
            Write-Host "[$?] guest: Get-ADReplicationSubnet -Identity $lannetwork2/24"   -ForegroundColor $(iif $? "Green" "Red") 

            get-ADReplicationSiteLink -filter "Name -eq 'default-to-$sitename'" | findstr "default-to-$sitename"
            Write-Host "[$?] guest: get-ADReplicationSiteLink -filter Name -eq 'Default-to-$sitename' | findstr Default-to-$sitename"   -ForegroundColor $(iif $? "Green" "Red") 
        }
    }


    # testing on host
    # Internal Switch, should create a host adapter named ie: "vEthernet (JMBC-VanLAN)"
    get-NetAdapter "vEthernet ($SwitchName)" | %{$_.InterfaceDescription} | %{ Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "Description='$_'" } | %{ $_.RenewDHCPLease(); } | %{
        Write-Host "[$($_.ReturnValue -eq 0)] host: get-NetAdapter `"vEthernet ($SwitchName)`" | %{`$_.InterfaceDescription} | %{ Get-WmiObject Win32_NetworkAdapterConfiguration -Filter `"Description='`$_'`" } | %{ `$_.RenewDHCPLease(); } | %{ `$_.ReturnValue -eq 0 }"   -ForegroundColor (iif ($_.ReturnValue -eq 0) "Green" "Red") 
        Write-host "(above is to test if DHCP DORA is working, using DC as DHCP server)"
    }  2>$null

    ping -n 1 $Dc1IP 2>$null 1>$null
    Write-Host "[$?] host: ping -n 1 $Dc1IP"     -ForegroundColor $(iif $? "Green" "Red") 

    ping -n 1 $Dc2IP 2>$null 1>$null
    Write-Host "[$?] host: ping -n 1 $Dc2IP"     -ForegroundColor $(iif $? "Green" "Red") 


    ipconfig /release "vEthernet ($SwitchName)"  2>$null 1>$null
    # above line is necessary bc the default gateway received by DHCP, on interface, confuses Windows routing for 0.0.0.0/0
}



# START
# $site=$args[0]
# $cidr=$args[1]
# $wanip=$args[2]
# $routesstring=$args[3]
# $domain=$args[4]
# if($args.Count -eq 5) {
#     $testpingstring=$args[5]
# }
# $routes=$routesstring -split ","
# $testpings=$testpingstring -split ","

$LANgatewayIP=ExtractIP -cidr $cidr
$LANprefixlen=ExtractPrefixLen -cidr $cidr
$LANnetwork=Get-Network-Address -cidr $cidr
$LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen

#$WANprefixlen=ExtractPrefixLen -cidr $wanip
#$WANnetwork=Get-Network-Address -cidr $wanip
#$WANnetworkcidr=$WANnetwork+"/"+$WANprefixlen

$domainca=$domain+".ca"

$ISO="C:\Users\Bob\Downloads\Windows Server Datacenter ISO\en-us_windows_server_2022_x64_dvd_620d7eac.iso"
if(-not $(Test-Path -Path $ISO -PathType Leaf)) {
    write-Error "Cannot find $ISO, if Windows Server ISO is located elsewhere, change the `$ISO variable in this file to true location of ISO"
    exit 1
}
$VMPATH="c:\VM"
if(-not $(Test-Path -Path $VMPATH)) {
    Write-Warning "Creating $VMPATH for VM files..."
    New-Item -Path "c:\" -Name "VM" -ItemType "directory"
}

# Creating switches
$SwitchName=$site+"LAN"
Get-VMSwitch $SwitchName
if( -not $? )
{
    Write-Host "Missing LAN vswitch $SwitchName"
    exit 1
}

Get-NetAdapter "vEthernet ($SwitchName)"
if(-not $?) {
    Write-Error "Cannot find the Host NIC [vEthernet ($SwitchName)] for connecting to VM LAN"
    exit 2
}


# Creating VM
#Get-VMSwitch * | Format-Table Name
# New-VM -Name <Name> -MemoryStartupBytes <Memory> -BootDevice <BootDevice> -VHDPath <VHDPath> -Path <Path> -Generation <Generation> -Switch <SwitchName>
$RouterName=$site+"Router"
Get-VM $RouterName
if( -not $? )
{
    Write-Host "Missing LAN gateway Router $RouterName"
    exit 2
}

$Dc1Name=$site+"DC1"
Get-VM $Dc1Name
if( -not $? )
{
    Create-VM-Guest -VmName $Dc1Name -ISO $ISO -RAM 2GB -HD 150GB -SwitchName $SwitchName
}

$Dc2Name=$site+"DC2"
Get-VM $Dc2Name
if( -not $? )
{
    Create-VM-Guest -VmName $Dc2Name -ISO $ISO -RAM 2GB -HD 150GB -SwitchName $SwitchName
}


#$session=New-PSSession -VMName Unicomm-srvdc1 -credential $localcred

Write-Host "Waiting until $Dc2Name,$Dc2Name is installed with Windows..."
Write-Host "Script will continue once it detects the VM is installed with windows..."
Write-Host "Hyper-V connect windows should already be opened"

$plaintext="Pa`$`$w0rd"
# $password = ConvertTo-SecureString $plaintext -AsPlainText -Force
# $localcred= New-Object System.Management.Automation.PSCredential (".\Administrator", $password )
$localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext

# installing hostname and IP on DC1
$Dc1Session=Wait-For-Session -server $Dc1Name -logincred $localcred -waitmessage "Please complete Windows install on $Dc1Name. Please set Administrator password to $plaintext"
$Dc1IP=MergeUsingOr-Network-Addresses -ip1 $lannetwork -ip2 0.0.0.1
Set-StaticIP-on-Guest -Session $Dc1Session  -IP4 $Dc1IP  -GatewayIPwCIDR $cidr  -DnsIP $dc_dns  -ComputerName $Dc1Name

Start-Sleep -Seconds 5

# installing AD FOREST/DOMAIN on DC1 (no internet yet)
$Dc1Session=   Wait-For-Session -server $Dc1Name -logincred $localcred -waitmessage "..."
#Start-AD-on-Guest -Session $Dc1Session -DomainName $domain -PlaintextRecoveryPassword $plaintext
Add-AD-on-Guest -Session $Dc1Session -DomainName $domain -DomainPlaintextPassword $plaintext
Start-Sleep -Seconds 5
$domaincred= Create-Credential -Resource $domain -Username "Administrator" -PlaintextPassword $plaintext
$Dc1Session=   Wait-For-Session -server $Dc1Name -logincred $domaincred -waitmessage "..."
Install-DNS-Reverse-Zone -VMName $Dc1Name -Session $Dc1Session -LANsubnetWithCIDR $lannetworkcidr

$Dc1Session=   Wait-For-Session -server $Dc1Name -logincred $domaincred -waitmessage "..."
Install-DHCP-Scope -VMName $Dc1Name -Session $Dc1Session  -FullyQualifiedDomainName $domainca  -DhcpIP $Dc1IP -DnsIP $Dc1IP -GatewayIP $LANgatewayIP  -LANsubnetWithCIDR $lannetworkcidr

Start-Sleep -Seconds 10





# installing hostname and IP on DC2
$Dc2Session=Wait-For-Session -server $Dc2Name -logincred $localcred -waitmessage "Please complete Windows install on $Dc2Name. Please set Administrator password to $plaintext"
$Dc2IP=MergeUsingOr-Network-Addresses -ip1 $lannetwork -ip2 0.0.0.2
# Computers that are on domain, must IP DNS pointed to DC
Set-StaticIP-on-Guest -Session $Dc2Session  -IP4 $Dc2IP  -GatewayIPwCIDR $cidr  -DnsIP $Dc1IP  -ComputerName $Dc2Name

Start-Sleep -Seconds 5

# installing AD Join Domain on DC2
$Dc2Session=   Wait-For-Session -server $Dc2Name -logincred $localcred -waitmessage "..."
Add-AD-on-Guest -Session $Dc2Session -DomainName $domain -DomainPlaintextPassword $plaintext
Start-Sleep -Seconds 5

$Dc2Session=   Wait-For-Session -server $Dc2Name -logincred $domaincred -waitmessage "..."
Install-DHCP -VMName $Dc2Name -Session $Dc2Session -FullyQualifiedDomainName $domainca -DhcpIP $Dc1IP 




# Back to DC1 to install failover, after DHCP installed
$Dc1Session=   Wait-For-Session -server $Dc1Name -logincred $domaincred -waitmessage "..."
Install-DHCP-Failover -VMName $Dc1Name -Session $Dc1Session -FullyQualifiedDomainName $domainca -DhcpIP $Dc2Name -ScopeID $lannetwork
# Write-Warning "DHCP failover needs to be configured manually!!!"

$Dc1Session=   Wait-For-Session -server $Dc1Name -logincred $domaincred -waitmessage "..."
Install-Site-Subnet -VMName $Dc1Name -Session $Dc1Session -FullyQualifiedDomainName $domainca -Subnet $LANnetworkcidr -SiteName $site
#Install-Site-Subnet -VMName $Dc2Name -Session $Dc2Session -FullyQualifiedDomainName $domainca -Subnet $LANnetworkcidr -SiteName $site





# Close all remote powershell sessions
Remove-PSSession -Session $Dc1Session
Remove-PSSession -Session $Dc2Session

Write-Host "Finished!"

Write-host ""
Write-host "Tests"
Write-host "====="

Test-Installation -FullyQualifiedDomainName $domainca

Write-host "Tests Complete!"
Write-host ""
Write-host ""
Write-host ""





# SIG # Begin signature block
# MIIbpwYJKoZIhvcNAQcCoIIbmDCCG5QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTlBUY2xuebFtAVdyU5xqv/fU
# 9higghYZMIIDDjCCAfagAwIBAgIQILC/BxlyRYZJ/JpoWdQ86TANBgkqhkiG9w0B
# AQsFADAfMR0wGwYDVQQDDBRBVEEgQXV0aGVudGljb2RlIEJvYjAeFw0yMzA1MTMw
# NzAxMzRaFw0yNDA1MTMwNzIxMzRaMB8xHTAbBgNVBAMMFEFUQSBBdXRoZW50aWNv
# ZGUgQm9iMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1S634xJz5zL
# u9xSU6J+nhYUwneEj3nz5QulBKBuMTjYUjieBgQsZcZyLI4wpWqmoH9CtWPi3yEN
# aLkNXu8pKCSdU5u8cIlJ29rWIxyuyHA1VOV5jqhjPYpPJpxrmy9OZStirBaSNV0F
# h3pMuigKRRbJ767JJiN2NKk3sFHTmjIpUjcG7KgAC+jzjuDTyOTwGJOKZqkMLapH
# vP8pmATqOtSFXr+f/nFO8KF+dsDMGc+8W4yzqrGjtECv7HZuB25xHLmKiNlrYrH/
# 2GEwPaaY726B0CJNWIcs5nWXm/2OCHvAcmdaSvzM6CvdIFGuRP5nvLNfG/7RFqC9
# MIW2fCii1QIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFPRbWcU+yUoWe506mykLzQ7h4df2MA0GCSqGSIb3DQEB
# CwUAA4IBAQBuxWS+EJ1nUt71FkgsQPMVTRPdWsfhe3N0Mm1D8k9oiXT00win5I7Y
# gFHjzuqa1zp/fylw56JzBNATPepDExLHv0OvmOBP64gJs/+24qfvKOcvSDAMkT68
# HoTJo6bcyOU93C5pH02pzCBIe7pj3rMVeTTLoxtUagZpgrdyprfuOZG6vq1plujk
# shWeNkVz0EFnUkzR2cvzfwuiw2aSR4i+vJUAlVKV5qjC6gHQyqCd7D/s5AzU3Vqn
# BZtW8Ag7NHDkULU6NoOnwcd9dHyKsQjOUSfbd0qJe/1rBU7e5y1niDj+qlANe8aG
# xls+P+IYB1p9vmDuJbutX2E3fM9MjjUBMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv
# 21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcN
# MzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf
# 8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1
# mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe
# 7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecx
# y9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX
# 2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX
# 9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp49
# 3ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCq
# sWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
# dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauG
# i0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# HwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGG
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXn
# OF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23
# OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFI
# tJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7s
# pNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgi
# wbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cB
# qZ9Xql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG
# 9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVz
# dGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRp
# Z2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENB
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUD
# xPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1AT
# CyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW
# 1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS
# 8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jB
# ZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCY
# Jn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucf
# WmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLc
# GEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNF
# YLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI
# +RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjAS
# vUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX
# 44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggr
# BgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDag
# NIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3
# DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJL
# Kftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgW
# valWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2M
# vGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSu
# mScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJ
# xLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un
# 8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SV
# e+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4
# k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJ
# Dwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr
# 5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBsAw
# ggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJKoZIhvcNAQELBQAwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAe
# Fw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTlaMEYxCzAJBgNVBAYTAlVTMREw
# DwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIw
# MjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz+ylJjrGqfJr
# u43BDZrboegUhXQzGias0BxVHh42bbySVQxh9J0Jdz0Vlggva2Sk/QaDFteRkjgc
# MQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdCriak5Lt4eLl6FuFWxsC6ZFO7
# KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58tySSgeTIAehVbnhe3yYbyqOgd99qtu
# 5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0jM1MuWbIu6pQOA3ljJRdGVq/
# 9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdPbnjEKD+jHA9QBje6CNk1prUe
# 2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2Off1wU9xLokDEaJLu5i/+k/k
# ezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZIS1j5Vn1TS+QHye30qsU5Thm
# h1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMvwi4g14Gs0/EH1OG92V1LbjGU
# KYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8JJVPxvzvpqwcOagc5YhnJ1oV/
# E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mDjcbu9Sx8e47LZInxscS451Ne
# X1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQE
# AwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1Ud
# IAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUv
# cyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8jzEU7ZcLzT0qlBTfUpwwWgYD
# VR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYB
# BQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkq
# hkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP1oUj8fz5lTmbJeb3coqYw3fU
# ZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCbEx2wmIncePLNfIXNU52vYuJh
# ZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojOfRu4aqKbwVNgCeijuJ3XrR8c
# uOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkVNTZZmg9U0rIbf35eCa12VIp0
# bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/HMCb7XxIstiSDJFPPGaUr10C
# U+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkjgNc2Wl+WFrFjDMZGQDvOXTXU
# WT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclTuf80EGf2JjKYe/5cQpSBlIKd
# rAqLxksVStOYkEVgM4DgI974A6T2RUflzrgDQkfoQTZxd639ouiXdE4u2h4djFrI
# HprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg53hWf2rvwpWaSxECyIKcyRoF
# fLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54BNu90ftbCqhwfvCXhHjjCANd
# RyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYBDriL7ubgclWJLCcZYfZ3AYwx
# ggT4MIIE9AIBATAzMB8xHTAbBgNVBAMMFEFUQSBBdXRoZW50aWNvZGUgQm9iAhAg
# sL8HGXJFhkn8mmhZ1DzpMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRj+yCQM8OvIAa/IF9TZJ2g
# MgnwdzANBgkqhkiG9w0BAQEFAASCAQCtwcxpWqDetB3Wazg6jq4cRPi0gyCalyxB
# enyDaQGYGmgnLTcQnDoK+CQyPcndd/k6yfZtdokQ/fTVEAFXUAxLgg64D0Ufapvr
# IMitAa8pjF6ft6jfXYG6N0QhWMnLibkfIGl6OJzyCy1xg0lYMCXKFIrVEdcF0dEf
# rqoqMjF4jYXr8bIU6iHYNiMoOV9ZJvn/Tbdn9yc8+DoXVaD8FXlx7fHVBowO4/RD
# x3x0ciIogVJnm9HaraBGnxPwQUy54FI4QWKnEwI+w1iv9wtB/pPzmIxWv2pe+JY/
# WmeeGs0VSgwGuKwfb/ekclefk3ad28mmeVosi+/gMaRw8ZRNiid2oYIDIDCCAxwG
# CSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJT
# QTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjAN
# BglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTIzMDcwODE5NTQzMFowLwYJKoZIhvcNAQkEMSIEINNUZ3Uz5dxn
# IK4cUGclcTAYLApDFg/Oj2+E1zqW9FFpMA0GCSqGSIb3DQEBAQUABIICAKRkEZrD
# d3hA/mJkSseDE13syQRr6ujVenm8Sjh8PDAbjWfS+l8J6vSdc0mEZmVu2pqwFFNP
# e53efjvgY7xBy1bNZ3pqN8rCztTQlrBEGuqawdTjP7i0AXu+ngR3j376KNF8zGgm
# UG7dvdOqQaYOCOFyfTHHRmBAu89UzNDc14OKi4EHpqThur3IpFs//fnKFKagJ9Gp
# 59ddv/wVkbvVS2B1Q9Fs54qlqojZOfdV2z2HCRYInuV64iMXOFH3AcaFjAICLRkq
# UQ8YhvEQX+Le5zgf1Aa1wQEuxGn4IBFI9l1ozN8kWpbomnezTQ7asliozxr2Rv0u
# UGka2DGVHpbUKSy+7RYlsGesXBJV4pkpbTMrlhMcyuVTy4XahdE76WnqAyhttp9p
# JXQhXo08d58o9/lq+gJMfANzHx3Ydd/s/0OX0DtQulmUKiRh39PqB0tXNSE9CgzP
# EfHY9VgubFfpOjFD7wyxyD/fb1VvU/lVIqh8Eyf+UWTrmJU82aQnl+mhVB6VKBG1
# gmVwOm67Sqi6izwt/nIim+zm96/ZBwvNrMeNxw8x2E8chEOHLjwOaIfHiJiIxfCG
# ezDmKJQWF74JQvxZjmzGRsqhjeoBoby97wiW/Q7mStrFYwx5r7fJNjnp4ToBPjoP
# qdsGM3980ZVSZItZGgU1qVk3QQnkzkZRTe0M
# SIG # End signature block
