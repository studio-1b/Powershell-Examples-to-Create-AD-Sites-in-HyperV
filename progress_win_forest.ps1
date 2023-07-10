$arglen=$($args.length)
if($arglen -lt 4) {
    Write-Host "Use same arguments as 'create_win_forest.ps1' to see online progress of the script"
   #Write-Host "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789|123456789 123456789 123456789"
    Write-Host "                                   Prefix    Gateway/subnet      other site subnets                      			Domain"
    Write-Host "                                   ------    --------------      ---------------                       				------"
    Write-Host "if you are running..."
    Write-Host "Running: ./create_win_forest.ps1   JMBC-Van  192.168.200.254/24  JMBC-Tor=192.168.150.0/24,JMBC-Mon=192.168.100.0/24,JMBC-Cal=192.168.50.0/24  JoMaBoCh"
    Write-Host "then run to see progress..."
    Write-Host "Usage:   ./progress_win_forest.ps1 JMBC-Van  192.168.200.254/24  JMBC-Tor=192.168.150.0/24,JMBC-Mon=192.168.100.0/24,JMBC-Cal=192.168.50.0/24  JoMaBoCh"

    exit 1
}


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

function Wait-For-Session {
    param (
        $server,
        $logincred,
        $localcred,
        $waitmessage
    )
    Write-Host "trying to connect to $server                                     "

    $session=New-PSSession -VMName $server -credential $logincred 2>$null
    if( -not $? ) { $session=New-PSSession -VMName $server -credential $localcred 2>$null}
    while( -not $? ) {
        Write-Host "Moving on now...                                             "; 
        return $null
    }
    Write-Host "$server connected!!!                                             " -ForegroundColor Black

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


Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}
Function IBAnd($a, $b, $Right, $Wrong) {If ($a -band $b) {$Right} Else {$Wrong}}
function Test-Installation {
    param (
        $FullyQualifiedDomainName
    )
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

   #Write-Host "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 "
    Get-VM $Dc1Name 2>$null 1>$null
    Write-Host "[$?] host: Get-VM $Dc1Name                                            "   -ForegroundColor $(iif $? "Green" "Red") 

    $domaincred= Create-Credential -Resource $domain -Username "Administrator" -PlaintextPassword $plaintext
    $localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext
    $Dc1Session=Wait-For-Session -server $Dc1Name -logincred $domaincred -localcred $localcred  -waitmessage "."  
    Write-Host "[($($Dc1Session -ne $null))] host: New-PSSession -VMName $Dc1Name -credential (New-Object PSCredential ($u, ConvertTo-SecureString($password)))    "                    -ForegroundColor $(iif ($Dc1Session -ne $null) "Green" "Red") 

    if($Dc1Session -ne $null) {
        $ArgumentList=$DC1Name,$DC2Name,$FullyQualifiedDomainName,$lannetwork,$sites,$Dc1IP,$Dc2IP
        $rc=Invoke-Command -Session $Dc1Session -ArgumentList $ArgumentList -ScriptBlock {
            Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}

            $DC1Name2=$args[0]
            $DC2Name2=$args[1]
            $FullyQualifiedDomainName2=$args[2]
            $lannetwork2=$args[3]
            $sites2=$args[4]
            $Dc1IP2=$args[5]
            $Dc2IP2=$args[6]

            # ping bug returns true, when it cannot arp the address.  Only output is reliable
            ping -n 1 8.8.8.8 | findstr 'bytes='
            Write-Host "[$?] guest: ping 8.8.8.8                                               "  -ForegroundColor $(iif $? "Green" "Red") 

            foreach($site2 in $sites2) {
                $part2=$site2 -split "="
                $otherdc=$part2[1].replace(".0/",".1/")
                $otherdc=$otherdc.substring(0,$otherdc.indexof("/"))
                ping -n 1 $otherdc | findstr 'bytes=' 
                Write-Host "[$?] guest: ping $otherdc (ok false, if other DC not installed)                                    "  -ForegroundColor $(iif $? "Green" "Red") 
            }

            Resolve-DNSName  $DC1Name2 2>$null 1>$null
            Write-Host "[$?] guest: Resolve-DNSName  $DC1Name2                                 "                                                                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $DC2Name2 2>$null 1>$null
            Write-Host "[$?] guest: Resolve-DNSName  $DC2Name2, for joined login auto dns register   " -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 2>$null 1>$null
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2, for list of domain controllers  "  -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2  2>$null | findstr $Dc1IP2 2>$null 1>$null
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc1IP2     "  -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 2>$null | findstr $Dc2IP2 2>$null 1>$null
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc2IP2     "   -ForegroundColor $(iif $? "Green" "Red") 

            try{Get-DhcpServerv4Scope $lannetwork2 2>$null 1>$null} catch {}
            Write-Host "[$?] guest: Get-DhcpServerv4Scope $lannetwork2                          "   -ForegroundColor $(iif $? "Green" "Red") 

            try{Get-DhcpServerv4Failover -ComputerName "$Dc1Name2" -Name "$lannetwork2-failover" 2>$null 1>$null} catch {}
            Write-Host "[$?] guest: Get-DhcpServerv4Failover -ComputerName '$Dc1Name2' -Name '$lannetwork2'   "   -ForegroundColor $(iif $? "Green" "Red") 

            foreach($site2 in $sites2) {
                $part2=$site2 -split "="
                #$othergateway=$part2[1].replace(".0/",".254/")
                #$othergateway=$othergateway.substring(0,$othergateway.indexof("/"))
                $sitename=$part2[0]
                $sitesubnet=$part2[1]

                try{Get-ADReplicationSite -identity $sitename 2>$null 1>$null} catch {}
                Write-Host "[$?] guest: Get-ADReplicationSite -identity $sitename                "   -ForegroundColor $(iif $? "Green" "Red") 

                try{Get-ADReplicationSubnet -Identity $sitesubnet 2>$null 1>$null} catch {}
                Write-Host "[$?] guest: Get-ADReplicationSubnet -Identity $sitesubnet            "   -ForegroundColor $(iif $? "Green" "Red") 

                try{get-ADReplicationSiteLink -filter "Name -eq 'default-to-$sitename'" 2>$null | findstr "default-to-$sitename" 2>$null 1>$null} catch {}
                Write-Host "[$?] guest: get-ADReplicationSiteLink -filter Name -eq 'default-to-$sitename' | findstr Default-to-$sitename   "   -ForegroundColor $(iif $? "Green" "Red") 
            }
        } 2>$null
    }




    Get-VM $Dc2Name 2>$null 1>$null
    Write-Host "[$?] host: Get-VM $Dc2Name                                      "     -ForegroundColor $(iif $? "Green" "Red") 

    $Dc2Session=Wait-For-Session -server $Dc2Name -logincred $domaincred -localcred $localcred -waitmessage ""
    Write-Host "[($($Dc2Session -ne $null))] host: New-PSSession -VMName $Dc2Name -credential (New-Object PSCredential ($u, ConvertTo-SecureString($password)))   "                    -ForegroundColor $(iif ($Dc2Session -ne $null) "Green" "Red") 

    if($Dc2Session -ne $null) {
        $ArgumentList=$DC1Name,$DC2Name,$FullyQualifiedDomainName,$lannetwork,$sites,$Dc1IP,$Dc2IP
        $rc=Invoke-Command -Session $Dc2Session -ArgumentList $ArgumentList -ScriptBlock {
            Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}

            $DC1Name2=$args[0]
            $DC2Name2=$args[1]
            $FullyQualifiedDomainName2=$args[2]
            $lannetwork2=$args[3]
            $sites2=$args[4]
            $Dc1IP2=$args[5]
            $Dc2IP2=$args[6]

            try {Get-ADDomainController 2>$null 1>$null}catch{}
            Write-Host "[$?] guest: Get-ADDomainController (Is AD software installed?)               "   -ForegroundColor $(iif $? "Green" "Red") 

            try {Get-ADDomainController $DC2Name2 2>$null 1>$null}catch{}
            Write-Host "[$?] guest: Get-ADDomainController $DC2Name2                                 "   -ForegroundColor $(iif $? "Green" "Red") 

            try {Get-DhcpServerv4Failover -ComputerName "$Dc2Name2" -Name "$lannetwork2-failover" 2>$null 1>$null}catch{}
            Write-Host "[$?] guest: Get-DhcpServerv4Failover -ComputerName '$Dc2Name2' -Name '$lannetwork2'   "   -ForegroundColor $(iif $? "Green" "Red") 

        } 2>$null
    }


    # testing on host
    # Internal Switch, should create a host adapter named ie: "vEthernet (JMBC-VanLAN)"
    $dhcpup=$false
    if($Dc1Session -ne $null) {
        $dhcpup=Invoke-Command -Session $Dc1Session -ArgumentList $lannetwork -ScriptBlock {
            $lannetwork2=$args[0]
            try {Get-DhcpServerv4Scope $lannetwork2    2>$null 1>$null} catch {}
            return $?
        }
    }
    if($dhcpup) {
        try{
            get-NetAdapter "vEthernet ($SwitchName)" | Set-NetIPInterface -DHCP Enabled
            ipconfig /release "vEthernet ($SwitchName)"  2>$null 1>$null
            get-NetAdapter "vEthernet ($SwitchName)" | %{$_.InterfaceDescription} | %{ Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "Description='$_'" } | %{ $_.RenewDHCPLease(); } | %{
                Write-Host "[$($_.ReturnValue -eq 0)] host: get-NetAdapter `"vEthernet ($SwitchName)`" | %{`$_.InterfaceDescription} | %{ Get-WmiObject Win32_NetworkAdapterConfiguration -Filter `"Description='`$_'`" } | %{ `$_.RenewDHCPLease(); } | %{ `$_.ReturnValue -eq 0 }    "   -ForegroundColor (iif ($_.ReturnValue -eq 0) "Green" "Red") 
                Write-host "(above is to test if DHCP DORA is working, using DC as DHCP server)              "
            }  2>$null

            ping -n 1 $Dc1IP 2>$null | findstr 'bytes='
            Write-Host "[$?] host: ping -n 1 $Dc1IP                                    "     -ForegroundColor $(iif $? "Green" "Red") 

            ping -n 1 $Dc2IP 2>$null | findstr 'bytes='
            Write-Host "[$?] host: ping -n 1 $Dc2IP                                    "     -ForegroundColor $(iif $? "Green" "Red") 

        } finally {
            ipconfig /release "vEthernet ($SwitchName)"  2>$null 1>$null
            get-NetAdapter "vEthernet ($SwitchName)" | Set-NetIPInterface -DHCP Disabled
            # above line is necessary bc the default gateway received by DHCP, on interface, confuses Windows routing for 0.0.0.0/0
        }
    }    else {
        Write-Host "[False] host: Can't test DORA, b/c DHCP on DC1 not up" -ForegroundColor Red
    }
    
}





# START (switches)


$site=$args[0]
$firstsite=$site
$cidr=$args[1]
$sitesstring=$args[2]
$domain=$args[3]
$sites=$sitesstring -split ","


$LANgatewayIP=ExtractIP -cidr $cidr
$LANprefixlen=ExtractPrefixLen -cidr $cidr
$LANnetwork=Get-Network-Address -cidr $cidr
$LANnetworkcidr=$LANnetwork+"/"+$LANprefixlen


$domainca=$domain+".ca"
$ISO="C:\Users\Bob\Downloads\Windows Server Datacenter ISO\en-us_windows_server_2022_x64_dvd_620d7eac.iso"
$VMPATH="c:\VM"
$SwitchName=$site+"LAN"
$RouterName=$site+"Router"
$Dc1Name=$site+"DC1"
$Dc2Name=$site+"DC2"

$plaintext="Pa`$`$w0rd"
$localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext
$Dc1IP=MergeUsingOr-Network-Addresses -ip1 $lannetwork -ip2 0.0.0.1
$domaincred= Create-Credential -Resource $domain -Username "Administrator" -PlaintextPassword $plaintext
$Dc2IP=MergeUsingOr-Network-Addresses -ip1 $lannetwork -ip2 0.0.0.2


cls
$Time = [System.Diagnostics.Stopwatch]::StartNew()
while ($true) {
    [System.Console]::SetCursorPosition(0, 0)

    $CurrentTime = $Time.Elapsed
    write-host $([string]::Format("`rTime: {0:d2}:{1:d2}:{2:d2}",
                                  $CurrentTime.hours,
                                  $CurrentTime.minutes,
                                  $CurrentTime.seconds)) -nonewline
    Write-Host "                                                                     "
    Test-Installation -FullyQualifiedDomainName $domainca
    Write-Host "                                                                     "
    write-host "##################################                                   "
    Write-Host "                                                                     "
    Write-Host "                                                                     "
    Write-Host "                                                                     "

    Start-Sleep -Seconds 5
    if ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character)) {
        Write-Host "Exiting now"
        break;
    }
}
