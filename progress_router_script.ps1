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

$all=$args[0]
$gatewaylist=$all -split ","







$Time = [System.Diagnostics.Stopwatch]::StartNew()
while ($true) {
    cls
    $CurrentTime = $Time.Elapsed
    write-host $([string]::Format("`rTime: {0:d2}:{1:d2}:{2:d2}",
                                  $CurrentTime.hours,
                                  $CurrentTime.minutes,
                                  $CurrentTime.seconds)) -nonewline
    write-host ""
    Show-Progress -all $all
    write-host ""
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"
    write-host "##################################"

    Start-Sleep -Seconds 5
    if ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character)) {
        Write-Host "Exiting now"
        break;
    }
}