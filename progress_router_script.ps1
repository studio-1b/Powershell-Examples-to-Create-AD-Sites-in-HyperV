$arglen=$($args.length)
if($arglen -lt 1) {
    Write-Host "Use same arguments as 'create_router_vm.ps1' to see the progress."
    Write-Host ""
   #Write-Host "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789|123456789 123456789 123456789"
    Write-Host "                                    Prefix=Gateway/subnet=WANIP=Domain"
    Write-Host "                                    ------    --------------      -----        ------"
    Write-Host "if running..."
    Write-Host "Running: ./create_router_vm.ps1     JMBC-Van=192.168.200.254/24=10.0.7.1/24=JoMaBoCh,JMBC-Tor=192.168.150.254/24=10.0.7.4/24=JoMaBoCh,JMBC-Mon=192.168.100.254/24=10.0.7.3/24=JoMaBoCh,JMBC-Cal=192.168.50.254/24=10.0.7.2/24=JoMaBoCh"
    Write-Host "then to see progress, run..."
    Write-Host "Usage:   ./progress_router_script.ps1 JMBC-Van=192.168.200.254/24=10.0.7.1/24=JoMaBoCh,JMBC-Tor=192.168.150.254/24=10.0.7.4/24=JoMaBoCh,JMBC-Mon=192.168.100.254/24=10.0.7.3/24=JoMaBoCh,JMBC-Cal=192.168.50.254/24=10.0.7.2/24=JoMaBoCh"

    exit 1
}
$limit=5

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
    $stop=$limit
    Write-Host "trying to connect to $server                                     "

    $session=New-PSSession -VMName $server -credential $logincred
    while( -not $? ) {
        Write-Host "Moving on now...                                             "; 
        return $null
    }
    Write-Host "$server connected!!!                                             " -ForegroundColor Black

    $limit=60
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
       #Write-Host "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 "
        Write-Host "Shared networks"
        Write-Host "[ ] host: Get-VMSwitch $ISPName                                      " -ForegroundColor Red
        Write-Host "[ ] host: Get-VMSwitch $WANName                                      " -ForegroundColor Red

        foreach($lan in $gatewaylist) {
            $site=$lanargs[0]
            $cidr=$lanargs[1]
            $wanip=$lanargs[2]
            $domain=$lanargs[3]
            Write-Host "Guest stub network: $site                                        "

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

            Write-Host "LAN config confirmation                                          "
            Write-Host "[ ] guest: get-NetAdapter $SwitchName                            "                            -ForegroundColor Red
            Write-Host "[ ] guest: get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP   "                  -ForegroundColor Red

            Write-Host "Internet config confirmation                                     "
            Write-Host "[ ] guest: get-NetAdapter Internet                               "                            -ForegroundColor Red
            Write-Host "[ ] guest: netsh routing ip nat show interface Internet          "                            -ForegroundColor Red
            Write-Host "[ ] guest: netsh routing ip nat show interface LAN               "                            -ForegroundColor Red
            Write-Host "[ ] guest: Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where {$_.InterfaceAlias -eq Internet}  " -ForegroundColor Red
            Write-Host "[ ] guest: ping 8.8.8.8                                          "                            -ForegroundColor Red
            Write-Host "[ ] guest: nslookup www.google.ca                                "                            -ForegroundColor Red

            Write-Host "WAN config confirmation                                          "
            Write-Host "[ ] guest: get-NetIPAddress -InterfaceAlias WAN -IPAddress $WANgatewayIP "                   -ForegroundColor Red
            foreach($wan in $allwan) {
                Write-Host "[ ] guest: ping $wan                                           "                          -ForegroundColor Red
            }

            foreach($lan in $alllan) {
                if ($lan -eq $LANgatewayIP) {
                    Write-Host "[ ] guest: Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq LAN}  " -ForegroundColor Red
                } else {
                    Write-Host "[ ] guest: Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq WAN}  " -ForegroundColor Red
                }
            }
            foreach($lan in $alllan) {
                Write-Host "[ ] guest: ping $lan                                         "                            -ForegroundColor Red
            }
        }
        return
    }

    Write-Host "Shared networks                                                          " -BackgroundColor white -Foregroundcolor black 
    Get-VMSwitch $ISPName  2>&1 > $null 
    Write-Host "[$?] host: Get-VMSwitch $ISPName                                         " -ForegroundColor (IIf $? "Green" "Red")
    Get-VMSwitch $WANName   2>&1 > $null 
    Write-Host "[$?] host: Get-VMSwitch $WANName                                         " -ForegroundColor (IIf $? "Green" "Red")

    $gatewaylist=$all -split ","
    $alllan = $gatewaylist | % {$(ExtractIP -cidr $_.split('=')[1]) }
    $allwan = $gatewaylist | % {$(ExtractIP -cidr $_.split('=')[2]) }
    foreach($lan in $gatewaylist) {
        Write-Host "                                                                     "
        $lanargs=$lan -split "="
        # Vancouver=192.168.200.254/24=10.0.7.1/24=JoMaBoCh

        $site=$lanargs[0]
        $cidr=$lanargs[1]
        $wanip=$lanargs[2]
        $domain=$lanargs[3]
        Write-Host "Guest stub network: $site                                            "  -BackgroundColor darkgray

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

        Write-Host "LAN config confirmation                                              "  -BackgroundColor darkgray
        Get-VMSwitch $SwitchName  2>$null 1>$null 
        Write-Host "[$?] host: Get-VMSwitch $SwitchName                                  " -ForegroundColor (IIf $? "Green" "Red")
        Get-VM $VMName  2>$null 1>$null 
        Write-Host "[$?] host: Get-VM $VMName                                            " -ForegroundColor (IIf $? "Green" "Red")

        Get-VM $VMName 2>$null 1>$null
        if ($?) {
            $Session=Wait-For-Session -server $VMName -logincred $localcred -waitmessage "" 2> $null
        }
        Write-Host "[$($Session -ne $null)] host: New-PSSession -VMName $VMName -credential $localcred     "  -ForegroundColor (IIf ($Session -ne $null) "Green" "Red")
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
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetAdapter LAN   "                                                               -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

        Write-Host "Internet config confirmation                                     "  -BackgroundColor darkgray

                get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetIPAddress -InterfaceAlias LAN -IPAddress $LANgatewayIP  "                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                get-NetAdapter Internet
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetAdapter Internet             "                                                          -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                netsh routing ip nat show interface Internet | findstr "Mode              : Address and Port Translation"
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: netsh routing ip nat show interface Internet                   "                                     -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                netsh routing ip nat show interface LAN | findstr "Mode              : Address and Port Translation"
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: netsh routing ip nat show interface LAN             "                                          -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                Find-NetRoute -RemoteIPAddress "8.8.8.8" | Where {$_.InterfaceAlias -eq "Internet"} | findstr "InterfaceAlias     : Internet"
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where {`$_.InterfaceAlias -eq Internet}     " -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                ping -n 1 8.8.8.8
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: ping 8.8.8.8                                         "                                                                     -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                Resolve-DNSName www.google.ca
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Resolve-DNSName www.google.ca                        "                                                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

        Write-Host "WAN config confirmation                                           "  -BackgroundColor darkgray

                get-NetIPAddress -InterfaceAlias WAN -IPAddress $WANgatewayIP
                $code=$code + (IIf $? $flag 0)
                Write-Host "[$(IBAnd $code $flag "X" " ")] guest: get-NetIPAddress -InterfaceAlias WAN -IPAddress $WANgatewayIP    "                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                $flag=$flag*2

                foreach($wan in $allwan) {
                    ping -n 1 $wan
                    $code=$code + (IIf $? $flag 0)
                    Write-Host "[$(IBAnd $code $flag "X" " ")] guest: ping $wan                                        "                                                                    -ForegroundColor (IBAnd $code $flag "Green" "Red")
                    $flag=$flag*2
                }
                foreach($lan in $alllan) {
                    if ($lan -eq $LANgatewayIP) {
                        Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq "LAN"} | findstr "InterfaceAlias     : LAN"
                        $code=$code + (IIf $? $flag 0)
                        Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress $lan | Where {`$_.InterfaceAlias -eq LAN}   " -ForegroundColor (IBAnd $code $flag "Green" "Red")
                        $flag=$flag*2
                    } else {
                        Find-NetRoute -RemoteIPAddress $lan | Where {$_.InterfaceAlias -eq "WAN"} | findstr "InterfaceAlias     : WAN"
                        $code=$code + (IIf $? $flag 0)
                        Write-Host "[$(IBAnd $code $flag "X" " ")] guest: Find-NetRoute -RemoteIPAddress $lan | Where {`$_.InterfaceAlias -eq WAN}   " -ForegroundColor (IBAnd $code $flag "Green" "Red")
                        $flag=$flag*2
                    }
                }
                foreach($lan in $alllan) {
                    ping -n 1 $lan
                    $code=$code + (IIf $? $flag 0)
                    Write-Host "[$(IBAnd $code $flag "X" " ")] guest: ping $lan                                        "                                                                     -ForegroundColor (IBAnd $code $flag "Green" "Red")
                    $flag=$flag*2
                }

                return $code

            }  2>$null 1>$null
            # Write-Host "rc=$rc"
            #if($rc -eq $null) {$rc=0}
            #$tp=$rc.GetType().Name
            #if($tp -eq "Object[]") { $rc=$rc[-1] }
        }
        # Write-Host $rc

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
    Show-Progress -all $all
    Write-Host "                                                                     "
    write-host "##################################"
    Write-Host "                                                                     "
    Write-Host "                                                                     "
    Write-Host "                                                                     "

    Start-Sleep -Seconds 5
    if ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character)) {
        Write-Host "Exiting now"
        break;
    }
}
# SIG # Begin signature block
# MIIbpwYJKoZIhvcNAQcCoIIbmDCCG5QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUu6cNl0Zo2cfO9duGqFAu/qJo
# qjygghYZMIIDDjCCAfagAwIBAgIQILC/BxlyRYZJ/JpoWdQ86TANBgkqhkiG9w0B
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
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRF2jsiNZJmdpt8RNe4BUYN
# VbDlVDANBgkqhkiG9w0BAQEFAASCAQBbcS9B3kBjfBVhmHck6XpTx7mzycxBprfD
# Qzwui9eJMaspycH34/pcicTFZFzmXjLfAf8N6pMblqCtvM2Hi2bn023W6G1OKIEX
# oaj3Ic5VNRJE/Wv/8Yj03J4PrhTvEB1F9kyvfUrp41vV6e3GBPTfujka3m3b8Sqr
# Hi8SAWbcKEmZKi+5lB4MTDFLl27fTJGN0BilrYN9pLVQhjxBuJtMtPZPnE9/n8ki
# NtkbYpH9VMa8JRfwxXAihOK5E7TilF8P+zYZBlMqVA5fdLuMt+bkFAH3WxOfJGel
# XWxMnRP7vdXe7wE13lM00kvZJxc+bvC1YyDYlewpoh20A2lp4WhCoYIDIDCCAxwG
# CSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJT
# QTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjAN
# BglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTIzMDcwODE5NTQzMFowLwYJKoZIhvcNAQkEMSIEIHkxWN4Hdg6H
# Ht8FlXBu7WsmaT/DTBSSCfxhRJvzGr92MA0GCSqGSIb3DQEBAQUABIICACZszwT2
# tfrbaZYc15jfVoXZOpfCmtx+f4IrMib0G9pp9yQwMdw61fMARxW9rMBVmIAZGnvN
# 4GHgjy9ROV4OnBG2bR8tIrYiU8fYo/sADnX8CUCj5sksc5g7+8O0C4tN6UArbjlJ
# AuwJS7OCX/IUX7NYhg3qVyL9C7NT2qNKCkt2jXOdExnprXpi79kVHWK6tTRNH7/X
# rbJo7hbH1DWsjVBRWvWYGve6NYgFnjMHC7nCLH8Y5iWrit+IPXrQXH6RhAZ7lq+n
# u0plflwfPMynVu/41YcnmwlkYB2ioym2h56Gxtb6CAVn20HF5tfeK8r6edjx1e2d
# hxCn6xLAqm2NEZGwte0me6tSD86XNj5ndHGd2mZG4QW1bT2M9GEkxhIRyknUkNF1
# CNv1zbcELhAJLBRJpkpnjkcU1X+E7jWLvrCKxGIGMEqq+qbwYrWTMYq7g/pzUUjj
# GzH8B27WZZOHUogFk8lu4+hGtsMfyMBGf/Xw3aApIGtOJDHOBHsQaeeyvfmVWEjk
# pWfxt7jKx83hwg64kDtsW/ZVU6IRvLfQHss/rkyTOOa1ZwP4X4mYdT71c7aCuHfG
# dR5bWlwjyAEfp3ThfMCizcZDI9/Nk8+esnFlQ+7qJCJ1mD5k6w2xHxMt+m1sRsFw
# tAta9/dWaI3DSTuSTr8VcR/gzGVeyMq3JP7N
# SIG # End signature block
