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
    Write-Host "trying to connect to $server"

    $session=New-PSSession -VMName $server -credential $logincred
    if( -not $? ) { $session=New-PSSession -VMName $server -credential $localcred }
    while( -not $? ) {
        Write-Host " ...connect to $server failed... $waitmessage ...trying again in 1sec"
        Start-Sleep -Seconds 1;
        $session=New-PSSession -VMName $server -credential $logincred
        if( -not $? ) { $session=New-PSSession -VMName $server -credential $localcred }
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


    Get-VM $Dc1Name 2>$null 1>$null
    Write-Host "[$?] host: Get-VM $Dc1Name"                                                                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

    $domaincred= Create-Credential -Resource $domain -Username "Administrator" -PlaintextPassword $plaintext
    $localcred= Create-Credential -Resource "." -Username "Administrator" -PlaintextPassword $plaintext
    $Dc1Session=Wait-For-Session -server $Dc1Name -logincred $domaincred -localcred $localcred  -waitmessage "."  
    Write-Host "[($($Dc1Session -ne $null))] host: New-PSSession -VMName $Dc1Name -credential (New-Object PSCredential ($u, ConvertTo-SecureString($password)))"                    -ForegroundColor $(iif ($Dc1Session -ne $null) "Green" "Red") 

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

            ping -n 1 8.8.8.8
            Write-Host "[$?] guest: ping 8.8.8.8"  -ForegroundColor $(iif $? "Green" "Red") 

            foreach($site2 in $sites2) {
                $part2=$site2 -split "="
                $othergateway=$part2[1].replace(".0/",".254/")
                $othergateway=$othergateway.substring(0,$othergateway.indexof("/"))
                ping -n 1 $othergateway 2>$null 1>$null
                Write-Host "[$?] guest: ping $othergateway"  -ForegroundColor $(iif $? "Green" "Red") 
            }

            Resolve-DNSName  $DC1Name2
            Write-Host "[$?] guest: Resolve-DNSName  $DC1Name2"                                                                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $DC2Name2
            Write-Host "[$?] guest: Resolve-DNSName  $DC2Name2, for joined login auto dns register"                                                                                                 -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2, for list of domain controllers"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 | findstr $Dc1IP2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc1IP2"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Resolve-DNSName  $FullyQualifiedDomainName2 | findstr $Dc2IP2
            Write-Host "[$?] guest: Resolve-DNSName $FullyQualifiedDomainName2 | findstr $Dc2IP2"                                                                                     -ForegroundColor $(iif $? "Green" "Red") 

            Get-DhcpServerv4Scope $lannetwork2
            Write-Host "[$?] guest: Get-DhcpServerv4Scope $lannetwork2"                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

            Get-DhcpServerv4Failover -ComputerName "$Dc1Name2" -Name "$lannetwork2-failover"
            Write-Host "[$?] guest: Get-DhcpServerv4Failover -ComputerName '$Dc1Name2' -Name '$lannetwork2'"                                                                                         -ForegroundColor $(iif $? "Green" "Red") 

            foreach($site2 in $sites2) {
                $part2=$site2 -split "="
                #$othergateway=$part2[1].replace(".0/",".254/")
                #$othergateway=$othergateway.substring(0,$othergateway.indexof("/"))
                $sitename=$part2[0]
                $sitesubnet=$part2[1]

                Get-ADReplicationSite -identity $sitename
                Write-Host "[$?] guest: Get-ADReplicationSite -identity $sitename"   -ForegroundColor $(iif $? "Green" "Red") 

                Get-ADReplicationSubnet -Identity $sitesubnet
                Write-Host "[$?] guest: Get-ADReplicationSubnet -Identity $sitesubnet"   -ForegroundColor $(iif $? "Green" "Red") 

                get-ADReplicationSiteLink -filter "Name -eq 'default-to-$sitename'" | findstr "default-to-$sitename"
                Write-Host "[$?] guest: get-ADReplicationSiteLink -filter Name -eq 'default-to-$sitename' | findstr Default-to-$sitename"   -ForegroundColor $(iif $? "Green" "Red") 
            }
        }
    }




    Get-VM $Dc2Name 2>$null 1>$null
    Write-Host "[$?] host: Get-VM $Dc2Name"     -ForegroundColor $(iif $? "Green" "Red") 

    $Dc2Session=Wait-For-Session -server $Dc2Name -logincred $domaincred -localcred $localcred -waitmessage ""
    Write-Host "[($($Dc2Session -ne $null))] host: New-PSSession -VMName $Dc2Name -credential (New-Object PSCredential ($u, ConvertTo-SecureString($password)))"                    -ForegroundColor $(iif ($Dc2Session -ne $null) "Green" "Red") 

    if($Dc2Session -ne $null) {
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

    foreach($s in $sites) {
        $part=$s -split "="
        $othergateway=$part[1].replace(".0/",".254/")
        $othergateway=$othergateway.substring(0,$othergateway.indexof("/"))
        ping -n 1 $othergateway 2>$null 1>$null
        Write-Host "[$?] host: ping $othergateway"  -ForegroundColor $(iif $? "Green" "Red") 
    }


    ipconfig /release "vEthernet ($SwitchName)"  2>$null 1>$null
    # above line is necessary bc the default gateway received by DHCP, on interface, confuses Windows routing for 0.0.0.0/0
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



$Time = [System.Diagnostics.Stopwatch]::StartNew()
while ($true) {
    cls
    $CurrentTime = $Time.Elapsed
    write-host $([string]::Format("`rTime: {0:d2}:{1:d2}:{2:d2}",
                                  $CurrentTime.hours,
                                  $CurrentTime.minutes,
                                  $CurrentTime.seconds)) -nonewline
    write-host ""
    Test-Installation -FullyQualifiedDomainName $domainca
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
# SIG # Begin signature block
# MIIbpwYJKoZIhvcNAQcCoIIbmDCCG5QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUS+tL53Xc7Tf5clEPqWADAAhp
# TpigghYZMIIDDjCCAfagAwIBAgIQILC/BxlyRYZJ/JpoWdQ86TANBgkqhkiG9w0B
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
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSfa4+j2TTSQXImSmqV5FWN
# 4msmgjANBgkqhkiG9w0BAQEFAASCAQCkEaTRyq5XSeHzdqNTrWrGw+iuzO6SLf6Z
# aczSXYfxxdKwi810Pccbd04lwg9JHRzQvOXOnuQcnwrMzorfPLeFCEh6cSUK7Qgf
# /jMliSrKSRUDMakA1aUMIE1Yha8ANpIxw6fr3TTZc5RMmH+gRhyQiFoAKv3/UAFp
# jrAMM7FgM6mv36l1H6FgjzVMIEYjvziR/F/gyCW40Ls+b5Xdt6XdSI4YIGpzLNJC
# nzjI3t8vCtQo9MQap7GNS8s6PaEXqE3TZCo35SDHO9Yy2v9ZSXArC85jl/NiMLM+
# N3w2pyv3ryCnx3nk/X04oS0vJDniXrCgEsMnbPmRYoypIE5ngFAxoYIDIDCCAxwG
# CSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJT
# QTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjAN
# BglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTIzMDcwNzAzMzkxMlowLwYJKoZIhvcNAQkEMSIEIHkCE7LzbAbC
# r7QK3XV5yM4yGJzqs9fo6OCc19XgcwysMA0GCSqGSIb3DQEBAQUABIICAJtOvUpt
# eVVTF1kRxnRFXzaRFdpX6isvGs20RPOoFc/ZMyEGavV2+eGq+5T1kf9bANAllRU4
# AZXSqCKhXntRt51ZbAmf8I8uxLCgS5TJUzmAd0GG/KPafvHpGqjg4A2Y1isGy2Gw
# bNY6s6NUr34uMNe/7uHSz07sK6Sc3amI+k0W678TPBzCbLsBa4JoBMS8QMr/idj3
# Leb1Cg5yyXSST0zGCUw2EzWTBIbilKNxl32hmFIu7h4vbC9eEXXezuuj3PnrcG9D
# LpPg7FRz/UeBooQn3TYse9z/sm5ZM4rW/9Hr/srhMXgjoRwCvz7hhgheJmhBDlBb
# iVm4JDUuAVaWrCne1acZvt+ySLcTi6XpYyzJIojzyM7Y71CW2jCML8/fOemcpdoY
# qDLcO+6PEaG+rvgeivHaYjeHFBc1m9+T2+VoMqU47bHPcoY6meGrwSm8PRSEFdC8
# j2eoPGmplVo0Tmy2fOkFDaTIMnmCiH+liCrElazpJvt9V6BTIkfAZgTMKl5XvJVJ
# 1gUd8C7PiX6H5X8sc/SJw/2i5m2B/bmJIsWmJMtHgeI5jzAJxN0jaxLd7irUOcEJ
# F8+QpiotxMCX6rSFsV2vNkRcieCWS+ky2rwC5so4udPAaR9jLIYGx2MUx3YXXDD1
# bo03oHHq0yAnpjq0TKyl+OP3X1dLOuV2BvVf
# SIG # End signature block
