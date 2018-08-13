###SET YOUR ENVIRONMENT VARIABLES HERE###
$global:smtpServer = "smtp.yourorg.com"
$global:fromAddress = "threat@yourorg.com"
$global:irAddress = "infosec@yourorg.com"
$global:proxyPath = "\\server01\folder\blockList.xml"


$compressedData = [System.Convert]::FromBase64String("H4sIAAAAAAAEAM1XbYvcNhD+frD/QWQP7IWVxDXJl6VX8qlQODgI5aBEqZxe0lJYYnrdC4XMj++8yZZkebmmlFTelS1pnnlmRtJY3lxsLi6P42+juTavnm2wZdaKxxJCWJfwKrEu4n2MeItxXcaC6UcTzLgzYFeE4D1gfR8DPf8Cq6
pC34cYo9/tvF2xCIfXHQqG4ca3hwHI4TMRIzThV+Dm8fHxDBqyelF8MPEcNY7vqGqOGXNnWlGLUhAWUMgHbVdY/DXAs5fB34WsVdhE8Lvl3OchgjF3eYIj+I6jMS7gRYChjFiYRALR++12Wxtfzk9JrwpIxI/ewJbw35UKqvmFesqC
4vH6tqWgXh9iQR55CafW220x74vVJfzpXwtC6b+v7old/6ES9Lg2Yhb/CT5TKT0aj3dICmaTvfl05a5emB8/nB7eFZyTAt02m4tnryghXZ4+/HXS9CSBMRKYvDaNEbN4JgUeewIZaPq4YzNBA12OGE1V5JBoxgoV4DzGnTcdygJBUI
CeGZ+NaC8KDAZEc4eymwuCRA9GLvSVOPkqR9LVswWG8giwC7IOgA2nC0fk2dQjfEeGPdfcQQoksJfv3n8qEv+ZbJKV1Wz7H4rFJ4m9eaK2sBRz1lpXmwYNmQWyc9F1yUwtAGXiZJmGacGGApch04q03rR8CgMjO9vx34TOZy3Ede13
Q2JMLh4KH5GtHUClW6B6C3aNKieLziLIOg0IrBIJVXSO3RCiwToEtmkiidrMq8wjJLEErd/vUZSXfs0436WkhsQVNtjBDW5qhAqLjL08uc51Cx+RbYYn6gQmWkjQhrPENqGVWrG0SAhLyOYcMlcCC7FAxdcdA9sRFibFcoORTGkc8N
JvT406KFBqEJAJkS7Z3VzbGldCRmwgDiUjGYkZ7MzaTpM5HHCn2gPXUzm4tbWtdOgMLhfAOrtgdW0L2YE2LGCJ2ZWnl5gXoep4jwMtXcem4T1PcLg8ubuTCpnQdw4YlEpZz4yDQRxVh3ULyQ5BRVhyB4SQh/T1B8ou5N3MVPoB8g4d
ZG8NaqhL8iTpnHqgnNzgSE6bc1ArJ1cL47JSwp5aGCWJ4x+B3CBJim6YJ4YBV2FqcGuI2EMzh65Tv6dsgmT0jOuF+pzExmSqSIvBLxB+FFHOLek1nB1w9DVcnbrrEufbdOiJ2UC76OmHF44cZ1ItbbzzkchEOXlEqvWYxE+zoMK0QZ
rpoBI9Y+iFJLU3lo9HnlTyUUgPNdTuSKqPlp+SZMKJKA6w1XR60RPMdKUTTYjS2KcDD/1JwPP4LDjB9tL/xCPKlxSZR57e+/Hjn6eHx/vT7+PH6hubPs/2do8bYK9d9Pns5UyHMfoJe/cYVPp4CeAHSqK0Wf7A8ElU+FX1uTf9Dr/2
PvfX19cnKN1CdxGIUJINySq062H89XiVL7rXt9/fHKoqz2Q/S7Y5coOZ37wljTe3N8g7r9eQhNL3L5a3maIf6D+3U4L2WczItm9y22q7qGrYdlPbdrw9Lmy7+fe2Pc9tWwQNq68Ytxe5bcsZfX37FeP2Mrftf7DcyLC/AeGnNp4BEw
AA")

$memStream = New-Object System.IO.MemoryStream
$memStream.Write($compressedData, 0, $compressedData.Length)
$memStream.Seek(0,0) | Out-Null

$compressedDataStream = New-Object System.IO.Compression.GZipStream($memStream, [System.IO.Compression.CompressionMode]::Decompress)
$memStreamReader = New-Object System.IO.StreamReader($compressedDataStream)
$uncompressedData = $memStreamReader.readtoend()

Invoke-Expression $uncompressedData

function Show-Menu
{
     param (
           [string]$Title = 'Phish Phinder'
     )
     cls
     Clear-Vars
     Write-Host $logo
     Write-Host $text
     Write-Host ""
     Write-Host "<><><><><><><><><><><> Make a Selection <><><><><><><><><><><>" 
     Write-Host ""

     Write-Host "1: Press '1' to go phishin!"
     Write-Host ""
     Write-Host "2: Press '2' for Commercial Phisherman Mode (Expert Mode)"
     Write-Host ""
     Write-Host "3: Press '3' for a ROFL copter."
     Write-Host ""
     Write-Host "Q: Press 'Q' to quit."
     Write-Host ""
     Write-Host ""
}

function Advanced-Menu
{
     param (
           [string]$Title = 'Commercial Phisherman'
     )
     cls
     Write-Host $advlogo
     Write-Host $advtext
     Write-Host "<><><><><><><><><> You must be pretty good at this here phishin thang! <><><><><><><><><>"
     Write-Host ""
     Write-Host "1: Press '1' to search O365 only"
     Write-Host ""
     Write-Host "2: Press '2' to search Exchange 2007"
     Write-Host ""
     Write-Host "3: Press '3' to block a URL in the Web Proxy"
     Write-Host ""
     Write-Host "4: Press '4' to send a Threat Alert"
     Write-Host ""
     Write-Host "R: Press 'R' to return to the previous menu."
     Write-Host ""
     Write-Host ""
}

function Purge-Parameters
{
     param (
           [string]$Title = 'Purge Parameters'
     )
     cls
    Write-Host ""
    Write-Host "Please enter a name for this search:" -ForegroundColor White `n
    $global:searchname = Read-Host "(e.g. PhishingSearch20)"
    Write-Host ""
    Write-Host "Please enter the earliest date to search:" -ForegroundColor White `n
    $global:earliest = Read-Host "(e.g. 2018-01-07)"
    Write-Host ""
    Write-Host "Please enter the latest date to search:" -ForegroundColor White `n
    $global:latest = Read-Host "(e.g. 2018-01-10)"
    Write-Host ""
    Write-Host "Please enter the phisher's e-mail address (leave blank for none):" -ForegroundColor White `n
    $global:phisher = Read-Host "(e.g. malicious@phish.com)"
    Write-Host ""
    Write-Host "Please enter the subject line of the phishing message (leave blank for none):" -ForegroundColor White `n
    $global:subject = Read-Host "(e.g. Open now!)"
    Write-Host ""
    Write-Host "Please enter the root domain of the phishing site:" -ForegroundColor White `n
    $global:phishdomain = Read-Host "(e.g. virus.com)"
}

function Purge-Online
{
     param (
           [string]$Title = 'Purge Online'
     )
     cls
            Write-Host "You will be prompted shortly for your administrative credentials"
            Sleep 3
            Clear
            # Get login credentials 
            $UserCredential = Get-Credential 
            $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid -Credential $UserCredential -Authentication Basic -AllowRedirection 
            Import-PSSession $Session -AllowClobber -DisableNameChecking 
            $Host.UI.RawUI.WindowTitle = $UserCredential.UserName + " (Office 365 Security & Compliance Center)" 
            $State = Get-PSSession | select -ExpandProperty State
            $SessID = Get-PSSession | select -ExpandProperty Id

            #Check if the Powershell session is actually open
            If ($State -eq "Opened")
                {
                #Kick-off the search with the parameters above. Exclusion rules are in place to prevent
                New-ComplianceSearch -Name $global:searchname -ExchangeLocation All
                If ($global:phisher -eq "")
                    {
                    Set-ComplianceSearch -Identity "$global:searchname" -ExchangeLocation All -ContentMatchQuery "(c:c)(date=$global:earliest..$global:latest)(subject:`"$global:subject`")"
                    }
                ElseIf ($global:subject -eq "")
                    {
                    Set-ComplianceSearch -Identity "$global:searchname" -ExchangeLocation All -ContentMatchQuery "(c:c)(date=$global:earliest..$global:latest)(from:`"$global:phisher`")"
                    }
                Else
                    {
                    Set-ComplianceSearch -Identity "$global:searchname" -ExchangeLocation All -ContentMatchQuery "(c:c)(date=$global:earliest..$global:latest)(from:`"$global:phisher`")(subject:`"$global:subject`")"
                    }
                Start-ComplianceSearch -Identity "$global:searchname"
                $SearchStatus=Get-ComplianceSearch -Identity "$global:searchname" | select -ExpandProperty Status
                Clear
                    
                While($SearchStatus -ne "Completed")
                    {
                    $SearchStatus=Get-ComplianceSearch -Identity "$global:searchname" | select -ExpandProperty Status
                    Sleep 5
                    Write-Host "Search is '$SearchStatus'"
                    }

                If ($SearchStatus -eq "Completed")
                    {
                    Sleep 2
                    Write-Host ""
                    $global:NumOfResults=Get-ComplianceSearch -Identity "$global:searchname" | select -ExpandProperty Items
                    Sleep 2
                    Write-Host "Number of hits: $global:NumOfResults"
                    Sleep 2
                    Write-Host ""
                    Sleep 2
                    
                    If ($global:NumOfResults -ge 1)
                    {
                        #See the actual results
                        $SearchPreview=New-ComplianceSearchAction -SearchName "$global:searchname" -Preview | Select Results | Format-List | Out-String
                        #While loop which waits until the results are available
                        While($SearchPreview -notlike '*Location*')
                        {
                            $SearchPreview=New-ComplianceSearchAction -SearchName "$global:searchname" -Preview | Select Results | Format-List | Out-String
                            Sleep 5
                            Write-Host "Retrieving results..."
                        }
                        If($SearchPreview -like '*Location*')
                        {
                            Write-Host ""
                            Write-Host "Below are the results of the search you are attempting to purge. Please confirm that the search has only captured phishing results before continuing:" -ForegroundColor White `n
                            Write-Host ""
                            Sleep 2
                            echo $SearchPreview
                            #After previewing the results, we extract the e-mail addresses from the crappy string that O365 uses to drop into our auto-mailer later using a global variable
                            $TargetAdd=[regex]::matches($SearchPreview, 'Location:\s([^;]+)').Value
                            $global:AutoMail=$TargetAdd -replace "Location: ", ""
                            $SubjectRaw=[regex]::matches($SearchPreview, 'Subject:\s([^;]+)') | Select-Object -first 1
                            $global:MailSubject=$SubjectRaw -replace "Subject: ", ""
                            Write-Host "Targeted users are as follows:" -ForegroundColor Yellow
                            echo $global:AutoMail
                            Write-Host ""
                            Write-host "Do the results appear consistent with your recent search? (Clicking 'Yes' will purge the results) `n" -ForegroundColor Yellow
                            $global:PurgeMsgs = Read-Host "(Y/N)"
                            Write-Host ""
                                If (($global:PurgeMsgs -eq "yes") -or ($global:PurgeMsgs -eq "Yes") -or ($global:PurgeMsgs -eq "Y") -or ($global:PurgeMsgs -eq "y"))
                                    {
                                    Sleep 1
                                    Write-host ""
                                    Write-host "Purging commencing: This action cannot be undone!`n" -ForegroundColor Yellow -BackgroundColor DarkRed
                                    Write-host ""
                                    Sleep 5
                                    New-ComplianceSearchAction -SearchName "$global:searchname" -Purge -PurgeType SoftDelete -Confirm:$false
                                    ##Adding loop to wait for the purge action to complete before continuing
                                    $purgeName=$global:searchname + "_purge"
                                    $purgeStatus=Get-ComplianceSearchAction -Identity "$purgeName" | select -ExpandProperty Status
                                    While($purgeStatus -ne "Completed")
                                        {
                                        $purgeStatus=Get-ComplianceSearchAction -Identity "$purgeName" | select -ExpandProperty Status
                                        Sleep 5
                                        Write-Host "Purge is '$purgeStatus'"
                                        }
                                    Write-Host ""
                                    Write-host "Cleaning up and continuing..."
                                    Write-Host ""
                                    Sleep 3
                                    Remove-ComplianceSearch "$global:searchname" -Confirm:$false
                                    Get-PSSession | Remove-PSSession
                                    Sleep 3
                                    }
                                ElseIf (($global:PurgeMsgs -eq "no") -or ($global:PurgeMsgs -eq "No") -or ($global:PurgeMsgs -eq "N") -or ($global:PurgeMsgs -eq "n"))
                                    {
                                    Write-host "Please re-run your search and try again. `n"
                                    Write-Host ""
                                    Write-host "Cleaning up and exiting to the main menu..."
                                    Write-Host ""
                                    Remove-ComplianceSearch "$global:searchname" -Confirm:$false
                                    Sleep 5
                                    Get-PSSession | Remove-PSSession
                                    Write-Host ""
                                    }
                                 Else 
                                    {
                                    Sleep 3
                                    Write-Host ""
                                    Remove-ComplianceSearch "$global:searchname" -Confirm:$false 
                                    Sleep 3
                                    Get-PSSession | Remove-PSSession
                                    Write-Host ""
                                    Write-host "Invalid option selected. Exiting..."
                                    Sleep 5
                                    Write-Host ""
                                    }
                      }
                    Else
                        {
                        Sleep 3
                        Write-Host ""
                        Remove-ComplianceSearch "$global:searchname" -Confirm:$false
                        Sleep 3
                        Get-PSSession | Remove-PSSession
                        Write-Host ""
                        Write-Host "Your search returned no results."
                        Write-Host ""
                        Sleep 2
                        }
                    }
                Else
                {
                Sleep 3
                Write-Host ""
                Remove-ComplianceSearch "$global:searchname" -Confirm:$false
                Sleep 3
                Get-PSSession | Remove-PSSession
                Write-Host ""
                Write-Host "Your search returned no results."
                Write-Host ""
                Sleep 2
                }
                }
            }
}

function Purge-2007
{
     param (
           [string]$Title = 'Purge 2007'
     )
     cls
            Write-Host "Beginning on-prem search..."
            Write-Host ""
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
            $Servers = Get-ExchangeServer;  
            $RESULTS = $Servers | where {$_.isHubTransportServer -eq $true -or $_.isMailboxServer -eq $true} | Get-MessageTrackingLog -Sender $global:phisher -MessageSubject $global:subject -EventID "DELIVER" -Start $global:earliest -End $global:latest | Format-Table
            $ResString = Out-String -InputObject $RESULTS
            If($ResString -like '*com*')
                {
                Write-Host "The following results were returned:"
                Write-Host ""
                echo $RESULTS
                $TargetArray=$Servers | where {$_.isHubTransportServer -eq $true -or $_.isMailboxServer -eq $true} | Get-MessageTrackingLog -Sender $global:phisher -MessageSubject $global:subject -EventID "DELIVER" -Start $global:earliest -End $global:latest
                $TargetString=$TargetArray | select -ExpandProperty Recipients | Out-String
                $global:MailSubject=$TargetArray | select -ExpandProperty MessageSubject | Out-String
                Write-Host ""
                Write-Host "Please verify the results appear consistent with the phishing campaign and continue..."
                Write-Host ""
                Pause
                Write-Host ""
                $global:AutoMail += "`n"
                Foreach ($Target in $TargetString)
                {
                    $global:AutoMail += $Target
                }
                Foreach ($Entry in $TargetArray)
                {
                    $global:OnPremCount++
                }
                cls
                Write-Host ""
                }
            Else
                {
                $global:OnPremCount="0"
                Write-Host "No results were returned..." -ForegroundColor Yellow
                Write-Host ""
                Pause
                }

}

function Threat-Alert
{
     param (
           [string]$Title = 'Threat Alert'
     )
    Sleep 1
    $targetnotify = ($global:AutoMail -split '[\r\n,; ]'|? {$_})
    $targetDeduped=$targetnotify | select -Unique
    $global:phisherScrubbed=$global:phisher.Replace("@", "[@]")
    Write-Host ""
    Write-Host "Sending Threat Alert to the following users:"
    Write-Host ""
    echo $targetDeduped
    Sleep 5
    $subject = "THREAT ALERT: Your e-mail has been targeted by a phishing campaign"
    $body = "The Information Security Team has been alerted that your e-mail address has been targeted by a phishing campaign. Phishing is a term used to describe a malicious campaign perpetrated by cyber criminals and other threat actors in an effort to steal sensitive personal data. We need your assistance to be sure that this campaign is not successful.<br><br>"
    $body += "You may have noticed an e-mail in your inbox with the subject line <b><i>$global:MailSubject</i></b> with a sender address of <b><i>$global:phisherScrubbed</i></b> between <b><i>$global:earliest</i></b> and <b><i>$global:latest</i></b>. Although the source may appear to be legitimate, please be advised that it is in fact spoofed. This message has been deleted from your inbox to avoid the risk of a malware infection and/or compromised credentials.<br><br>"
    $body += "<b><font color=red>IMPORTANT NOTE:</b></font> If you accidentally clicked a link in the e-mail you received, opened an attachment contained in the e-mail, or have any other reason to believe that your machine or credentials may have been compromised by this phishing attempt, <b><i>please stop what you are doing and notify us immediately</b></i> so that we can take action to determine if your account was compromised.<br><br>"
    $body += "Our team is analyzing the message to determine if any further action is necessary. Should you have any questions or concerns, please let us know.<br><br><br>"
    $body += "Thank you,<br><br>"
    $body += "<b>Information Security Threat Response</b><br>"
    Sleep 1
	ForEach($to in $targetDeduped) {
    send-MailMessage -SmtpServer $gloabl:smtpServer -To $to -From $global:fromAddress -Subject $subject -Body $body -BodyAsHtml -Priority high
	sleep 1
	}
    Sleep 1
}

function Inv-Summary
{
     param (
           [string]$Title = 'Investigation Summary'
     )  
    
    Sleep 1
    $timestamp = Get-Date
    Write-Host ""
    Write-Host "Compiling investigative report..."
    Write-Host ""
    Sleep 5
    $subject = "PhishPhinder Investigative Summary for `"$global:searchname`" on $timestamp"
    $body = "PhishPhinder investigative report generated on <b><font color=blue>`"$timestamp`"</b></font><br><br>"
    $body += "Message subject: <b><font color=blue>`"$global:MailSubject`"</b></font><br><br>"
    $body += "Number of hits on O365: <b><font color=blue>`"$global:NumOfResults`"</b></font><br><br>"
    $body += "Number of hits in Exchange 2007: <b><font color=blue>`"$global:OnPremCount`"</b></font><br><br>"
    $body += "Sender address: <b><font color=blue>`"$global:phisherScrubbed`"</b></font> <br><br>"
    $body += "Time period searched: <b><font color=blue>`"$global:earliest`"</b></font> to <b><font color=blue>`"$global:latest`"</b></font> <br><br>"
    $body += "Targeted users:<font color=blue>`"$global:AutoMail`"</font><br><br>"
    $body += "The URL <b><font color=blue>`"$global:phishdomain`"</b></font> was identified from the campaign and the result of the Ironport block attempt was as follows: <b><font color=blue>`"$global:message`"</b></font><br><br><br>"
    $body += "----------------------------------------------------------------------END OF REPORT----------------------------------------------------------------------<br><br><br>"
    Sleep 1
    send-MailMessage -SmtpServer $global:smtpServer -To $global:irAddress -From $global:fromAddress -Subject $subject -Body $body -BodyAsHtml -Priority high
    Sleep 1
    Clear-Variable AutoMail -Scope Global
}

function blockDomain {
#This function requires 1 parameter; a root level domain to be blocked. For example:
#blockDomain -domain malware.com
#The function will check the XML file referenced in $path, and if the domain supplied is not already in the XML file
#will add it, and the wildcard domain *.malware.com, to the XML file.
#The function will return a string message indicating a succesful update of the XML file or an error code.

	Param(
	   [Parameter(Mandatory=$true)]
	   [string]$domain
	) 

    Write-Host ""
    Write-Host "Blocking domain `"$global:phishdomain`""
    Write-Host ""
    Sleep 2
	$global:message = 'Generic error'
	
	if ($domain -match '^[a-zA-Z0-9][a-zA-Z0-9\-]+\.+[a-zA-Z0-9\-\.]+[a-zA-Z0-9]+$')
	{
		if (Test-path $global:proxyPath)
		{

			$rootDomainToAdd = $domain
			$dateTime = Get-Date -Format g
			$XMLrootDomainToAdd = "<address>$rootDomainToAdd</address>"
			$XMLwildcardDomainToAdd = "<address>*.$rootDomainToAdd</address>"
			$regex = ‘<address>([^<]+)</address>’
			$XMLexistingDomains = select-string -Path $path -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }

			if ($XMLexistingDomains.Contains($XMLrootDomainToAdd))
			{
				$global:message = "Domain already in list"
			} 
			Else 
			{
				Set-Content -Path $path -Value "<?xml version=`"1.0`" encoding=`"utf-8`"?>`r`n<products updated=`"$dateTime`">`r`n<product name=`"PhishFinder`">`r`n<addresslist type=`"URL`">"
				Add-Content -Path $path -Value $XMLexistingDomains
				Add-Content -path $path -Value $XMLrootDomainToAdd
				Add-Content -path $path -Value $XMLwildcardDomainToAdd
				Add-Content -Path $path -Value "</addresslist>`r`n</product>`r`n</products>"
				$global:message = "`"$rootDomainToAdd`" and `"*.$rootDomainToAdd`" added to block list"
			}
		}
		else
		{
			$global:message = "File not writable"
		}
	}
	else
	{
		$global:message = "Supplied domain not valid"
	}

echo $global:message
Sleep 3
}

function Clear-Vars
{
     param (
           [string]$Title = 'ClearVars'
     )

        Clear-Variable searchname -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable earliest -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable latest -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable phisher -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable subject -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable phishdomain -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable NumOfResults -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable OnPremCount -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable AutoMail -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable message -Scope Global -ErrorAction SilentlyContinue
        Clear-Variable PurgeMsgs -Scope Global -ErrorAction SilentlyContinue
}

Function ROFL-Copter
{
    echo $rofl1
    Start-Sleep -m 100
    cls
    echo $rofl2
    Start-Sleep -m 100
    cls
    echo $rofl3
    Start-Sleep -m 100
    cls
    echo $rofl4
    Start-Sleep -m 100
    cls
    echo $rofl5
    Start-Sleep -m 100
    cls
}

do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
              Purge-Parameters
              blockDomain -domain $global:phishdomain
              Purge-Online
              If (($global:PurgeMsgs -eq "no") -or ($global:PurgeMsgs -eq "No") -or ($global:PurgeMsgs -eq "N") -or ($global:PurgeMsgs -eq "n"))
                {
                Show-Menu
                }
              Else
                {
                  Write-Host ""
                  Purge-2007
                  #T-Diggity awareded 200 internet points for discovering a flaw in the logic here
                  If ($global:NumOfResults -lt 1 -and $global:OnPremCount -lt 1)
                    {
                    cls
                    Write-Host ""
                    Write-Host "No results were returned in either Exchange 2007 or O365..."
                    Write-Host ""
                    Pause
                    Clear-Vars
                    Show-Menu
                    }
                  Else
                    {
                    Threat-Alert
                    Write-Host ""
                    Inv-Summary
                    Clear-Vars
                    cls
                    Write-Host ""
                    Write-Host "All done!"
                    Write-Host ""
                    Sleep 5
                    Show-Menu
                    }
                }

           } '2' {
                cls
                do
                 {
                 C
                 Advanced-Menu
                 $adv_input = Read-Host "Please make a selection"

                 switch ($adv_input)
                 {
                     '1' {
                        Purge-Parameters
                        Purge-Online
                        Advanced-Menu
                   } '2' {
                        cls
                        Purge-Parameters
                        Purge-2007
                        Advanced-Menu
                   } '3' {
                        cls
                        Write-Host "Please enter the root domain you want to block:" -ForegroundColor White `n
                        $global:phishdomain = Read-Host "(e.g. virus.com)"
                        blockDomain -domain $global:phishdomain
                        Write-Host ""
                        Pause
                   } '4' {
                        cls
                        Write-Host "Please enter the users you would like to send this to, separated by commas:" -ForegroundColor White `n
                        [string[]]$global:AutoMail = Read-Host "(e.g. user1@domain.com,user2@domain.com)"
                        Write-Host ""
                        Write-Host "Please enter the subject like of the malicious message:" -ForegroundColor White `n
                        $global:MailSubject = Read-Host "(e.g. Open now!)"
                        Write-Host ""
                        Write-Host "Sending message"
                        Write-Host ""
                        Sleep 2
                        Threat-Alert

                        Write-Host "Message sent"
                        Write-Host ""
                        Sleep 2
                   } 'r' {
                        cls
                        Show-Menu
                   }
                 }
               }
                 until ($adv_input -eq 'r')
        } '3' {
                cls
                ROFL-Copter
        }'rofl'{
                cls
                ROFL-Copter
        }

     }
}
until ($input -eq 'q')