#Utilized IOCs and PS snippets from MSSC Blog on Hafnium targeting Exchange Servers
#-outputpath is where to create a directory to store any files 
#-days is number of days back to look for newly created files for webshells or exfiltration
param([System.IO.FileInfo]$outputpath, [ValidatePattern("[0-9]*")]$days=7)

# IOCs from https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
$webShell_hashes = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e", "2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1", "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5", "511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1", "4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea", "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d", "1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"
$webShell_names = "web.aspx", "help.aspx", "document.aspx", "errorEE.aspx", "errorEEE.aspx", "errorEW.aspx", "errorFF.aspx", "healthcheck.aspx", "aspnet_www.aspx", "aspnet_client.aspx", "xx.aspx", "shell.aspx", "aspnet_iisstart.aspx", "one.aspx"
$webShell_paths = "C:\inetpub\wwwroot\aspnet_client\", "C:\inetpub\wwwroot\aspnet_client\system_web\", "%PROGRAMFILES%\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\", "C:\Exchange\FrontEnd\HttpProxy\owa\auth\"

# Files and path for possible indications of exfiltration
$exfil_exts = "'*.zip','*.rar','*.7z'"
$exfil_path = "C:\ProgramData\*"

If ($outputpath -eq $null) {
    $outputpath = '.\output'
    $cleanup = $true
}

If (-not (Test-Path $outputpath)) {
    New-Item -Path $outputpath -ItemType "directory" | Out-Null
}


$time_delay = [DateTime]::Now.AddDays(-$days)
write "[-] Checking for any newly created .aspx files"
# Create a list of all .aspx files created in the last week
$aspx = $webShell_paths | %{
    If ( Test-Path -Path $_ ) {
        Get-ChildItem -Path $_ -Filter '*.aspx' | Where-Object { $_.creationTime -ge $time_delay  }
    }
}

If ($aspx.Count -gt 0) {
    write "[!] Recently created .aspx files found, saving for investigation"
    $aspx | Export-Csv -Path $outputpath\new_aspx.csv
}

write "[-] Checking for indicators of potential exfiltration"
# Create a list of all potential exfiltration files
$potential_exfil = Get-ChildItem -Path $exfil_path -Filter $exfil_exts | Where-Object { $_.creationTime -ge $time_delay }

If ($potential_exfil.Count -gt 0) {
    write "[!] Signs of potential exfiltration found, saving for investigation"
    $potential_exfil | Export-Csv -Path $outputpath\potential_exfil.csv
}
write "[-] Checking for CVE-2021-26855 exploitation"
# CVE-2021-26855 exploitation can be detected via the following Exchange HttpProxy logs
If ( Test-Path -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" ) {
    $logs = Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
    if ($logs.Count -gt 0) {
        write "[!] Savings signs of CVE-2021-26855 exploitation"
        $logs | Export-csv -Path $outputpath\cve-2021-26855.csv 
    }
}
write "[-] Checking for CVE-2021-26858 exploitation"
# CVE-2021-26858 exploitation can be detected via the Exchange log files
If ( Test-Path -Path "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log" ) {
    $logs_26858 = findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"
    if ($logs_26858.Length -gt 0) {
        write "[!] Savings signs of CVE-2021-26858 exploitation"
        $logs_26858 > $outputpath\cve-2021-26858.txt
    }
}
write "[-] Checking for CVE-2021-26857 exploitation"
# CVE-2021-26857 exploitation can be detected via the Windows Application event logs
$events = Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*System.InvalidCastException*" }
If ($events.Count -gt 0) {
    write "[!] Savings signs of CVE-2021-26857 exploitation"
    $events  | Export-Csv -Path $outputpath\cve-2021-26857.csv
}

write "[-] Checking for CVE-2021-27065 exploitation"
# CVE-2021-27065 exploitation can be detected via the following Exchange log files
If ( Test-Path -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log") {
    $logs_27065 = Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'
    If ($logs_27065.Length -gt 0) {
        write "[!] Savings signs of CVE-2021-27065 exploitation"
        $logs_27065 > $outputpath\cve-2021-27065.txt
    }
}

#Save all the outputs into a zip and clean up

$zipname = "${env:COMPUTERNAME}.zip"

$compress = @{
CompressionLevel = "Fastest"
DestinationPath = "$outputpath\$zipname"
}
$output = Get-ChildItem -Path $outputpath | Where-Object { $_.Length -gt 0 }

If ($output.Count -gt 0) {
    write "[!] Results found, files and logs have been zipped for further analysis"
    $output | Compress-Archive -Force @compress
    If ($aspx.Count -gt 0) {
        $aspx | Compress-Archive -Update @compress
    }

    If ($potential_exfil.Count -gt 0) {
        $potential_exfil | Compress-Archive -Update @compress
    }
} else {
    write "[*] No results found."
    If ($cleanup) { Remove-Item $outputpath -Recurse }
}