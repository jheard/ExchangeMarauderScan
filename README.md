# ExchangeMarauderScan
# Summary

The script utilizes IOC's from Microsoft Security [blog](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/) to search for potential signs of exchange server compromise.

# Directions
1. R-Click on the Start button.
2. Select Windows Powershell (Admin)
3. mkdir C:\ScriptFiles
4. cd c:\ScriptFiles
5. wget https://raw.githubusercontent.com/jheard/ExchangeMarauderScan/main/exchange_marauder_detect.ps1 -o exchange_marauder_detect.ps1
6. .\exchange_marauder_detect.ps1

**If the script returns results, there will be a zip file in C:\ScriptFiles\output\ directory.**

If no results were found, the output directory will not exist.
