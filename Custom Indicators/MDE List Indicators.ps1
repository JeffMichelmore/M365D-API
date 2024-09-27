# PLEASE NOTE THAT I TAKE NO RESPONSIBILITY FOR THE RESULTS THIS SCRIPT MIGHT YIELD
# PLEASE USE AT YOUR DESCRETION, TEST, AND ENSURE IT FITS YOUR NEEDS

# Author: Jeff Michelmore
# Connect: https://www.linkedin.com/in/jeffrey-michelmore/
# Blog: https://securityoccupied.com/


# For simplicity, this script authenticates using Tenant ID, App ID, and AppSecret in plaintext below. Note there are safer ways to access the MDE APIs that don't involve keeping these values in plaintext.
# You can read about other authentication methods in Microsoft's public documentation. https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro?view=o365-worldwide


[String] $tenantId = '000000000000000000000' ### Paste your tenant ID between the single quotes
[string] $appId = '000000000000000000000' ### Paste your Application ID between the single quotes
[string] $appSecret = '000000000000000000000' ### Paste your Application key between the single quotes

# Creating token for MDE API
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com' 
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token


# Creating the List IoCs Request
$webResponse = $null
Write-Host "List IoCs to CSV" -ForegroundColor Yellow
    $url = "https://api.securitycenter.microsoft.com/api/indicators"
$headers = @{
Authorization = "Bearer $token"
}
$webResponse = Invoke-WebRequest -Method Get -Uri $url -Headers $headers
$IocContent = $webResponse.Content | ConvertFrom-Json
        
$IocOutputFile = Join-Path $PSScriptRoot "\Indicators.csv"

# Check if Indicators.csv exists and increment file name if it does.
$counter = 0 
while (Test-Path $IocOutputFile) {
    $counter++
    $IocOutputFile = Join-Path $PSScriptRoot "Indicators($counter).csv"
}

$IocContent.Value | ConvertTo-Csv -NoTypeInformation | Set-Content $IocOutputFile -Force 
if ($?) {
    Write-Host "Successfully created $IocOutputFile" -ForegroundColor Yellow
    Invoke-Item -Path $IocOutputFile
} else {
    Write-Host "Failed to create $IocOutputFile" -ForegroundColor Red
}