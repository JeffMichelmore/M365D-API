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

# Get CSV input from user
Write-Host "Please enter the path to a CSV file containing 1 or more indicators." -ForegroundColor Yellow
Write-Host "See `"Sample Indicators.csv`" for an example."
$inputCsv = Read-Host

# Remove double quotes that may cause errors
$inputCsv = $inputCsv -replace '"',''

# If CSV fails to import, prompt user to try again.
$csvData = Import-Csv -Path $inputCsv 
While (-not $?){
    Write-Host "=============================================================================="
    Write-Host "Importing the CSV failed! Please try again." -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    Write-Host "Ensure the file contains .csv extension and is not in use by another program."
    Write-Host "`nPlease enter the path to a CSV file containing 1 or more indicators." -ForegroundColor Yellow
    Write-Host "See `"Sample Indicators.csv`" for an example."
    Write-Host "=============================================================================="
    $inputCsv = Read-Host
    $inputCsv = $inputCsv -replace '"',''
    $csvData = Import-Csv -Path $inputCsv 
}

# Convert the imported CSV data to JSON
$jsonData = $csvData | ConvertTo-Json

# Check if any properties are null or blank and convert to $null so there is not a bad response.
$jsonObject = $jsonData | ConvertFrom-Json
foreach ($property in $jsonObject.PsObject.Properties) {
    if ($property.Value -eq "" -or $property.Value -eq "null") {
        $jsonObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $null -Force
    }
}
# Check for the presence of 'rbacGroupNames', "mitreTechniques", and 'rbacGroupIds', and wrap their values in brackets if populated, remove them if null or blank
if ($jsonObject.PSObject.Properties.Name -contains "rbacGroupNames") {
    # If rbacGroupNames is null, remove it completely to avoid bad response
    if ($null -eq $jsonObject.rbacGroupNames){
        $jsonObject.PsObject.Properties.Remove("rbacGroupNames")
    }
    # Check if the value is not already an array
    else{
        $jsonObject.rbacGroupNames = @($jsonObject.rbacGroupNames)
    }
}

if ($jsonObject.PSObject.Properties.Name -contains "rbacGroupIds") {
    # If rbacGroupIds is null, remove it completely to avoid bad response
    if ($null -eq $jsonObject.rbacGroupIds){
        $jsonObject.PsObject.Properties.Remove("rbacGroupIds")
    }
    # Check if the value is not already an array
    else{
        $jsonObject.rbacGroupIds = @($jsonObject.rbacGroupIds)
    }
}

if ($jsonObject.PsObject.Properties.Name -contains "mitreTechniques") {
    # If mitreTechniques is null, remove it completely to avoid bad response
    if ($null -eq $jsonObject.mitreTechniques){
        $jsonObject.PsObject.Properties.Remove("mitreTechniques")
    }
    # Check if the value is not already an array
    else{
        $jsonObject.mitreTechniques = @($jsonObject.mitreTechniques)
    }
}

# Check if JSON is a collection of multiple IoCs
if ($jsonObject -is [System.Collections.IEnumerable]){

    # Declare an array of indicators
    $indicators = @()

    # Remove unwanted properties that are added to arrays
    foreach ($indicator in $jsonObject){
        $indicator.PsObject.Properties.Remove('IsReadOnly')
        $indicator.PsObject.Properties.Remove('IsFixedSize')
        $indicator.PsObject.Properties.Remove('IsSynchronized')

        # Create a new PSCustomObject and add all properties dynamically
        $newIndicator = [PSCustomObject]@{}
        foreach ($property in $indicator.PSObject.Properties) {
            # If any of the properties which are expected to be arrays have value, split them into an array
            if ($property.Name -eq 'rbacGroupNames' -or $property.Name -eq 'rbacGroupIds' -or $property.Name -eq 'mitreTechniques') {
                if ($property.Value){
                    $newIndicator | Add-Member -MemberType NoteProperty -Name $property.Name -Value ($property.Value -split ',')
                }
            } 
            # If property is null or blank, remove quotes
            elseif ($property.Value -eq "" -or $property.Value -eq "null") {
                $jsonObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $null -Force
            }
            else {
                $newIndicator | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
            }
        }

        $indicators += $newIndicator

    }

    $jsonOutput = [PSCustomObject]@{
        Indicators = $indicators
    }

    $jsonData = $jsonOutput | ConvertTo-Json -Depth 10
    $url = "https://api.securitycenter.microsoft.com/api/indicators/import"
} else {
    # JSON contains only one IoC

    # Convert PsObject back into JSON after checking formatting errors.
    $jsonData = $jsonObject | ConvertTo-Json 
    $url = "https://api.securitycenter.microsoft.com/api/indicators/"
}



# Creating the Submit IoC Request
$webResponse = $null
$headers = @{
    'Content-Type' = 'application/json'
    Authorization = "Bearer $token"
}

$body = @"
$jsonData
"@

$webResponse = Invoke-WebRequest -Method POST -Uri $url -Headers $headers -body $body
$IocContent = $webResponse.Content | ConvertFrom-Json
$webResponse.BaseResponse
