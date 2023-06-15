# PLEASE NOTE THAT I TAKE NO RESPONSIBILITY ON THE RESULTS THIS SCRIPT MIGHT YIELD
# PLEASE USE AT YOUR DESCRETION, TEST, AND ENSURE IT FITS YOUR NEEDS

# Author: Jeff Michelmore
# Connect: https://www.linkedin.com/in/jeffrey-michelmore/
# Blog: https://securityoccupied.com/

# Objective:
# Script can perform several machine-related actions on devices onboarded to MDE 
# These actions include: Output all machine data to CSV, collect investigation package, isolate/unisolate, live response commands, restrict/unrestrict apps, AV scan, offboard, stop & quarantine, cancel action.
# For the actions that take Machine ID as input, you can either supply a single machine ID or provide a CSV file which contains a column titled "Device ID" or "id".
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

Function Set-DeviceInputQuantity {
    param([ref]$breakFlag)
    # This function is used throughout the script to check if user would like to input a single machine ID or a csv of machines.
    $script:CsvDeviceIDs = $null 
    Write-Host "Type 'y' to enter a CSV of devices or 'n' to enter a single device ID."
    $script:MultipleInputChoice = Read-Host 
    switch($MultipleInputChoice)
    {
        'n'{
            # User input a single machine ID
            $UserInput = Read-Host "Enter a Machine ID"
            $Script:UserChosenMachineID = $UserInput
        }

        'y'{
            # User input a CSV of machine IDs
            Write-Host "Enter full file path to input CSV." -ForegroundColor Yellow
            Write-Host "Ensure there is a column titled 'Device ID' or 'id' in the CSV file."
            $script:CsvInputPath = Read-Host 
            $script:CsvInputPath = $Script:CsvInputPath -replace '"',''
            $script:CsvDevicesObject = $null
            $script:CsvDevicesObject = Import-Csv $script:CsvInputPath
            
            # Checking CSV headers for "id" or "Device ID" value and creating list of Device IDs based on those values
            If($CsvDevicesObject.'Device ID' -ne $null){
                [System.Collections.ArrayList]$Script:UserChosenMachineIds = $CsvDevicesObject.'Device ID'
            }
            elseif ($CsvDevicesObject.id -ne $null) {
                [System.Collections.ArrayList]$Script:UserChosenMachineIds = $CsvDevicesObject.id
            }
            if ($CsvDevicesObject -eq $null) {
                Write-Host "Could not find any column titled 'Device Id' or 'id' in supplied CSV. Please add one of those two column titles and try again."
                $breakFlag.Value = $True
            }
            
        }

    }

}

Function Show-Menu {

# Display Main Menu
Write-Host "============== Machine Actions ==============" -ForeGroundColor Yellow
Write-Host "1: Press '1' Output All Machine Info to CSV"
Write-Host "2: Press '2' Collect Investigation Package"
Write-Host "3: Press '3' Isolate or Unisolate Machine"
Write-Host "4: Press '4' Run Live Response"
Write-Host "5: Press '5' Restrict or Unrestrict Applications"
Write-Host "6: Press '6' Run Antivirus Scan"
Write-Host "7: Press '7' Offboard Machine"
Write-Host "8: Press '8' Stop and Quarantine File"
Write-Host "9: Press '9' Cancel a Machine Action"
Write-Host "Q: Press 'Q' to Quit"
Write-Host "`n"
# Get User Input for Machine Action Choice
$Script:MachineActionSelection = Read-Host "Please make a selection" 
}

do
{
    $breakFlag = $false
    Show-Menu
    switch ($MachineActionSelection)
    {
    '1'{
        # Outputs list of all machines to CSV
        # List Machines API public doc: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machines?view=o365-worldwide
        $webResponse = $null
        Write-Host "List Machines to CSV" -ForegroundColor Yellow
        $url = "https://api.securitycenter.microsoft.com/api/machines"
        $headers = @{
        Authorization = "Bearer $token"
        }
        $webResponse = Invoke-WebRequest -Method Get -Uri $url -Headers $headers
        $MachinesContent = $webResponse.Content | ConvertFrom-Json
        
        Write-Host "Enter File path to .csv output of machine info" -ForegroundColor Yellow
        $MachinesOutputFile = Read-Host
        $MachinesOutputFile = $MachinesOutputFile -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $MachinesOutputFile = [System.IO.Path]::ChangeExtension($MachinesOutputFile, ".csv")
        $MachinesContent.Value | ConvertTo-Csv -NoTypeInformation | Set-Content $MachinesOutputFile -Force 
        if ($?) {
            Write-Host "Successfully created $MachinesOutputFile" -ForegroundColor Yellow
            Invoke-Item -Path $MachinesOutputFile
        } else {
            Write-Host "Failed to create $MachinesOutputFile" -ForegroundColor Red
        }
    }
    '2'{
        # Collects Investigation Package from Device(s)
        # Investigation package API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/collect-investigation-package?view=o365-worldwide
        $PackageCollectionWebRequest = $null
        Write-Host "Collect Investigation Package." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $comment = Read-Host 
        $body = @"
    {
"Comment": "$comment"
    }
"@

        switch($MultipleInputChoice){
            'n'{
                # User chose to input a single device ID
                $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineId/collectInvestigationPackage"
                $PackageCollectionWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body 
                $PackageCollectionWebRequest | ConvertFrom-Json
            }
            'y'{
                # User chose to input a CSV of device IDs
                foreach($i in $UserChosenMachineIds){
                    $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/collectInvestigationPackage"
                    $PackageCollectionWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                    $PackageCollectionWebRequest | ConvertFrom-Json
                }
            }
        }

    }
    '3'{
        # Isolate/Unisolate Machines
        # Isolation API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine?view=o365-worldwide
        # Unisolation API public doc:  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unisolate-machine?view=o365-worldwide
        $DeviceIsolationWebRequest = $null
        Write-Host 'Isolate/Unisolate Device(s)' -ForegroundColor Yellow    
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }

        # Get user input for isolate/unisolate then set comment and headers
        Write-Host "Type 'I' to isolate or 'U' to unisolate." -ForegroundColor Yellow
        $IsolateOrUnisolateSelection = Read-Host
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host 
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }

        # Check if user is inputing CSV or single Machine ID
        switch ($MultipleInputChoice){
            'n'{
                # User entering single Machine ID
                # Check if user is isolating or unisolating
                switch($IsolateOrUnisolateSelection){
                    'i'{
                        # User chose to isolate
                        # For isolation, user must input isolation type (full/selective)
                        Write-Host "Please enter isolation type. Allowed values are: 'Full' or 'Selective'." -ForegroundColor Yellow
                        $IsolationType = Read-Host 
                        $body = @"
                        {
                            "Comment": "$comment",
                            "IsolationType": "$IsolationType"
                        }
"@
                        $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/isolate"
                        $DeviceIsolationWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body
                        $DeviceIsolationWebRequest | ConvertFrom-Json
                    }
                    'u'{
                        # User chose to unisolate
                        $body = @"
                        {
                            "Comment": "$comment"
                        }
"@           
                        $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/unisolate"
                        $DeviceIsolationWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body
                        $DeviceIsolationWebRequest | ConvertFrom-Json
                    }
                }
            }
            'y'{
                # User entering CSV of machine IDs
                switch($IsolateOrUnisolateSelection){
                    'i'{
                        # User chose to isolate
                        # For isolation, user must input isolation type (full/selective)
                        Write-Host "Please enter isolation type. Allowed values are: 'Full' or 'Selective'." -ForegroundColor Yellow
                        $IsolationType = Read-Host 
                        $body = @"
                        {
                            "Comment": "$comment",
                            "IsolationType": "$IsolationType"
                        }
"@
                        foreach($i in $UserChosenMachineIds){
                            $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/isolate"
                            $PackageIsolationWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                            $PackageIsolationWebRequest | ConvertFrom-Json
                        }
                    }                    
                    'u'{
                        # User chose to unisolate
                        $body = @"
                        {
                            "Comment": "$comment"
                        }
"@
                        foreach($i in $UserChosenMachineIds){
                        $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/unisolate"
                        $DeviceIsolationWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body
                        $DeviceIsolationWebRequest | ConvertFrom-Json
                        }
                        
                    }
                }
            }
        }


    }
    '4'{
        # Live Response
        # Live Response API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide
        $LiveResponseWebRequest = $null
        Write-Host 'Live Response' -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a command. Allowed values are 'PutFile', 'RunScript', or 'GetFile'" -ForegroundColor Yellow
        $commands = Read-Host 
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $comment = Read-Host 
        
        switch($script:commands){
            'PutFile'   {
                Write-Host 'PutFile' -ForegroundColor Yellow
                $script:PutFilePath = Read-Host "Please enter file path of library file to put."
                $script:body = @"
                {
                "Commands":[
                {
                    "type":"$commands",
                    "params":[
                        {
                            "key":"FileName",
                            "value":"$PutFilePath"
                        }
                    ]
                }
                ],
                "Comment":"$comment"
                }
"@
       }
       'RunScript'{
           Write-Host 'RunScript' -ForegroundColor Yellow
           $script:ScriptName = Read-Host "Please enter the script name."
           #$script:LiveResponseArgs = Read-Host "Please enter any parameters to pass to the script (leave blank if there are none)." #Omitting Arguments key for now
       $script:body = @"
       {
       "Commands":[
        {
           "type":"$commands",
           "params":[
               {
                   "key":"ScriptName",
                   "value":"$ScriptName"
                }
            ]   
       }
       ],
       "Comment":"$comment"
        }
       
"@    
       
       }
       'GetFile'{
           Write-Host 'GetFile' -ForegroundColor Yellow
           $script:GetFilePath = Read-Host "Please enter the file path and name to get."
           $script:body = @"
           {
       "Commands":[
        {
           "type":"$commands",
           "params":[
               {
                   "key":"Path",
                   "value":"$GetFilePath"
                }
            ]
        }
       ],
       "Comment":"$comment"
        }
"@
        }
    }

    switch($MultipleInputChoice){
        'n'{ 
            # User entering single machine ID
            $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/runliveresponse"
            $LiveResponseWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body 
            $LiveResponseWebRequest | ConvertFrom-Json    
        }
        'y'{ 
            # User entering CSV of machine IDs       
            foreach($i in $UserChosenMachineIds){
                $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/runliveresponse"
                $LiveResponseWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                $LiveResponseWebRequest | ConvertFrom-Json             
            }    
        }
     }


    }
    '5'{
        # Restricts/Unrestricts App Execution
        # Restrict App API Public Doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/restrict-code-execution?view=o365-worldwide
        # Remove Restriction API Public Doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unrestrict-code-execution?view=o365-worldwide
        $RestrictAppsWebRequest = $null
        Write-Host "Restrict/Unrestrict execution of non-Microsoft signed applications." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Type 'R' to Restrict or 'U' to Unrestrict." -ForegroundColor Yellow
        $RestrictOrUnrestrict = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host 
        $body = @"
                        {
    "Comment": "$comment"
                        }
"@
            switch($MultipleInputChoice){
                'n'{
                    # User entering single machine ID
                    switch($RestrictOrUnrestrict){
                        'r'{
                            # User chose to restrict
                            $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/restrictCodeExecution"
                            $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                            $RestrictAppsWebRequest | ConvertFrom-Json
                        }
                        'u'{
                            # User chose to unrestrict
                            $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/unrestrictCodeExecution"
                            $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                            $RestrictAppsWebRequest | ConvertFrom-Json
                        }
                    }

                }
                'y'{
                    # User entering CSV of machine IDs
                    switch($RestrictOrUnrestrict){
                        'r'{
                            # User chose to restrict
                            foreach($i in $UserChosenMachineIds){
                                $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/restrictCodeExecution"
                                $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                                $RestrictAppsWebRequest | ConvertFrom-Json
                            }
                            
                        }
                        'u'{
                            # User chose to unrestrict
                            foreach($i in $UserChosenMachineIds){
                                $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/unrestrictCodeExecution"
                                $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                                $RestrictAppsWebRequest | ConvertFrom-Json
                            }
                        }
                    }
                }
            }

    }
    '6'{
        # Runs an AV scan
        # AV Scan API Public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-av-scan?view=o365-worldwide
        $AVScanWebRequest = $null
        Write-Host "Run Antivirus Scan." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Type 'F' for Full scan or 'Q' for Quick scan."
        $ScanType = Read-Host
        If($ScanType.ToLower() -eq 'f'){$ScanType = 'Full'}
        If($ScanType.ToLower() -eq 'q'){$ScanType = 'Quick'}
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        $body = @"
        {
            "Comment": "$Comment",
            "ScanType": "$ScanType"
        }
"@
        switch($MultipleInputChoice){
            'n'{
                # User entering single machine ID
                $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/runAntiVirusScan"
                $AVScanWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
                $AVScanWebRequest | ConvertFrom-Json
            }
            'y'{
                # User entering CSV of machine IDs
                foreach($i in $UserChosenMachineIds){
                    $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/runAntiVirusScan"
                    $AVScanWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
                    $AVScanWebRequest | ConvertFrom-Json
                }
            }
        }
    }
    '7'{
        # Offboards devices
        # Offboarding API Public Doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/offboard-machine-api?view=o365-worldwide
        $OffboardWebRequest = $null
        Write-Host "Offboard Machines." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        $body = @"
        "Comment": "$comment"
"@
switch($MultipleInputChoice){
    'n'{
        # User entering single machine ID
      $URL =  "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/offboard"
      $OffboardWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
      $OffboardWebRequest | ConvertFrom-Json
    }
    'y'{
        # User entering CSV of machine IDs
        foreach($i in $UserChosenMachineIds){
      $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/offboard"
      $OffboardWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
      $OffboardWebRequest | ConvertFrom-Json
        }
    }
}

    }
    '8'{
        # Stop and Quarantine a file
        # Stop and Quarantine API Public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file?view=o365-worldwide
        $StopFileWebRequest = $null
        Write-Host "Stop & Quarantine File" -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Please enter the SHA1 of the file to stop and quarantine." -ForegroundColor Yellow
        $sha1 = Read-Host
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        $body = @"
        "Comment": "$comment",
        "Sha1": "$Sha1"
"@
switch($MultipleInputChoice){
    'n'{
        $URL =  "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/StopandQuarantineFile"
        $StopFileWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
        $StopFileWebRequest | ConvertFrom-Json
    }
    'y'{
        foreach($i in $UserChosenMachineIds){
            $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/StopandQuarantineFile"
            $StopFileWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
            $StopFileWebRequest | ConvertFrom-Json
        }
    }
}


    }
    '9'{    
        # Cancels a pending machine action
        # Cancel action API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cancel-machine-action?view=o365-worldwide
        $CancelActionWebRequest = $null
        Write-Host "Cancel a pending machine action." -ForegroundColor Yellow
        Write-Host "Enter Machine Action ID" -ForegroundColor Yellow
        $MachineActionID = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $comment = Read-Host
        $body = @"
        {
    "Comment": "$comment"
        }
"@
    
        $URL = "https://api.securitycenter.microsoft.com/api/machineactions/$MachineActionID/cancel"
        $CancelActionWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body 
        $CancelActionWebRequest | ConvertFrom-Json    
    }
}

}
until ($MachineActionSelection -eq 'q')

