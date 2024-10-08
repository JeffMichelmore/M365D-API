# M365D-API
Sample scripts for accessing the M365D APIs.

### MDE Machine Actions API.ps1
Script can perform several machine-related actions on devices onboarded to MDE.

These actions include: Output all machine data to CSV, collect investigation package, isolate/unisolate, live response commands, restrict/unrestrict apps, AV scan, offboard, stop & quarantine, cancel action.

For the actions that take Machine ID as input, you can either supply a single machine ID or provide a CSV file which contains a column titled "Device ID" or "id".

For simplicity, this script authenticates using Tenant ID, App ID, and AppSecret in plaintext below. Note there are safer ways to access the MDE APIs that don't involve keeping these values in plaintext.

You can read about other authentication methods in Microsoft's public documentation. https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro?view=o365-worldwide

### MDE List Indicators.ps1
Using the [List Indicators API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-ti-indicators-collection), this script simply calls the API and outputs the content to a CSV in the root folder of the script. See the above documentation for required permissions and troubleshooting.


### MDE Submit Indicator.ps1
This script accepts a CSV file containing one or more custom indicators as input. A sample csv is provided. If one indicator is supplied, the [Submit or Update Indicator API](https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator) will be called. If multiple indicators are supplied, the [Import Indicators API](https://learn.microsoft.com/en-us/defender-endpoint/api/import-ti-indicators) will be called instead. Keep in mind, if rbacGroupNames and rbacGroupIds are both supplied for the same indicator, they must match (I would recommend only supplying one or the other). Additionally, if mitreTechniques is supplied, the correct category must be supplied too. See the corresponding documentations for troubleshooting.