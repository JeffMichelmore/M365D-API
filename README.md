# M365D-API
Sample scripts for accessing the M365D APIs.

### MDE Machine Actions API.ps1
Script can perform several machine-related actions on devices onboarded to MDE.

These actions include: Output all machine data to CSV, collect investigation package, isolate/unisolate, live response commands, restrict/unrestrict apps, AV scan, offboard, stop & quarantine, cancel action.

For the actions that take Machine ID as input, you can either supply a single machine ID or provide a CSV file which contains a column titled "Device ID" or "id".

For simplicity, this script authenticates using Tenant ID, App ID, and AppSecret in plaintext below. Note there are safer ways to access the MDE APIs that don't involve keeping these values in plaintext.

You can read about other authentication methods in Microsoft's public documentation. https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro?view=o365-worldwide
