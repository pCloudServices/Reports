**Privilege Cloud License Capacity User Report**

**Introduction:**
The Privilege Cloud License Capacity User Report script is a PowerShell tool designed to generate comprehensive reports of users consuming resources in the Privilege Cloud for a specific tenant URL.

**Prerequisites:**
1. Must execute from a machine that can reach the tenant via CyberArk Port 1858

2. Must execute from a machine that can reach the tenant via HTTPs

3. Privilege Cloud Tenant URL, Example `https://<subdomain>.cyberark.cloud`.

4. Local CyberArk Account (for STD we recommend admin_<subdomain>. for ISPSS installeruser@<suffix>


**Flag Options:**

1. `-PortalURL` (Mandatory):
   - Specifies the URL of the Privilege Cloud tenant. Example: `-PortalURL "https://<subdomain>.cyberark.cloud"`

2. `-AuthType` (Optional):
   - Specifies the authentication type for accessing Privilege Cloud. Default value: `cyberark`
   - Valid values: `cyberark`

3. `-InactiveDays` (Optional):
   - Specifies the number of days to consider users as inactive. Default value: `60`
   - Example: `-InactiveDays 90`

4. `-ExportToCSV` (Switch):
   - If this switch is specified, the results will be exported to a CSV file. If not specified, results will be printed in the PowerShell console.

5. `-GetSpecificUserTypes` (Optional):
   - Specifies the user types to generate a report on. Default values: `EPVUser, EPVUserLite, BasicUser, ExtUser, CPM, PSM, AppProvider`
   - Example: `-GetSpecificUserTypes "EPVUser", "BasicUser"`

6. `-ReportType` (Optional):
   - Specifies the type of report to generate. Default value: `CapacityReport`
   - Valid values: `CapacityReport`, `DetailedReport`
   - Example: `-ReportType DetailedReport`

7. `-Credentials` (Optional):
   - Specifies the credential to use for authenticating with Privilege Cloud. If not specified, the script will prompt for credentials.

**Examples:**

1. License Capacity Report:
   ```
   .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "https://<subdomain>.cyberark.cloud" -AuthType "cyberark" -InactiveDays 60 -ReportType CapacityReport
   ```

2. Detailed Report for Specific User Types:
   ```
   .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "https://<subdomain>.cyberark.cloud" -AuthType "cyberark" -InactiveDays 90 -ExportToCSV -ReportType DetailedReport
   ```

Note:
-----
- The script may take some time to execute, depending on the number of users and the response time from the Privilege Cloud API.

**Demo**
--------

![image](https://github.com/pCloudServices/Reports/assets/29689227/38263093-6605-4a9c-8c41-c650fe2c0047)

![image](https://github.com/pCloudServices/Reports/assets/29689227/29cc786d-f384-4aea-a753-ac99fb92aaaa)

