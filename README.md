>[!IMPORTANT]
>This repository is no longer maintained. The script has been tested and works with version 7.6.4 FortiWeb.

# 1.0 Description
This script is designed to generate a file .xlsx and .json only of the policy configuration giving in as input the fortiweb full backup.

## 1.1 Feature Overview
- **XLSX Output**:  
  The .XLSX output file contains the following columns: Entry, Policy Name, Protected Hostname, VIP Name, VIP, Server Pool, Deployment Mode, Content Routing, Monitor Mode, Load Balancing Algorithm, Health Check, Certificate, Persistence, and X-Forwarded-For/X-Real-IP.
- **JSON Output**:  
  The .JSON output file contains the complete policy configuration in detail.

# 2.0 Usage
1. Export the full backup file (.conf) from the FortiWeb appliance.
1. Run the script.
```powershell
PS Desktop> python3 fortiweb_extract.py <INPUT> <OUTPUT>

PS Desktop> python3 fortiweb_extract.py fwb_system.conf myoutput
File JSON: myoutput.json
File Excel: myoutput.xlsx
```

>[!NOTE]
> On the input field, specify the path where the backup file (.conf) is located. If you've executed the script in the same directory as the full backup configuration, you can simply provide the filename. 

## 2.1 Output

<details>

<summary>This screenshot shows how the .XLSX output file appears.</summary>
<img width="1721" height="191" alt="xlsxl-file-output" src="https://github.com/user-attachments/assets/56d7fd6d-547a-466e-bac1-ad4e9a98ff8e" />

</details>



<details>

<summary>The following screenshot show how the file .JSON appears.</summary>
<img width="753" height="1652" alt="json-file-output" src="https://github.com/user-attachments/assets/5eecad64-ab5c-4a7f-a426-5bf18a75424d" />

</details>

---
