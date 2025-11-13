>[!IMPORTANT]
>This repository is no longer maintained. The script has been tested and works with version **7.6.4 FortiWeb**.
# 1.0 Fortiweb to xlsx/json
## 1.1 Introduction
This script is designed to generate a file .xlsx and .json only of the policy configuration giving in as input the fortiweb full backup.

## 1.2 Features Overview
- **XLSX Output**:  
  The .xlsx output file contains the following columns: Entry, Policy Name, Protected Hostname, VIP Name, VIP, Server Pool, Deployment Mode, Content Routing, Monitor Mode, Load Balancing Algorithm, Health Check, Certificate, Persistence, and X-Forwarded-For/X-Real-IP.
- **JSON Output**:  
  The .json output file contains the complete policy configuration in detail.

# 2.0 I/O Interface
## 2.1 Usage
1. Export the full backup file (.conf) from the FortiWeb appliance.
2. Run the script.
```powershell
PS Desktop> python3 fortiweb_extract.py <INPUT> <OUTPUT>

PS Desktop> python3 fortiweb_extract.py fwb_system.conf myoutput
File JSON: myoutput.json
File Excel: myoutput.xlsx
```

>[!NOTE]
> On the input field, specify the path where the backup file (.conf) is located. If you've executed the script in the same directory where the backup file are located, you can simply provide the filename. 

## 2.2 Output

![anim](https://github.com/user-attachments/assets/7a20fbf4-e1da-4ed3-83ff-9ad3c1626667)

### 2.2.1 XLSX Output
<img width="1892" height="132" alt="xlsx_output" src="https://github.com/user-attachments/assets/9fd6d53d-71f2-4c79-a7e8-5701e629c037" />

### 2.2.2 JSON Output
<img width="623" height="873" alt="json_output" src="https://github.com/user-attachments/assets/141f187c-abd7-4ade-85fa-5746ef60f23c" />

---
