# Horizon Profile Storage Automation (DEM + FSLogix)

This repository provides PowerShell automation scripts for deploying and validating profile storage for:

- Omnissa Dynamic Environment Manager (DEM)
- Microsoft FSLogix

Supports both:

- Windows File Server (SMB)
- Nutanix Files (SMB)

---

## ⚙️ Requirements

- PowerShell 5.1 or later
- Administrator privileges
- SMB access to target storage
- Active Directory security groups created (recommended)

---

## 🧪 Supported Platforms

| Platform              | Share Creation | NTFS ACLs | Validation        |
|----------------------|---------------|----------|------------------|
| Windows File Server  | ✅            | ✅       | ✅               |
| Nutanix Files        | ❌ (Prism)    | ✅       | ✅ (NTFS only)   |

> Nutanix Files SMB shares must be created in Prism / Files Console

---

## 📄 Usage

### ▶️ Full Deployment (DEM + FSLogix)

```powershell
.\Horizon-ProfileStorage-MultiPlatform.ps1 `
  -StorageType WindowsFileServer `
  -Workload Both
```

---

### ▶️ Nutanix Files Deployment

```powershell
.\Horizon-ProfileStorage-MultiPlatform.ps1 `
  -StorageType NutanixFiles `
  -Workload Both
```

---

### ▶️ FSLogix Only

```powershell
.\Horizon-ProfileStorage-MultiPlatform.ps1 `
  -StorageType WindowsFileServer `
  -Workload FSLogix
```

---

### ▶️ DEM Only

```powershell
.\Horizon-ProfileStorage-MultiPlatform.ps1 `
  -StorageType WindowsFileServer `
  -Workload DEM
```

---

### ▶️ Validation Only (No Changes)

```powershell
.\Horizon-ProfileStorage-MultiPlatform.ps1 `
  -StorageType NutanixFiles `
  -Workload Both `
  -Mode ValidateOnly
```

---

## 🔐 Permissions Model

### FSLogix (Microsoft Recommended)

| Identity        | Permission | Scope                     |
|----------------|-----------|--------------------------|
| CREATOR OWNER  | Modify    | Subfolders & files only  |
| SYSTEM         | Full      | All                      |
| Admins         | Full      | All                      |
| Users          | Modify    | This folder only         |

---

### DEM Configuration Share

| Identity   | Permission        |
|-----------|------------------|
| Admins    | Full Control      |
| Users     | Read & Execute    |
| Computers | Read & Execute    |

---

### DEM Profile Archives Share

| Identity        | Permission                     |
|----------------|--------------------------------|
| Admins         | Full Control                   |
| CREATOR OWNER  | Full Control (subfolders)      |
| Users          | Create folder (root only)      |

---

## 🔍 Validation

The script includes built-in validation:

- NTFS ACL checks
- SMB share permission checks (Windows only)
- PASS / FAIL output

---

## ⚠️ Important Notes

### Nutanix Files

- SMB shares must be created manually in Prism
- Validate share permissions separately:
  - Admins → Full Control
  - Users → Modify / Change

---

## 🧠 Best Practices

- Do NOT use Domain Users in production  
- Use dedicated AD groups:
  - FSLogix-Users
  - DEM-Users
- Enable Access-Based Enumeration (ABE)
- Disable offline caching
- Exclude FSLogix paths from antivirus

---

## 📚 References

- https://learn.microsoft.com/en-us/fslogix/how-to-configure-storage-permissions  
- https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/DynamicEnvironmentManagerConfigurationShare.html  
- https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2603/page/ProfileArchivesShare.html  
- https://portal.nutanix.com/docs/Files-v5_1%3Afil-file-server-authorization-c.html  

---

## 📄 License

MIT License (or your preferred license)
