using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace Confuser.Runtime
{
    internal static class AntiVM
    {
        [DllImport("kernel32.dll", EntryPoint = "GetModuleHandle", CharSet = CharSet.Unicode)]
        internal static extern IntPtr SearchData(string x);
        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", CharSet = CharSet.Unicode)]
        internal static extern IntPtr EnvironmentStringExpressionSet(IntPtr a, string b);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetFileAttributes", SetLastError = true)]
        internal static extern uint ICryptoTransform(string d);
        
        static void Initialize()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return; // Virtual Machine detection logic uses Windows specific APIs (WMI/Registry)

            try 
            {
                if (CspParameters())
                {
                    // Fixed: FailFast is uncatchable and cross-platform instead of using cmd.exe 
                    Environment.FailFast("VirtualMachine Detected!");
                    Process.GetCurrentProcess().Kill();
                }
            } 
            catch { }
        }

        internal static bool CspParameters()
        {
            if (NodeEnumerator("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VBOX"))
                return true;
            if (NodeEnumerator("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("VBOX"))
                return true;
            if (NodeEnumerator("HARDWARE\\Description\\System", "VideoBiosVersion").ToUpper().Contains("VIRTUALBOX"))
                return true;
            if (NodeEnumerator("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "") == "noValueButYesKey")
                return true;
            if (ICryptoTransform("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys") != 4294967295u)
                return true;
            if (NodeEnumerator("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE"))
                return true;
            if (NodeEnumerator("SOFTWARE\\VMware, Inc.\\VMware Tools", "") == "noValueButYesKey")
                return true;
            if (NodeEnumerator("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE"))
                return true;
            if (NodeEnumerator("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE"))
                return true;
            if (NodeEnumerator("SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0").ToUpper().Contains("VMWARE"))
                return true;
            if (NodeEnumerator("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc").ToUpper().Contains("VMWARE"))
                return true;
            if (NodeEnumerator("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description").ToUpper().Contains("VMWARE"))
                return true;
            if (NodeEnumerator("SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath").ToUpper().Contains("C:\\PROGRAM FILES\\VMWARE\\VMWARE TOOLS\\"))
                return true;
            if (ICryptoTransform("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys") != 4294967295u)
                return true;
            if (ICryptoTransform("C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys") != 4294967295u)
                return true;
            if (EnvironmentStringExpressionSet(SearchData("kernel32.dll"), "wine_get_unix_file_name") != (IntPtr)0)
                return true;
            if (NodeEnumerator("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("QEMU"))
                return true;
            if (NodeEnumerator("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("QEMU"))
                return true;

            try 
            {
                ManagementScope scope = new ManagementScope("\\\\.\\ROOT\\cimv2");
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_VideoController");
                foreach (ManagementBaseObject managementBaseObject in new ManagementObjectSearcher(scope, query).Get())
                {
                    ManagementObject managementObject = (ManagementObject)managementBaseObject;
                    if (managementObject["Description"].ToString() == "VM Additions S3 Trio32/64") return true;
                    if (managementObject["Description"].ToString() == "S3 Trio32/64") return true;
                    if (managementObject["Description"].ToString() == "VirtualBox Graphics Adapter") return true;
                    if (managementObject["Description"].ToString() == "VMware SVGA II") return true;
                    if (managementObject["Description"].ToString().ToUpper().Contains("VMWARE")) return true;
                    if (managementObject["Description"].ToString() == "") return true;
                }
            } catch { }
            return false;
        }

        internal static string NodeEnumerator(string A_0, string A_1)
        {
            try 
            {
                RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(A_0, false);
                if (registryKey == null) return "noKey";
                
                object value = registryKey.GetValue(A_1, "noValueButYesKey");
                if (value.GetType() == typeof(string)) return value.ToString();
                
                if (registryKey.GetValueKind(A_1) == RegistryValueKind.String || registryKey.GetValueKind(A_1) == RegistryValueKind.ExpandString)
                    return value.ToString();
                if (registryKey.GetValueKind(A_1) == RegistryValueKind.DWord)
                    return Convert.ToString((int)value);
                if (registryKey.GetValueKind(A_1) == RegistryValueKind.QWord)
                    return Convert.ToString((long)value);
                if (registryKey.GetValueKind(A_1) == RegistryValueKind.Binary)
                    return Convert.ToString((byte[])value);
                if (registryKey.GetValueKind(A_1) == RegistryValueKind.MultiString)
                    return string.Join("", (string[])value);
            } catch { }
            
            return "noValueButYesKey";
        }
    }
}