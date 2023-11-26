using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Threading;
using System.Collections;

namespace CSAPTray
{

    
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

        }

        /*The PeScan() method calls the GetImportedFunctions() method to obtain the list of imported functions in the given PE file, 
         * and then calculates the similarity between each function in the list and the predefined function list (i.e., functionList). 
         * If the similarity between any imported function name and any function name in the predefined function list exceeds 0.5, the PeScan() method will return true, 
         * indicating that the PE file contains malicious code.*/
        //Pescan


        private List<string> functionList = new List<string> {
        
        
        };

        public bool PeScan(string pePath)
        {
            string filePath = ""; 

            try
            {
                List<string> fn = GetImportedFunctions(pePath);

                foreach (var vfl in functionList)
                {
                    double similarity = CalculateSimilarity(vfl, fn);
                    if (similarity > 0.5)
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private List<string> GetImportedFunctions(string pePath)
        {
            List<string> importedFunctions = new List<string>();
            IntPtr hModule = LoadLibrary(pePath);
            if (hModule != IntPtr.Zero)
            {
                try
                {
                    IntPtr pAddress = GetProcAddress(hModule, "GetProcAddress");
                    if (pAddress != IntPtr.Zero)
                    {

                        //Bug ACx000001
                    }
                }
                finally
                {
                    FreeLibrary(hModule);
                }
            }
            return importedFunctions;
        }

        private double CalculateSimilarity(string vfl, List<string> fn)
        {
            int minLength = Math.Min(vfl.Length, fn.Count);
            int matchingCount = fn.Take(minLength).Count(f => vfl.Contains(f));
            return (double)matchingCount / minLength;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string lpFileName);

        

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr hModule);

        //MD5Scan
        /*
         The ScanFile() method now takes an array of strings named expectedHashes as a parameter, 
        and after calculating the MD5 hash value of the file, compares it one by one with the expected hash value.
        If there is any matching hash value, return true; Otherwise, return false.
         */

        public static bool ScanFile(string filePath, string expectedHashes)
        {
            string fileExtension = Path.GetExtension(filePath).ToLower();
            if (fileExtension == ".exe" || fileExtension == ".dll" ||
                fileExtension == ".com" || fileExtension == ".bat" ||
                fileExtension == ".vbs" || fileExtension == ".vbe" ||
                fileExtension == ".msi" || fileExtension == ".js" ||
                fileExtension == ".jar" || fileExtension == ".ps1" ||
                fileExtension == ".xls" || fileExtension == ".xlsx" ||
                fileExtension == ".doc" || fileExtension == ".docx")
            {
                string[] hashes = expectedHashes.Split(',');

                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hash = md5.ComputeHash(stream);
                        string md5Hash = BitConverter.ToString(hash).Replace("-", "").ToLower();

                        // Compare the computed MD5 hash with the expected hashes
                        foreach (var expectedHash in hashes)
                        {
                            if (md5Hash.Equals(expectedHash.Trim(), StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            // File extension is not supported for MD5 scanning or no matching hash found
            return false;
        }

        //RegProtect

        private bool regProtect;

        public void ProtectSystemRegRepair()
        {
            while (regProtect)
            {
                try
                {
                    Thread.Sleep(200);
                    RepairSystemRestrictions();
                }
                catch { }
            }
        }

        //regFix
        private void RepairSystemRestrictions()
        {
            try
            {
                string[] permission = {"NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu",
                "NoSetFolders", "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop", "NoLogOff",
                "NoFolderOptions", "RestrictRun", "DisableCMD", "NoViewContexMenu", "HideClock", "NoStartMenuMorePrograms",
                "NoStartMenuMyGames", "NoStartMenuMyMusic", "NoStartMenuNetworkPlaces", "NoStartMenuPinnedList",
                "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges", "NoChangeStartMenu",
                "ClearRecentDocsOnExit", "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp",
                "NoTrayContextMenu", "NoViewContextMenu", "NoWindowsUpdate", "NoWinKeys", "StartMenuLogOff",
                "NoSimpleNetlDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation", "NoManageMyComputerVerb",
                "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword", "Wallpaper", "NoComponents",
                "NoAddingComponents", "Restrict_Run"};

                RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }

                key = Registry.CurrentUser.OpenSubKey("Software\\Policies\\Microsoft\\MMC\\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}", true);
                if (key != null)
                {
                    foreach (string perm in permission)
                    {
                        try
                        {
                            key.DeleteValue(perm);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        //MBRFix

        private bool mbrProtect;
        private byte[] mbrValue;

        public void ProtectSystemMBRRepair()
        {
            while (mbrProtect && mbrValue != null)
            {
                try
                {
                    Thread.Sleep(200);
                    using (FileStream fs = new FileStream(@"\\.\PhysicalDrive0", FileMode.Open, FileAccess.ReadWrite))
                    {
                        byte[] buffer = new byte[512];
                        fs.Read(buffer, 0, 512);
                        if (!StructuralComparisons.StructuralEqualityComparer.Equals(buffer, mbrValue))
                        {
                            fs.Seek(0, SeekOrigin.Begin);
                            fs.Write(mbrValue, 0, mbrValue.Length);
                            //information1
                        }
                    }
                }
                catch { }
            }
        }


        //other Fix codes

        public void RepairSystemIcon()
        {
            try
            {
                string[] fileTypes = { "exefile", "comfile", "txtfile", "dllfile", "inifile", "VBSfile" };

                foreach (string fileType in fileTypes)
                {
                    try
                    {
                        RegistryKey key = Registry.ClassesRoot.OpenSubKey(fileType, true);
                        key.SetValue("DefaultIcon", "%1", RegistryValueKind.String);
                    }
                    catch { }

                    try
                    {
                        RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Classes\\" + fileType, true);
                        key.SetValue("DefaultIcon", "%1", RegistryValueKind.String);
                    }
                    catch { }
                }
            }
            catch { }
        }

        public void RepairSystemImage()
        {
            try
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true);
                string[] subKeyNames = key.GetSubKeyNames();

                foreach (string subKeyName in subKeyNames)
                {
                    try
                    {
                        key.DeleteSubKey(subKeyName);
                    }
                    catch { }
                }
            }
            catch { }
        }

        public void RepairSystemFileType()
        {
            try
            {
                string[,] data = { { "jpegfile", "JPEG Image" }, { ".exe", "exefile" }, { "exefile", "Application" }, { ".com", "comfile" },
                               { "comfile", "MS-DOS Application" }, { ".zip", "CompressedFolder" }, { ".dll", "dllfile" },
                               { "dllfile", "Application Extension" }, { ".sys", "sysfile" }, { "sysfile", "System file" },
                               { ".bat", "batfile" }, { "batfile", "Windows Batch File" }, { "VBS", "VB Script Language" },
                               { "VBSfile", "VBScript Script File" }, { ".txt", "txtfile" }, { "txtfile", "Text Document" },
                               { ".ini", "inifile" }, { "inifile", "Configuration Settings" } };

                RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Classes", true);

                for (int i = 0; i < data.GetLength(0); i++)
                {
                    key.SetValue(data[i, 0], data[i, 1], RegistryValueKind.String);
                }

                key.Close();
                key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Classes", true);

                for (int i = 0; i < data.GetLength(0); i++)
                {
                    key.SetValue(data[i, 0], data[i, 1], RegistryValueKind.String);

                    try
                    {
                        RegistryKey keyOpen = key.OpenSubKey(data[i, 0] + "\\shell\\open", true);
                        keyOpen.SetValue("command", "\"%1\" %*", RegistryValueKind.String);
                        keyOpen.Close();
                    }
                    catch { }
                }

                key.Close();
                key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts", true);
                string[] extensions = { ".exe", ".zip", ".dll", ".sys", ".bat", ".txt", ".msc" };

                foreach (string extension in extensions)
                {
                    key.SetValue(extension, "", RegistryValueKind.String);
                }

                key.Close();
                key = Registry.ClassesRoot.OpenSubKey(null, true);

                for (int i = 0; i < data.GetLength(0); i++)
                {
                    key.SetValue(data[i, 0], data[i, 1], RegistryValueKind.String);

                    if (data[i, 0] == ".cmd" || data[i, 0] == ".vbs")
                    {
                        key.SetValue(data[i, 0] + "file", "Windows Command Script", RegistryValueKind.String);
                    }

                    try
                    {
                        RegistryKey keyOpen = key.OpenSubKey(data[i, 0] + "\\shell\\open", true);
                        keyOpen.SetValue("command", "\"%1\" %*", RegistryValueKind.String);
                        keyOpen.Close();
                    }
                    catch { }
                }

                key.Close();
            }
            catch { }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void tabPage1_Click(object sender, EventArgs e)
        {

        }

        
    }
    
}
