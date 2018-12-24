#include "kRpm.h"

BOOL MoaRpm::load_driver(std::string TargetDriver, std::string TargetServiceName, std::string TargetServiceDesc)
{
	SC_HANDLE ServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!ServiceManager) return FALSE;
	SC_HANDLE ServiceHandle = CreateService(ServiceManager, TargetServiceName.c_str(), TargetServiceDesc.c_str(), SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, TargetDriver.c_str(), NULL, NULL, NULL, NULL, NULL);
	if (!ServiceHandle)
	{
		ServiceHandle = OpenService(ServiceManager, TargetServiceName.c_str(), SERVICE_START | DELETE | SERVICE_STOP);
		if (!ServiceHandle) return FALSE;
	}
	if (!StartServiceA(ServiceHandle, NULL, NULL)) return FALSE;
	CloseServiceHandle(ServiceHandle);
	CloseServiceHandle(ServiceManager);
	return TRUE;
}

BOOL MoaRpm::delete_service(std::string TargetServiceName)
{
	SERVICE_STATUS ServiceStatus;
	SC_HANDLE ServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!ServiceManager) return FALSE;
	SC_HANDLE ServiceHandle = OpenService(ServiceManager, TargetServiceName.c_str(), SERVICE_STOP | DELETE);
	if (!ServiceHandle) return FALSE;
	if (!ControlService(ServiceHandle, SERVICE_CONTROL_STOP, &ServiceStatus)) return FALSE;
	if (!DeleteService(ServiceHandle)) return FALSE;
	CloseServiceHandle(ServiceHandle);
	CloseServiceHandle(ServiceManager);
	return TRUE;
}

std::string MoaRpm::exePath() {
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}

bool MoaRpm::isElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

bool MoaRpm::isTestMode() {
	typedef NTSTATUS(__stdcall* td_NtQuerySystemInformation)(
		ULONG           SystemInformationClass,
		PVOID           SystemInformation,
		ULONG           SystemInformationLength,
		PULONG          ReturnLength
		);

	struct SYSTEM_CODEINTEGRITY_INFORMATION {
		ULONG Length;
		ULONG CodeIntegrityOptions;
	};

	static td_NtQuerySystemInformation NtQuerySystemInformation = (td_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	SYSTEM_CODEINTEGRITY_INFORMATION Integrity = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0 };
	NTSTATUS status = NtQuerySystemInformation(103, &Integrity, sizeof(Integrity), NULL);

	return (NT_SUCCESS(status) && (Integrity.CodeIntegrityOptions & 1));
}

void MoaRpm::init(DWORD pID, MOA_MODE AccessMode) {
	this->pID = pID;
	this->mode = AccessMode;
	if (this->mode == MOA_MODE::KERNEL) {
		if (!this->isElevated()) {
			MessageBox(NULL, "Must be running as admin for kernel mode stuff", "Fatal Error", MB_OK);
			exit(1);
		}
		if (!this->isTestMode()) {
			MessageBox(NULL, "Must have testing mode enabled to load unsigned driver", "Fatal Error", MB_OK);
			exit(1);
		}
		this->load_driver(exePath() + "\\kRpm.sys", "kRpm", "Kernel level readprocessmemory and writeprocessmemory");
	}
	else {

		this->hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pID);
	}
}

MoaRpm::MoaRpm(DWORD pID, MOA_MODE AccessMode) {
	this->init(pID, AccessMode);
}

MoaRpm::MoaRpm(const char* windowname, MOA_MODE AccessMode) {
	HWND targetWindow = FindWindow(NULL, windowname);
	//if (!targetWindow) printf("target window not found");
	GetWindowThreadProcessId(targetWindow, &this->pID);
	//printf("Target PID:%d\n", this->pID);
	this->init(pID, AccessMode);
}

MoaRpm::~MoaRpm() {
	if (this->mode == MOA_MODE::KERNEL) {
		this->delete_service("kRpm");
	}
	else {
		CloseHandle(this->hProcess);
	}
}

void MoaRpm::readRaw(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead) {
	if (this->mode == MOA_MODE::STANDARD) {
		ReadProcessMemory(this->hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
	if (this->mode == MOA_MODE::NTDLL) {
		NtReadVirtualMemory(this->hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, (PULONG)lpNumberOfBytesRead);
	}
	if (this->mode == MOA_MODE::KERNEL) {
		struct Rpmdata
		{
			HANDLE pid;
			PVOID SourceAddress;
			PVOID TargetAddress;
			SIZE_T Size;
		} rpm;
		rpm.pid = (HANDLE)pID;
		rpm.SourceAddress = (PVOID)lpBaseAddress;
		rpm.TargetAddress = lpBuffer;
		rpm.Size = nSize;
		HANDLE hDevice = INVALID_HANDLE_VALUE;
		BOOL bResult = FALSE;
		DWORD junk = 0;

		hDevice = CreateFileW(DRIVER_NAME, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);            // do not copy file attributes

		if (hDevice != INVALID_HANDLE_VALUE) {
			bResult = DeviceIoControl(hDevice, IOCTL_DUMP_MEM, &rpm, sizeof(rpm), lpBuffer, nSize, &junk, (LPOVERLAPPED)NULL);
			CloseHandle(hDevice);
			return;
		}
	}
}

bool MoaRpm::writeRaw(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead) {
	if (this->mode == MOA_MODE::STANDARD) {
		WriteProcessMemory(this->hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		return (*lpNumberOfBytesRead == nSize);
	}
	if (this->mode == MOA_MODE::NTDLL) {
		NtWriteVirtualMemory(this->hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, (PULONG)lpNumberOfBytesRead);
		return (*lpNumberOfBytesRead == nSize);
	}
	if (this->mode == MOA_MODE::KERNEL) {
		struct Rpmdata
		{
			HANDLE pid;
			PVOID SourceAddress;
			PVOID TargetAddress;
			SIZE_T Size;
		} rpm;
		rpm.pid = (HANDLE)pID;
		rpm.SourceAddress = (PVOID)lpBaseAddress;
		rpm.TargetAddress = lpBuffer;
		rpm.Size = nSize;
		HANDLE hDevice = INVALID_HANDLE_VALUE;
		BOOL bResult = FALSE;
		DWORD junk = 0;

		hDevice = CreateFileW(DRIVER_NAME, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);            // do not copy file attributes

		if (hDevice != INVALID_HANDLE_VALUE) {
			bResult = DeviceIoControl(hDevice, IOCTL_WRITE_MEM, &rpm, sizeof(rpm), lpBuffer, nSize, &junk, (LPOVERLAPPED)NULL);
			CloseHandle(hDevice);
			return false;
		}
	}
	return true;
}

