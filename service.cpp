#include "service.h"
#include "nt.hpp"
#include "sk_crypt.h"
#include "utils/lazy_importer.h"
#include <fstream>
#include <iostream>
bool service::RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;

	std::string t(service::driver_name);
	std::wstring name(t.begin(), t.end());

	const std::wstring driver_name = name;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = SAFE_CALL(RegCreateKeyW)(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		return false;
	}



	status = SAFE_CALL(RegSetKeyValueW)(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		SAFE_CALL(RegCloseKey)(dservice);
		return false;
	}

	status = SAFE_CALL(RegSetKeyValueW)(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		SAFE_CALL(RegCloseKey)(dservice);
		return false;
	}

	SAFE_CALL(RegCloseKey)(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);

	std::cout << Status << std::endl;

	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
		return true;
	}

	return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::wstring& driver_name) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	LSTATUS status = SAFE_CALL(RegOpenKeyW)(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	SAFE_CALL(RegCloseKey)(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	if (st != 0x0) {
		status = SAFE_CALL(RegDeleteTreeW)(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return false; //lets consider unload fail as error because can cause problems with anti cheats later
	}

	status = SAFE_CALL(RegDeleteTreeW)(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return false;
	}

	return true;
}

void generateRandomData(BYTE* buffer, size_t length) {
	for (size_t i = 0; i < length; i++) {
		buffer[i] = static_cast<BYTE>(rand() % 255);
	}
}

void saveToFile(const std::string& filename, BYTE* data, size_t length) {
	FILE* file = fopen(filename.c_str(), "wb");
	if (file == nullptr) {
		return;
	}

	size_t bytesWritten = fwrite(data, sizeof(BYTE), length, file);
	if (bytesWritten != length) {
		
	}

	fclose(file);
}

bool service::UnloadSignedDriver() {

	std::string t(service::driver_name);
	std::wstring name(t.begin(), t.end());

	if (!service::StopAndRemove(name)) {
		return false;
	}


	std::string driver_path = skCrypt("C:\\Windows\\TEMP\\corelele.sys").decrypt();



	int newFileLen = 30900 + (rand() % 2348767 + 56725);
	BYTE* randomData = new BYTE[newFileLen];

	generateRandomData(randomData, newFileLen);
	saveToFile(driver_path, randomData, newFileLen);

	delete[] randomData;


	//unlink the file
	
	SAFE_CALL(system)(skCrypt("del C:\\Windows\\TEMP\\corelele.sys >nul"));

	/*if (remove(_("C:\\Windows\\TEMP\\corelogic.sys")) != 0) {
		return false;
	}*/


	return true;
	
}

std::wstring service::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}
