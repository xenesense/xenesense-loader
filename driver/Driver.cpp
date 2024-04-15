#include "Driver.h"

Driver::Driver(const wchar_t* driver_name, int target_process_id)
{
	this->driver_handle = CreateFileW(driver_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	this->target_process_id = target_process_id; // yes i am lazy
}
Driver::~Driver()
{
	CloseHandle(driver_handle);
}
uintptr_t Driver::get_base_address(const std::string& module_name)
{
	base_request req;
	req.pid = target_process_id;
	req.handle = 0;
	std::wstring wstr{ std::wstring(module_name.begin(), module_name.end()) };
	memset(req.name, 0, sizeof(WCHAR) * 260);
	wcscpy(req.name, wstr.c_str());
	DWORD bytes_read;
	if (DeviceIoControl(driver_handle, BASE_CODE, &req,
		sizeof(base_request), &req, sizeof(base_request), &bytes_read, 0)) {
        std::cout << "nigga1" << bytes_read << std::endl;
        std::cout << "nigga1" << req.handle << std::endl;
		return req.handle;
	}
    std::cout << "nigga" << std::endl;
	return req.handle;
}

uintptr_t Driver::get_base_address2(const std::string& module_name)
{
    if (!driver_handle) return 0;
    base_request req;
    req.pid = this->target_process_id;
    req.handle = 0;
    std::wstring wstr{ std::wstring(module_name.begin(), module_name.end()) };
    memset(req.name, 0, sizeof(WCHAR) * 260);
    wcscpy(req.name, wstr.c_str());
    DWORD bytes_read;
    if (DeviceIoControl(driver_handle, BASE86_CODE, &req,
        sizeof(base_request), &req, sizeof(base_request), &bytes_read, 0)) {
        return req.handle;
    }
    return req.handle;
}



bool Driver::write_memory(uintptr_t destination, uintptr_t source, int size)
{

	if (driver_handle == INVALID_HANDLE_VALUE) return 0;
	rw_request request{ target_process_id, destination, source, size, TRUE };
	DWORD bytes_read;
	DeviceIoControl(driver_handle, RW_CODE, &request, sizeof(rw_request), 0, 0, &bytes_read, 0);
	return true;
}
bool Driver::read_memory(uintptr_t source, uintptr_t destination, int size)
{
	if (driver_handle == INVALID_HANDLE_VALUE) return 0;
	rw_request request{ target_process_id, source, destination, size, FALSE };
	DWORD bytes_read;
	DeviceIoControl(driver_handle, RW_CODE, &request, sizeof(rw_request), 0, 0, &bytes_read, 0);

	return true;
}

bool Driver::protect_virtual_memory(uintptr_t address, size_t size, DWORD protect_type, int old_protection)
{
	protect_mem_request request{ target_process_id, protect_type, address, size };
	DWORD bytes_read;
	if (!DeviceIoControl(driver_handle, PROTECT_CODE, &request, sizeof(protect_mem_request), 0, 0, &bytes_read, 0)) {
		return false;
	}
	


	return true;
}

void Driver::set_dtb(uintptr_t new_cr3) {
    init_request req;
    req.cr3 = new_cr3;


    DWORD bytes_read;
    DeviceIoControl(driver_handle, INITIAL_CODE, &req, sizeof(init_request), 0, 0, &bytes_read, 0);

}

uintptr_t Driver::translate_address(uintptr_t virtual_address, uintptr_t directory_base) {
    tr_request req;
    req.virtual_address = virtual_address;
    req.directory_base = directory_base;
    req.physical_address = 0;
    DWORD bytes_read;
    if (DeviceIoControl(driver_handle, TR_CODE, &req,
        sizeof(tr_request), &req, sizeof(tr_request), &bytes_read, 0)) {
        return (uintptr_t)req.physical_address;
    }
    return (uintptr_t)req.physical_address;
}


uintptr_t Driver::get_dtb(ULONG pid) {
    dtb_request req;
    req.pid = pid;
    req.output = 0;
    DWORD bytes_read;
    if (DeviceIoControl(driver_handle, DTB_CODE, &req,
        sizeof(dtb_request), &req, sizeof(dtb_request), &bytes_read, 0)) {
        return (uintptr_t)req.output;
    }
    return (uintptr_t)req.output;
}


/*typedef struct _PROTECT_MEM {
    int pid, protect;
    ULONGLONG addr;
    SIZE_T size;
} PROTECT_MEM, * PPROTECT_MEM;

typedef struct _COPY_MEMORY {
    ULONG ProcessId;
    PVOID Destination;
    PVOID Source;
    SIZE_T Size;
} COPY_MEMORY, * PCOPY_MEMORY;
typedef struct _ALLOC_MEM {
    int procid, protect, allocation_type;
    uintptr_t addr;
    SIZE_T size;
} ALLOC_MEM, * PALLOC_MEM;
typedef struct _MODULE_BASE {
    ULONG ProcessId;
    WCHAR name[260];
    PVOID Base;
} MODULE_BASE, * PMODULE_BASE;

typedef struct _REQUEST {
    UINT32 Type;
    PVOID Instruction;
} REQUEST, * PREQUEST;
void ReadWriteRegistry(uint32_t type, void* instruction) {

    HKEY hKey = NULL;
    void* pointer = NULL;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, ("Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers"), 0, KEY_ALL_ACCESS, &hKey);
    if (hKey != NULL && hKey != INVALID_HANDLE_VALUE) {

        auto SetRegistryValue = [&](BYTE* pointer, SIZE_T size, DWORD Type) -> BOOL
        {
            if (RegSetValueExA(hKey, ("zanegoescrazy"), 0, Type, reinterpret_cast<BYTE*>(pointer), size) == ERROR_SUCCESS)
            {
                RegDeleteValueA(hKey, ("zanegoescrazy"));
                RegCloseKey(hKey);
                return TRUE;
            }
            return FALSE;
        };

        REQUEST request;

        request.Type = type;
        request.Instruction = instruction;

        pointer = &request;
        SetRegistryValue(reinterpret_cast<BYTE*>(&pointer), sizeof uintptr_t, REG_QWORD);
    }
}
int pid;
Driver::Driver(const wchar_t* driver_name, int target_process_id)
{

    this->target_process_id = target_process_id; // yes i am lazy
}

Driver::~Driver()
{
    CloseHandle(driver_handle);
}

uintptr_t Driver::get_base_address(LPCWSTR module_name) {

    MODULE_BASE Request;

    Request.ProcessId = this->target_process_id;
    memset(Request.name, 0, sizeof(WCHAR) * 260);
    wcscpy(Request.name, module_name);
    ReadWriteRegistry(3, &Request);

    return reinterpret_cast<uint64_t>(Request.Base);
}

bool Driver::write_memory(uintptr_t destination, uintptr_t source, int size)
{
    COPY_MEMORY m;
    m.ProcessId = this->target_process_id;
    m.Source = (PVOID)source;
    m.Destination = (PVOID)destination;
    m.Size = size;

    ReadWriteRegistry(2, &m);

    return true;
}
bool Driver::read_memory(uintptr_t source, uintptr_t destination, int size)
{
    COPY_MEMORY Request;
    Request.ProcessId = this->target_process_id;
    Request.Source = reinterpret_cast<void*>(source);
    Request.Destination = (PVOID)destination;
    Request.Size = size;

    ReadWriteRegistry(1, &Request);
    return true;
}



bool Driver::protect_virtual_memory(uintptr_t address, int size, DWORD protect_type)
{

    PROTECT_MEM Request;
    sizeof(PROTECT_MEM);
    Request.pid = this->target_process_id;
    Request.addr = address;
    Request.protect = protect_type;
    Request.size = size;

    ReadWriteRegistry(5, &Request);
    return 1;

}*/

