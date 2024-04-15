#include "Inject.h"

/*
	!!!IMPORTANT!!! for this to work correctly please disable Security Check (/GS-)
*/
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

//keep this 
#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall shellcode()
{
	uintptr_t base = 0x15846254168; // random
	uintptr_t pointer_address = 0x24856841253; // random
	memset((void*)pointer_address, 0x69, 1);

	constexpr char t[] = { 'a', 'a', 'a', '\0'};

	//LI_FN(MessageBoxA)((HWND)0, t, t, 0);

	BYTE* pBase = (BYTE*)base;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;
	
	auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved)>(pBase + pOpt->AddressOfEntryPoint);
	_DllMain(pBase, DLL_PROCESS_ATTACH, 0);

	//auto _DllMain = reinterpret_cast<void(*)()>(pBase + pOpt->AddressOfEntryPoint);
	//_DllMain();
}



bool Inject::inject_module_from_path_to_process_by_name(const wchar_t* module_path, const char* process_name)
{
	int target_process_id = utils::get_pid_from_name(process_name);
	
	if (!target_process_id)
	{
		return false;
	}

	
	auto target_process_hwnd = utils::get_hwnd_of_process_id(target_process_id); // HWND needed for hook
	auto thread_id = GetWindowThreadProcessId(target_process_hwnd, 0); // also needed for hook
	auto nt_dll = LoadLibraryA(xor_a("ntdll.dll"));

	
	uintptr_t target_file = utils::read_file_by_name(module_path);
	//uintptr_t target_file = uintptr_t(module_path);

	if (!target_file)
	{
		
		return false;
	}

	Driver* driver = new Driver(L"\\\\.\\{b78cbd55-a51e-4cc7-b233-bfz7f78dgAf6}", target_process_id);

	PIMAGE_NT_HEADERS nt_header = utils::get_nt_header(target_file);
	
	
	//auto base_address = driver->get_base_address2("FortniteClient-Win64-Shipping.exe");
	//
	//std::cout << "base_address : " << std::hex << base_address << std::endl;
	//
	//system("pause");
	//
	//auto ntdll_address = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntdll.dll"));
	//
	//std::cout << "ntdll_address " << ntdll_address << std::endl;
	//
	//
	//auto current_dtb = driver->get_dtb(GetCurrentProcessId());
	//
	//std::cout << "current_dtb " << current_dtb << std::endl;
	//
	//auto nt_dll_physical = driver->translate_address(
	//	ntdll_address,
	//	current_dtb
	//);
	//
	//std::cout << "nt_dll_physical " << nt_dll_physical << std::endl;
	//
	//
	//uintptr_t actual_dtb = 0;
	//
	//for (std::uintptr_t i = 0; i != 0x50000000; i++)
	//{
	//	std::uintptr_t dtb = i << 12;
	//
	//	if (dtb == current_dtb)
	//		continue;
	//
	//	auto phys_address = driver->translate_address(
	//		ntdll_address,
	//		dtb
	//	);
	//
	//	if (!phys_address)
	//		continue;
	//
	//	if (phys_address == nt_dll_physical)
	//	{
	//		driver->set_dtb(dtb);
	//
	//
	//		const auto bytes = driver->readv<char>(base_address);
	//		if (bytes == 0x4D)
	//		{
	//
	//			//this->dtb = std::move(dtb);
	//			//auto aaa = std::move(dtb);
	//			driver->set_dtb(dtb);
	//			actual_dtb = dtb;
	//			break;
	//		}
	//	}
	//}
	//
	//
	//std::cout << "actual_dtb " << std::hex << actual_dtb << std::endl;

	auto dtb_test = driver->get_dtb(target_process_id);
	//driver->set_dtb(dtb_test);

	
	
	//PBYTE dll_address = (PBYTE)driver->get_base_address(_("d3dcompiler_47.dll")); //fn = d3dcompiler_47;
	//if (!dll_address) {
	//	dll_address = (PBYTE)driver->get_base_address(_("d3dcompiler_43.dll"));
	//}


	PBYTE dll_address = (PBYTE)driver->get_base_address("libvorbis_64.dll"); //fn = DirectML;
	uintptr_t discordhook = driver->get_base_address("DiscordHook64.dll");

	uintptr_t hijack_pointer = discordhook + 0xFD008;

	uintptr_t shellcode_value_base = uintptr_t(dll_address + 0x1000);
	uintptr_t shellcode_base = uintptr_t(dll_address + 0x2000);
	//uintptr_t dll_base = uintptr_t(dll_address + 0x50000);
	uintptr_t dll_base = uintptr_t(dll_address + 0x3000);
	//std::cout << std::hex << shellcode_value_base << std::endl;

	
	if (!utils::relocate_image((void*)dll_base, (void*)target_file, nt_header)) {
		
	}

	if (!utils::resolve_import((void*)target_file, nt_header)) {
		
	}

	
	driver->protect_virtual_memory(dll_base, nt_header->OptionalHeader.SizeOfImage, PAGE_READWRITE);
	driver->protect_virtual_memory(shellcode_value_base, 0x1000, PAGE_READWRITE);
	
	
	uint64_t a = 0;
	driver->write_memory(shellcode_value_base, (uintptr_t)&a, sizeof(uint64_t));
	
	for (uint64_t i = 0; i < nt_header->OptionalHeader.SizeOfImage; i += 0x1000)
	{
		void* _null = malloc(0x1000); // alloc 1000 bytes
		ZeroMemory(_null, 0x1000); // overwrite with 0
		if (!driver->write_memory((uint64_t)dll_base + i, (uint64_t)_null, 0x1000)) {
			return -2;
		}
	}
	
	
	
	driver->write_memory(dll_base, target_file, 0x1000);
	
	
	
	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);
	for (int i = 0; i != nt_header->FileHeader.NumberOfSections; i++, ++section_header)
	{
	
		if (section_header->SizeOfRawData)
		{
			DWORD protection_before = utils::get_page_protection(section_header->Characteristics);
			
			
			if (!driver->protect_virtual_memory(dll_base + section_header->VirtualAddress, section_header->SizeOfRawData, PAGE_READWRITE)) {
				
			}
	
			driver->write_memory(dll_base + section_header->VirtualAddress, target_file + section_header->PointerToRawData, section_header->SizeOfRawData);
	
			if (!driver->protect_virtual_memory(dll_base + section_header->VirtualAddress, section_header->SizeOfRawData, protection_before)) {
	
			}
		}
	}
	
	uintptr_t shellcode_value = shellcode_value_base; // there we set the value to stop the hook once the shellcode is called!
	uintptr_t allocatedbase_offset = uintptr_t((uintptr_t)utils::find_pattern("\x68\x41\x25\x46\x58\x01\x00\x00", "xxxxxx??") - (uintptr_t)&shellcode); //scans the value 0x15846254168 in shellcode
	uintptr_t allocatedvalue_offset = uintptr_t((uintptr_t)utils::find_pattern("\x53\x12\x84\x56\x48\x02\x00\x00", "xxxxxx??") - (uintptr_t)&shellcode); // scans the value 0x24856841253 in shellcode
	if (!allocatedbase_offset || !allocatedvalue_offset)
	{
		return -6;
	}
	
	
	
	driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READWRITE);
	
	auto shellcodefunction_length = utils::get_function_length(&shellcode);
	uintptr_t localshellcodealloc = (uintptr_t)VirtualAlloc(0, shellcodefunction_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	
	memcpy((PVOID)localshellcodealloc, &shellcode, 0x1000);
	
	*(uintptr_t*)(localshellcodealloc + allocatedbase_offset) = dll_base;
	*(uintptr_t*)(localshellcodealloc + allocatedvalue_offset) = shellcode_value;
	
	driver->write_memory(shellcode_base, localshellcodealloc, 0x1000);
	
	driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READWRITE);
		
	driver->protect_virtual_memory((uintptr_t)hijack_pointer, 0x1000, PAGE_EXECUTE_READWRITE);
	
	
	
	uintptr_t original_value;
	driver->read_memory(hijack_pointer, (uintptr_t)&original_value, 0x8);
	
	driver->write_memory(hijack_pointer, (uintptr_t)&shellcode_base, 0x8);
	

	while (true)
	{
		int buffer;
	
		driver->read_memory(shellcode_value, (uintptr_t)&buffer, sizeof(int));
	
	
		if (buffer == 0x69) 
		{
			driver->write_memory(hijack_pointer, (uintptr_t)&original_value, 0x8);

			driver->protect_virtual_memory((uintptr_t)hijack_pointer, 0x1000, PAGE_READONLY);

			//driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READ);
			return true;
		}
	}


	




	//auto win_event_hook = SetWinEventHook(EVENT_MIN, EVENT_MAX, nt_dll, (WINEVENTPROC)shellcode_base, target_process_id, thread_id, WINEVENT_INCONTEXT);
	////printf(xor_a("Hook created at : %p\nWaiting..."), win_event_hook);
	//while (true)
	//{
	//
	//	int buffer;
	//	driver->read_memory(shellcode_value, (uintptr_t)&buffer, sizeof(int));
	//	if (buffer == 0x69) { // if shellcode called
	//		UnhookWinEvent(win_event_hook);
	//		return true;
	//	}
	//}


	//uintptr_t original_value;
	//driver->read_memory(hijack_pointer, (uintptr_t)&original_value, 0x8);
	//
	//driver->write_memory(hijack_pointer, (uintptr_t)&shellcode_base, 0x8);
	//
	//std::cout << " about to executee2 " << std::endl;
	//
	//while (true)
	//
	//{
	//	int buffer;
	//
	//	driver->read_memory(shellcode_value, (uintptr_t)&buffer, sizeof(int));
	//	
	//	std::cout << buffer << std::endl;
	//
	//	if (buffer == 0x69) { // if shellcode called
	//		driver->write_memory(hijack_pointer, (uintptr_t)&original_value, 0x8);
	//		std::cout << "ud" << std::endl;
	//		//driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READ);
	//		break;
	//	}
	//}
	
	
	

	return false;
}

bool Inject::inject_module_from_path_to_process_by_name_fn(BYTE* module_path, const char* process_name)
{
	int target_process_id = utils::get_pid_from_name(process_name);

	if (!target_process_id)
	{
		return false;
	}

	
	auto target_process_hwnd = utils::get_hwnd_of_process_id(target_process_id); // HWND needed for hook
	auto thread_id = GetWindowThreadProcessId(target_process_hwnd, 0); // also needed for hook
	auto nt_dll = LoadLibraryA(xor_a("ntdll.dll"));


	//uintptr_t target_file = utils::read_file_by_name(module_path);
	uintptr_t target_file = uintptr_t(module_path);

	if (!target_file)
	{
		return false;
	}

	Driver* driver = new Driver(L"\\\\.\\{b78cbd55-a51e-4cc7-b233-bfz7f78dgAf6}", target_process_id);


	PIMAGE_NT_HEADERS nt_header = utils::get_nt_header(target_file);
	


	//auto base_address = driver->get_base_address2("a");
	//auto ntdll_address = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(skCrypt("ntdll.dll")));
	//auto current_dtb = driver->get_dtb(GetCurrentProcessId());
	//
	//auto nt_dll_physical = driver->translate_address(
	//	ntdll_address,
	//	current_dtb
	//);
	//
	//
	//
	//for (std::uintptr_t i = 0; i != 0x50000000; i++)
	//{
	//	std::uintptr_t dtb = i << 12;
	//
	//	if (dtb == current_dtb)
	//		continue;
	//
	//	auto phys_address = driver->translate_address(
	//		ntdll_address,
	//		dtb
	//	);
	//
	//	if (!phys_address)
	//		continue;
	//
	//	if (phys_address == nt_dll_physical)
	//	{
	//		driver->set_dtb(dtb);
	//
	//
	//		const auto bytes = driver->readv<char>(base_address);
	//		if (bytes == 0x4D)
	//		{
	//
	//			//this->dtb = std::move(dtb);
	//			//auto aaa = std::move(dtb);
	//			driver->set_dtb(dtb);
	//			break;
	//		}
	//	}
	//}
	
	
	

	auto dtb_test = driver->get_dtb(target_process_id);
	std::cout << std::hex << dtb_test << std::endl;
	
	
	//driver->set_dtb(dtb_test);
	PBYTE dll_address = (PBYTE)driver->get_base_address(_("d3dcompiler_47.dll")); //fn = d3dcompiler_47;
	if (!dll_address) {
		dll_address = (PBYTE)driver->get_base_address(_("d3dcompiler_43.dll"));
	}


	//PBYTE dll_address = (PBYTE)driver->get_base_address("libvorbis_64.dll"); //fn = DirectML;
	uintptr_t discordhook = driver->get_base_address("DiscordHook64.dll");

	uintptr_t hijack_pointer = discordhook + 0xFD008;


	uintptr_t shellcode_value_base = uintptr_t(dll_address + 0x1000);
	uintptr_t shellcode_base = uintptr_t(dll_address + 0x2000);
	uintptr_t dll_base = uintptr_t(dll_address + 0x50000); 
	//uintptr_t dll_base = uintptr_t(dll_address + 0x3000);
	//std::cout << std::hex << shellcode_value_base << std::endl;



	if (!utils::relocate_image((void*)dll_base, (void*)target_file, nt_header)) {

	}
	if (!utils::resolve_import((void*)target_file, nt_header)) {

	}


	driver->protect_virtual_memory(dll_base, nt_header->OptionalHeader.SizeOfImage, PAGE_READWRITE);
	driver->protect_virtual_memory(shellcode_value_base, 0x1000, PAGE_READWRITE);


	uint64_t a = 0;
	driver->write_memory(shellcode_value_base, (uintptr_t)&a, sizeof(uint64_t));

	for (uint64_t i = 0; i < nt_header->OptionalHeader.SizeOfImage; i += 0x1000)
	{
		void* _null = malloc(0x1000); // alloc 1000 bytes
		ZeroMemory(_null, 0x1000); // overwrite with 0
		if (!driver->write_memory((uint64_t)dll_base + i, (uint64_t)_null, 0x1000)) {
			return -2;
		}
	}



	driver->write_memory(dll_base, target_file, 0x1000);



	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);
	for (int i = 0; i != nt_header->FileHeader.NumberOfSections; i++, ++section_header)
	{

		if (section_header->SizeOfRawData)
		{
			DWORD protection_before = utils::get_page_protection(section_header->Characteristics);


			if (!driver->protect_virtual_memory(dll_base + section_header->VirtualAddress, section_header->SizeOfRawData, PAGE_READWRITE)) {

			}

			driver->write_memory(dll_base + section_header->VirtualAddress, target_file + section_header->PointerToRawData, section_header->SizeOfRawData);

			if (!driver->protect_virtual_memory(dll_base + section_header->VirtualAddress, section_header->SizeOfRawData, protection_before)) {

			}
		}
	}

	uintptr_t shellcode_value = shellcode_value_base; // there we set the value to stop the hook once the shellcode is called!
	uintptr_t allocatedbase_offset = uintptr_t((uintptr_t)utils::find_pattern("\x68\x41\x25\x46\x58\x01\x00\x00", "xxxxxx??") - (uintptr_t)&shellcode); //scans the value 0x15846254168 in shellcode
	uintptr_t allocatedvalue_offset = uintptr_t((uintptr_t)utils::find_pattern("\x53\x12\x84\x56\x48\x02\x00\x00", "xxxxxx??") - (uintptr_t)&shellcode); // scans the value 0x24856841253 in shellcode
	if (!allocatedbase_offset || !allocatedvalue_offset)
	{
		return -6;
	}



	driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READWRITE);

	auto shellcodefunction_length = utils::get_function_length(&shellcode);
	uintptr_t localshellcodealloc = (uintptr_t)VirtualAlloc(0, shellcodefunction_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


	memcpy((PVOID)localshellcodealloc, &shellcode, 0x1000);

	*(uintptr_t*)(localshellcodealloc + allocatedbase_offset) = dll_base;
	*(uintptr_t*)(localshellcodealloc + allocatedvalue_offset) = shellcode_value;

	driver->write_memory(shellcode_base, localshellcodealloc, 0x1000);

	driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READWRITE);
	
	driver->protect_virtual_memory((uintptr_t)hijack_pointer, 0x1000, PAGE_EXECUTE_READWRITE);

	uintptr_t original_value;
	driver->read_memory(hijack_pointer, (uintptr_t)&original_value, 0x8);
	
	driver->write_memory(hijack_pointer, (uintptr_t)&shellcode_base, 0x8);
	
	
	while (true)
	{
		int buffer;
	
		driver->read_memory(shellcode_value, (uintptr_t)&buffer, sizeof(int));
		
	
		if (buffer == 0x69) { // if shellcode called
			driver->write_memory(hijack_pointer, (uintptr_t)&original_value, 0x8);

			driver->protect_virtual_memory((uintptr_t)hijack_pointer, 0x1000, PAGE_READONLY);
			//driver->protect_virtual_memory((uintptr_t)shellcode_base, 0x1000, PAGE_EXECUTE_READ);
			return true;
		}
	}

	//auto win_event_hook = SetWinEventHook(EVENT_MIN, EVENT_MAX, nt_dll, (WINEVENTPROC)shellcode_base, target_process_id, thread_id, WINEVENT_INCONTEXT);
	//while (true)
	//{
	//
	//	int buffer;
	//	driver->read_memory(shellcode_value, (uintptr_t)&buffer, sizeof(int));
	//	if (buffer == 0x69) { // if shellcode called
	//		UnhookWinEvent(win_event_hook);
	//
	//		return true;
	//	}
	//}

	

	return false;
}
