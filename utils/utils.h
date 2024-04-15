#pragma once


namespace utils
{
	inline int get_pid_from_name(const char* name)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		Process32First(snapshot, &entry);
		do
		{
			if (strcmp(entry.szExeFile, name) == 0)
			{
				return entry.th32ProcessID;
			}

		} while (Process32Next(snapshot, &entry));

		return 0; // if not found
	}
	inline uintptr_t read_file_by_name(const wchar_t* file_path)
	{
		HANDLE h_dll = CreateFileW(file_path ,GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (h_dll == INVALID_HANDLE_VALUE) return 0;
		int file_size = GetFileSize(h_dll, 0);
		PVOID buffer = VirtualAlloc(0, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!ReadFile(h_dll, buffer, file_size, 0, FALSE) || *(int*)(buffer) != 9460301) // MZ CHECK
		{
		
			CloseHandle(h_dll);
			VirtualFree(buffer,0, MEM_RELEASE);
			return 0;
		}
		else
		{
			CloseHandle(h_dll);
			return (uintptr_t)buffer;
		}
	}
	inline PIMAGE_NT_HEADERS get_nt_header(uintptr_t base)
	{
		PIMAGE_DOS_HEADER dos_headers = PIMAGE_DOS_HEADER(base);
		return PIMAGE_NT_HEADERS(base + dos_headers->e_lfanew);
	}
	inline bool mask_compare(void* buffer, const char* pattern, const char* mask)
	{
		for (auto b = reinterpret_cast<PBYTE>(buffer); *mask; ++pattern, ++mask, ++b)
		{
			if (*mask == 'x' && *reinterpret_cast<LPCBYTE>(pattern) != *b)
			{
				return FALSE;
			}
		}
		return TRUE;
	}
	inline PBYTE find_pattern(const char* pattern, const char* mask)
	{
		MODULEINFO info = {0};
		GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(0), &info, sizeof(info));
		info.SizeOfImage -= static_cast<DWORD>(strlen(mask));
		for (auto i = 0UL; i < info.SizeOfImage; i++)
		{
			auto addr = reinterpret_cast<PBYTE>(info.lpBaseOfDll) + i;
			if (mask_compare(addr, pattern, mask))
			{
				return addr;
			}
		}
	}
	inline int get_function_length(void* funcaddress)
	{
		int length = 0;
		for (length = 0; *((UINT32*)(&((unsigned char*)funcaddress)[length])) != 0xCCCCCCCC; ++length);
		return length;
	}
	inline HWND hwndout;
	inline BOOL EnumWindowProcMy(HWND input, LPARAM lParam)
	{
	
		DWORD lpdwProcessId;
		GetWindowThreadProcessId(input, &lpdwProcessId);
		if (lpdwProcessId == lParam)
		{
			hwndout = input;
			return FALSE;
		}
		return true;
	}
	inline HWND get_hwnd_of_process_id(int target_process_id)
	{
		EnumWindows(EnumWindowProcMy, target_process_id);
		return hwndout;
	}
	inline DWORD get_page_protection(DWORD section_characteristics)
	{
		DWORD page_protection = 0;

		if (section_characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (section_characteristics & IMAGE_SCN_MEM_WRITE)
			{
				page_protection = PAGE_EXECUTE_READWRITE;
			}
			else if (section_characteristics & IMAGE_SCN_MEM_READ)
			{
				page_protection = PAGE_EXECUTE_READ;
			}
			else
			{
				page_protection = PAGE_EXECUTE;
			}
		}
		else if (section_characteristics & IMAGE_SCN_MEM_WRITE)
		{
			if (section_characteristics & IMAGE_SCN_MEM_READ)
			{
				page_protection = PAGE_READWRITE;
			}
			else
			{
				page_protection = PAGE_WRITECOPY;
			}
		}
		else if (section_characteristics & IMAGE_SCN_MEM_READ)
		{
			page_protection = PAGE_READONLY;
		}

		return page_protection;
	}

	inline auto rva_va(const std::uintptr_t rva, IMAGE_NT_HEADERS* nt_header, void* local_image) -> void*
	{
		const auto first_section = IMAGE_FIRST_SECTION(nt_header);

		for (auto section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++)
		{
			if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
			{
				return (unsigned char*)local_image + section->PointerToRawData + (rva - section->VirtualAddress);
			}
		}

		return 0;
	}

	inline auto relocate_image(void* remote_image, void* local_image, IMAGE_NT_HEADERS* nt_header) -> bool
	{
		typedef struct _RELOC_ENTRY
		{
			ULONG ToRVA;
			ULONG Size;
			struct
			{
				WORD Offset : 12;
				WORD Type : 4;
			} Item[1];
		} RELOC_ENTRY, * PRELOC_ENTRY;

		const auto delta_offset = (std::uintptr_t)remote_image - nt_header->OptionalHeader.ImageBase;

		if (!delta_offset)
		{
			return true;
		}

		else if (!(nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
		{
			return false;
		}

		auto relocation_entry = (RELOC_ENTRY*)rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, local_image);
		const auto relocation_end = (std::uintptr_t)relocation_entry + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (relocation_entry == nullptr)
		{
			return true;
		}

		while ((std::uintptr_t)relocation_entry < relocation_end && relocation_entry->Size)
		{
			auto records_count = (relocation_entry->Size - 8) >> 1;

			for (auto i = 0ul; i < records_count; i++)
			{
				WORD fixed_type = (relocation_entry->Item[i].Type);
				WORD shift_delta = (relocation_entry->Item[i].Offset) % 4096;

				if (fixed_type == IMAGE_REL_BASED_ABSOLUTE)
				{
					continue;
				}

				if (fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64)
				{
					auto fixed_va = (std::uintptr_t)rva_va(relocation_entry->ToRVA, nt_header, local_image);

					if (!fixed_va)
					{
						fixed_va = (std::uintptr_t)local_image;
					}

					*(std::uintptr_t*)(fixed_va + shift_delta) += delta_offset;
				}
			}

			relocation_entry = (PRELOC_ENTRY)((LPBYTE)relocation_entry + relocation_entry->Size);
		}

		return true;
	}

	inline auto resolve_function_address(LPCSTR module_name, LPCSTR function_name) -> std::uintptr_t
	{
		const auto handle = LoadLibraryExA(module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);

		const auto offset = (std::uintptr_t)GetProcAddress(handle, function_name) - (std::uintptr_t)handle;

		FreeLibrary(handle);

		return offset;
	}


	inline auto resolve_import(void* local_image, IMAGE_NT_HEADERS* nt_header) -> bool
	{


		IMAGE_IMPORT_DESCRIPTOR* import_description = (IMAGE_IMPORT_DESCRIPTOR*)rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_header, local_image);

		if (!nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			return true;
		}

		LPSTR module_name = NULL;


		while ((module_name = (LPSTR)rva_va(import_description->Name, nt_header, local_image)))
		{
			int imports = 0;
			//const auto base_image = (uintptr_t)remote_call_load_lib(driver_pointer, threadId, module_name, shellcode_base);
			const auto base_image = (uintptr_t)LoadLibraryA(module_name);

			if (!base_image)
			{
				return false;
			}

			auto import_header_data = (IMAGE_THUNK_DATA*)rva_va(import_description->FirstThunk, nt_header, local_image);

			while (import_header_data->u1.AddressOfData)
			{
				if (import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)(import_header_data->u1.Ordinal & 0xFFFF));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)rva_va(import_header_data->u1.AddressOfData, nt_header, local_image);
					import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)ibn->Name);
				}
				import_header_data++;
				imports++;
			}
			import_description++;

			std::cout << "[+] Resolved " << imports << " import(s) in " << module_name << std::endl;
		}



		return true;
	}

}