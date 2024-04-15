#pragma once
#include "../includes.h"

class Driver
{
public:
	Driver(const wchar_t* driver_name, int target_process_id);
	~Driver();
	uintptr_t get_base_address(const std::string& module_name);
	uintptr_t get_base_address2(const std::string& module_name);
    //bool protect_virtual_memory(uintptr_t address, int size, DWORD protect_type);
    bool protect_virtual_memory(uintptr_t address, size_t size, DWORD protect_type, int old_protection = 0);
    bool write_memory(uintptr_t destination, uintptr_t source, int size);
    bool read_memory(uintptr_t source, uintptr_t destination, int size);
    void set_dtb(uintptr_t new_cr3);
    uintptr_t translate_address(uintptr_t virtual_address, uintptr_t directory_base);
    uintptr_t get_dtb(ULONG pid);

    template <typename T>
    inline T readv(uintptr_t src, size_t size = sizeof(T))
    {
        T buffer;
        read_memory(src, (uintptr_t)&buffer, size);
        return buffer;
    }


    HANDLE driver_handle;
    int target_process_id;
private:

    /*
            Driver Structs
    */
    typedef struct _KERNEL_RW_REQUEST {
        ULONG pid;
        ULONGLONG src;
        ULONGLONG dst;
        ULONGLONG size;
        BOOLEAN write;
    } rw_request, * prw_request;

    typedef struct _KERNEL_BOX_REQUEST {
        int r, g, b, x, y, w, h, t;
    } box_request, * pbox_request;

    typedef struct _GUARDED_REGION_REQUEST {
        uintptr_t allocation;
    } gr_request, * pgr_request;

    typedef struct _KERNEL_PROT_REQUEST {
        ULONG pid, protect;
        ULONGLONG addr;
        SIZE_T size;
    } protect_mem_request, * pprotect_mem_request;

    typedef struct _KERNEL_BASE_REQUEST {
        ULONG pid;
        ULONGLONG handle;
        WCHAR name[260];
    } base_request, * pbase_request;


    typedef struct _KERNEL_INIT_REQUEST {
        ULONGLONG cr3;
    } init_request, * pinit_request;

    typedef struct _KERNEL_DTB_REQUEST {
        ULONG pid;
        ULONGLONG output;
    } dtb_request, * pdtb_request;

    typedef struct _KERNEL_TR_REQUEST {
        uintptr_t virtual_address;
        uintptr_t directory_base;
        void* physical_address;
    }tr_request, * ptr_request;

    /*
        Driver IOCTL codes
    */
    #define PHYS_RW_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3881, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define RW_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3882, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define DRAW_BOX_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3883, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define GUARDED_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3884, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define BASE_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3885, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define BASE86_CODE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3887, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define PROTECT_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3890, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define INITIAL_CODE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3999, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define DTB_CODE	  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3895, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
    #define TR_CODE		  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)  
};
