#pragma once
#include <windows.h>
#include <iostream>
#include <psapi.h>

// https://github.com/LiamG53

namespace protection
{
	enum types
	{
		search = EXCEPTION_CONTINUE_SEARCH,
		page_guard_violation = STATUS_GUARD_PAGE_VIOLATION,
		break_point = STATUS_BREAKPOINT,
		long_jump = STATUS_LONGJUMP
	};

	// helper function to determine wether or not the address is within the current module/handle.
	bool within_region(HMODULE module, LPVOID address)
	{
		MODULEINFO info; // place holder for the information

		// use this function in order to get the module information.
		bool result = GetModuleInformation(GetCurrentProcess(),
			module, &info, sizeof(info));
		if (result)
		{
			LPVOID module_base = info.lpBaseOfDll;
			size_t module_size = info.SizeOfImage;
			
			// return wether not the module is within the means of the current image size and base.
			return (address >= module_base && 
				address < (PBYTE)module_base + module_size);
		}
		return false; // failed to get the information.
	}

	long handler(EXCEPTION_POINTERS *info)
	{
		// place holder for the current module, in regards with our regional memory checks.
		static auto current_module = 
			GetModuleHandleA(0);
		if (!current_module)
		{
			// throw a random page guard violation causing the application to most likely crash
			return types::page_guard_violation;
		}

		// get the return address for this context.
#ifdef _WIN64
		auto return_address = info->ContextRecord->Rip;
		if (return_address != info->ContextRecord->Rip)
		{
			// tampered with the return address via an external process or via byte patching.
			//  either way we will detect it.
			return types::page_guard_violation;
		}

		// check if the return address is within the region of our process memory.
		if (!within_region(current_module,
			reinterpret_cast<LPVOID>(return_address)))
		{
			return types::page_guard_violation;
		}
#else
		auto return_address = info->ContextRecord->Eip;
		if (return_address != info->ContextRecord->Eip)
		{
			// tampered with the return address via an external process or via byte patching.
			//  either way we will detect it.
			return types::page_guard_violation;
		}

		// check if the return address is within the region of our process memory.
		if (!within_region(current_module,
			reinterpret_cast<LPVOID>(return_address)))
		{
			return types::page_guard_violation;
		}
#endif

		// check for long jumps if they are within the modules memory
		if (info->ExceptionRecord->ExceptionCode == types::long_jump)
		{
			if (!within_region(current_module,
				reinterpret_cast<LPVOID>(info->ExceptionRecord->ExceptionAddress)))
			{
				return types::page_guard_violation;
			}
		}
		
		// check breakpoints because some people like writing bytes which are weird
		if (info->ExceptionRecord->ExceptionCode == types::break_point)
		{
			if (!within_region(current_module,
				reinterpret_cast<LPVOID>(info->ExceptionRecord->ExceptionAddress)))
			{
				return types::page_guard_violation;
			}
		}
		
		// continue on with the search
		return types::search;
	}

	void init()
	{
		AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)handler);
	}
};
