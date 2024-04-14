#pragma once
#pragma once
#include <Windows.h>
#include <string>
#include <filesystem>

namespace service
{
	inline char driver_name[100] = {};

	bool RegisterAndStart(const std::wstring& driver_path);
	bool StopAndRemove(const std::wstring& driver_name);
	bool UnloadSignedDriver();
	std::wstring GetFullTempPath();
};