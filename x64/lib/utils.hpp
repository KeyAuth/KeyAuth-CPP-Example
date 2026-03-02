#pragma once
#include <Windows.h>
#include <ctime>
#include <iostream>
#include <string>

namespace utils
{
	std::string get_hwid();
	std::time_t string_to_timet(std::string timestamp);
	std::tm timet_to_tm(time_t timestamp);
}
