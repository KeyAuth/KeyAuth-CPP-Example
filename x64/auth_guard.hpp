#pragma once

#include <Windows.h>
#include <string>

inline void checkAuthenticated(const std::string& ownerid) {
	while (true) {
		if (GlobalFindAtomA(ownerid.c_str()) == 0) {
			exit(13);
		}
		Sleep(1000);
	}
}
