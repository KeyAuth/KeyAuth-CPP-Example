#include "utils.hpp"

#include <atlsecurity.h> 

std::string utils::get_hwid() {
	ATL::CAccessToken accessToken;
	ATL::CSid currentUserSid;
	if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
		accessToken.GetUser(&currentUserSid))
		return std::string(CT2A(currentUserSid.Sid()));
	return "none";
}

std::time_t utils::string_to_timet(std::string timestamp) {
	char* end = nullptr;
	auto cv = strtol(timestamp.c_str(), &end, 10);
	if (end == timestamp.c_str())
		return 0;
	return static_cast<time_t>(cv);
}

std::tm utils::timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
