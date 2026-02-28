#pragma once
#include "json.hpp"
#include "skStr.h"
#include <filesystem>
#include <fstream>
#include <string>

using json = nlohmann::json; // header-only helpers below. -nigel

inline std::string ReadFromJson(std::string path, std::string section)
{
	if (!std::filesystem::exists(path))
		return ""; // missing file returns empty. -nigel
	std::ifstream file(path);
	if (!file.good())
		return ""; // failed open returns empty. -nigel
	json data = json::parse(file, nullptr, false);
	if (data.is_discarded() || !data.contains(section))
		return ""; // invalid or missing key returns empty. -nigel
	return data[section];
}

inline bool CheckIfJsonKeyExists(std::string path, std::string section)
{
	if (!std::filesystem::exists(path))
		return false; // missing file means no key. -nigel
	std::ifstream file(path);
	if (!file.good())
		return false; // failed open means no key. -nigel
	json data = json::parse(file, nullptr, false);
	if (data.is_discarded())
		return false; // invalid json means no key. -nigel
	return data.contains(section);
}

inline bool WriteToJson(std::string path, std::string name, std::string value, bool userpass, std::string name2, std::string value2)
{
	json file;
	if (!userpass)
	{
		file[name] = value;
	}
	else
	{
		file[name] = value;
		file[name2] = value2;
	}

	std::ofstream jsonfile(path, std::ios::out | std::ios::trunc);
	if (!jsonfile.good())
		return false; // failed open means no write. -nigel
	jsonfile << file;
	jsonfile.flush();
	if (!jsonfile.good() || !std::filesystem::exists(path))
		return false;

	return true;
}
