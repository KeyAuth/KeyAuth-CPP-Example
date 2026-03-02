#pragma once

#include <filesystem>
#include <fstream>
#include <string>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

inline std::string ReadFromJson(const std::string& path, const std::string& section)
{
	if (!std::filesystem::exists(path))
		return "";
	std::ifstream file(path);
	if (!file.good())
		return "";
	json data = json::parse(file, nullptr, false);
	if (data.is_discarded() || !data.contains(section))
		return "";
	return data[section];
}

inline bool WriteToJson(const std::string& path, const std::string& name, const std::string& value, bool userpass,
	const std::string& name2, const std::string& value2)
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
		return false;
	jsonfile << file;
	jsonfile.flush();
	if (!jsonfile.good() || !std::filesystem::exists(path))
		return false;

	return true;
}
