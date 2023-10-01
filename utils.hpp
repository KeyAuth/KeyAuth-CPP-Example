#pragma once
#include <filesystem> 
#include <string> 
#include <fstream>
#include "skStr.h"
#include "json.hpp"
using json = nlohmann::json;

std::string ReadFromJson(std::string path, std::string section) 
{
	if (!std::filesystem::exists(path))
		return skCrypt("File Not Found").decrypt();
	std::ifstream file(path);
	json data = json::parse(file);
	return data[section];
}

bool CheckIfJsonKeyExists(std::string path, std::string section) 
{
	if (!std::filesystem::exists(path))
		return skCrypt("File Not Found").decrypt();
	std::ifstream file(path);
	json data = json::parse(file);
	return data.contains(section);
}

bool WriteToJson(std::string path, std::string key, std::string value, std::string key2 = "", std::string value2 = "") 
{
	json file;
	file[key] = value;
	key2 == "" && value2 == "" ? file[key] = value; : file[key] = value; file[key2] = value2;

	std::ofstream jsonfile(path, std::ios::out);
	jsonfile << file;
	jsonfile.close();
	if (!std::filesystem::exists(path))
		return false;

	return true;
}
