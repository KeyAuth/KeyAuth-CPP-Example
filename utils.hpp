#pragma once
#include <filesystem> 
#include <string> 
#include <fstream>
#include "skStr.h"
#include "json.hpp"
using json = nlohmann::json;

std::string LoginFromFileWithUser(std::string path) 
{
	if (!std::filesystem::exists(path))
		return skCrypt("File Not Found").decrypt();
	std::ifstream file(path);
	json data = json::parse(file);
	std::string user = data.value(skCrypt("username").decrypt(), skCrypt("Error 505").decrypt());
	if (user == "Error 505")
	{
		return skCrypt("Failed").decrypt();
	}
	else
	{
		return user;
	}
}

std::string LoginFromFileWithPass(std::string path)
{
	if (!std::filesystem::exists(path))
		return skCrypt("File Not Found").decrypt();
	std::ifstream file(path);
	json data = json::parse(file);
	std::string pass = data.value(skCrypt("password").decrypt(), skCrypt("Error 505").decrypt());
	if (pass == "Error 505")
	{
		return skCrypt("Failed").decrypt();
	}
	else
	{
		return pass;
	}
}

std::string LoginFromFileWithKey(std::string path)
{
	if (!std::filesystem::exists(path))
		return skCrypt("File Not Found").decrypt();
	std::ifstream file(path);
	json data = json::parse(file);
	std::string key = data.value(skCrypt("License").decrypt(), skCrypt("Error 505").decrypt());
	if (key == "Error 505")
	{
		return skCrypt("Failed").decrypt();
	}
	else
	{
		return key;
	}
}

std::string WriteUserPass(std::string path, std::string username, std::string password)
{
	std::string json2 = "{\"username\": " "\"" + username + "\"" ",\"password\": " "\"" + password + "\"" "}";
	std::ofstream file(path, std::ios::out);
	file << json2;
	file.close();
	if (!std::filesystem::exists(path))
		return skCrypt("Failed To Create File").decrypt();
	else
		return skCrypt("Successfully Created").decrypt();
}

std::string WriteKey(std::string path, std::string license)
{
	std::ofstream file(path, std::ios::out);
	file << "{\"License\": " "\"" + license + "\"" + "}";
	file.close();

	if (!std::filesystem::exists(path))
		return skCrypt("Failed To Create File").decrypt();
	else
		return skCrypt("Successfully Created").decrypt();
}