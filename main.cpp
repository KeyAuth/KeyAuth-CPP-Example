#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
using namespace KeyAuth;
std::string tm_to_readable_time(tm ctx);

/*
*
*
* WATCH THIS VIDEO FOR SETUP TUTORIAL: https://youtube.com/watch?v=uJ0Umy_C6Fg
* DO NOT CONTACT DISMAIL WITHOUT WATCHING VIDEO FIRST
*
*/

std::string name = ("");
std::string ownerid = ("");
std::string secret = ("");
std::string version = ("1.0");

api KeyAuthApp(name, ownerid, secret, version);

int main()
{
	SetConsoleTitleA(XorStr("Loader").c_str());
	std::cout << XorStr("\n\n Connecting..");
	KeyAuthApp.init(); // required
	system(XorStr("cls").c_str());
	
	std::cout << XorStr("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

	int option;
	std::string username;
	std::string password;
	std::string key;

	std::cin >> option;
	switch (option)
	{
		case 1:
			std::cout << XorStr("\n\n Enter username: ");
			std::cin >> username;
			std::cout << XorStr("\n Enter password: ");
			std::cin >> password;
			KeyAuthApp.login(username, password);
			break;
		case 2:
			std::cout << XorStr("\n\n Enter username: ");
			std::cin >> username;
			std::cout << XorStr("\n Enter password: ");
			std::cin >> password;
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.regstr(username,password,key);
			break;
		case 3:
			std::cout << XorStr("\n\n Enter username: ");
			std::cin >> username;
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.upgrade(username, key);
			break;
		case 4:
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.license(key);
			break;
		default:
			std::cout << XorStr("\n\n Status: Failure: Invalid Selection");
			Sleep(3000);
			exit(0);
	}

	/*
	KeyAuthApp.Memory("231696", "C:\\Users\\mak\\Downloads\\keyauth_example\\x64\\Release\\DLL.dll"); // download file to disk
	KeyAuthApp.Memory("231696", NULL, true); // download file to byte array
	*/

	Sleep(-1); // this is to keep your application open for test purposes. it pauses your application forever, remove this when you want.
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[25];

	strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

	return std::string(buffer);
}
