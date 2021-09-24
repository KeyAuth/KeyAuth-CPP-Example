#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
using namespace KeyAuth;

/*
*
*
* WATCH THIS VIDEO FOR SETUP TUTORIAL: https://youtube.com/watch?v=uJ0Umy_C6Fg
* DO NOT CONTACT DISMAIL WITHOUT WATCHING VIDEO FIRST
*
*/

std::string name = XorStr(""); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = XorStr(""); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = XorStr(""); // app secret, the blurred text on licenses tab and other tabs
std::string version = XorStr("1.0"); // leave alone unless you've changed version on website

api KeyAuthApp(name, ownerid, secret, version);

int main()
{

	SetConsoleTitleA(XorStr("Loader").c_str());
	std::cout << XorStr("\n\n Connecting..");
	KeyAuthApp.init();
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
	// download file
    std::vector<std::uint8_t> bytes = KeyAuthApp.download("123456");
    std::ofstream file("file.exe", std::ios_base::out | std::ios_base::binary);
    file.write((char*)bytes.data(), bytes.size());
    file.close();
	*/
	
	// KeyAuthApp.log("user logged in"); // send event to logs. if you set discord webhook in app settings, it will send there too
	// KeyAuthApp.webhook("HDb5HiwOSM", "&type=black&ip=1.1.1.1&hwid=abc"); // webhook request to securely send GET request to API, here's what it looks like on dashboard https://i.imgur.com/jW74Hwe.png
	// KeyAuthApp.ban(); // ban the current user, must be logged in

	#pragma region
	time_t rawtime = mktime(&KeyAuthApp.user_data.expiry);
	struct tm* timeinfo;
	timeinfo = localtime(&rawtime);
	printf(XorStr("\n Your Subscription Expires At: %s").c_str(), asctime(timeinfo));
	
	time_t currtime;
	struct tm* tminfo;
	time(&currtime);
	tminfo = localtime(&currtime);

	std::time_t x = std::mktime(tminfo);
	std::time_t y = std::mktime(&KeyAuthApp.user_data.expiry);
	if (x != (std::time_t)(-1) && y != (std::time_t)(-1))
	{
		double difference = std::difftime(y, x) / (60 * 60 * 24);
		std::cout << "\n " << difference << " day(s) left" << std::endl;
	}
	#pragma endregion Display Expiration Date and Days Left Until Expiry
	
	Sleep(-1); // this is to keep your application open for test purposes. it pauses your application forever, remove this when you want.
}
