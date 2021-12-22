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

	if (KeyAuthApp.checkblack()) // check if user HWID or IP is blacklisted (don't put before init or it won't work)
	{
		exit(0);
	}

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
		KeyAuthApp.regstr(username, password, key);
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

	std::cout << XorStr("\n\n User data:");
	std::cout << XorStr("\n Username: ");
	std::cout << KeyAuthApp.user_data.username;
	std::cout << XorStr("\n IP address: ");
	std::cout << KeyAuthApp.user_data.ip;
	std::cout << XorStr("\n Hardware-Id: ");
	std::cout << KeyAuthApp.user_data.hwid;

	time_t rawtime = mktime(&KeyAuthApp.user_data.createdate);
	struct tm* timeinfo;
	timeinfo = localtime(&rawtime);
	printf(XorStr("\n Created at: %s").c_str(), asctime(timeinfo));

	rawtime = mktime(&KeyAuthApp.user_data.lastlogin);
	timeinfo = localtime(&rawtime);
	printf(XorStr(" Last login at: %s").c_str(), asctime(timeinfo));

	rawtime = mktime(&KeyAuthApp.user_data.expiry);
	timeinfo = localtime(&rawtime);
	printf(XorStr(" Expires At: %s").c_str(), asctime(timeinfo));

	std::cout << XorStr(" Time Left in seconds: ");
	std::cout << KeyAuthApp.user_data.timeleft;
	std::cout << XorStr("\nSubscription Type: ");
	std::cout << KeyAuthApp.user_data.subscription;

	/*
	// download file, change file.exe to whatever you want.
	// remember, certain paths like windows folder will require you to turn on auto run as admin https://stackoverflow.com/a/19617989

	std::vector<std::uint8_t> bytes = KeyAuthApp.download("167212");
	std::ofstream file("file.exe", std::ios_base::out | std::ios_base::binary);
	file.write((char*)bytes.data(), bytes.size());
	file.close();
	*/

	// KeyAuthApp.setvar("discord", "test#0001"); // set the variable 'discord' to 'test#0001'
	// std::cout << KeyAuthApp.getvar("discord"); // display the user variable 'discord'

	// let's say you want to send request to https://keyauth.com/api/seller/?sellerkey=f43795eb89d6060b74cdfc56978155ef&type=black&ip=1.1.1.1&hwid=abc
	// but doing that from inside the loader is a bad idea as the link could get leaked.
	// Instead, you should create a webhook with the https://keyauth.com/api/seller/?sellerkey=f43795eb89d6060b74cdfc56978155ef part as the URL
	// then in your loader, put the rest of the link (the other paramaters) in your loader. And then it will send request from KeyAuth server and return response in string resp
	// std::string resp = KeyAuthApp.webhook("XESXjhZuwN", "&type=black&ip=1.1.1.1&hwid=abc");
	// std::cout << XorStr("\n  Response recieved from webhook request: ");
	// std::cout << resp;

	// KeyAuthApp.log("user logged in"); // send event to logs. if you set discord webhook in app settings, it will send there too
	// KeyAuthApp.ban(); // ban the current user, must be logged in

	std::cout << "\n\n Closing in ten seconds...";
	Sleep(10000);
	exit(0);
}
