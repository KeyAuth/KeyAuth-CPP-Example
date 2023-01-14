#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "utils.hpp"
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;

std::string name = ""; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = ""; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = ""; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website
std::string url = "https://keyauth.win/api/1.2/"; // change if you're self-hosting

/*
	Video on what ownerid and secret are https://youtu.be/uJ0Umy_C6Fg

	Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA

	Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version, url);

int main()
{
	SetConsoleTitleA(skCrypt("Loader"));
	std::cout << skCrypt("\n\n Connecting..");
	KeyAuthApp.init();
	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	/*
		Optional - check if HWID or IP blacklisted

	if (KeyAuthApp.checkblack()) {
		abort();
	}
	*/

	std::cout << skCrypt("\n\n App data:");
	std::cout << skCrypt("\n Number of users: ") << KeyAuthApp.data.numUsers;
	std::cout << skCrypt("\n Number of online users: ") << KeyAuthApp.data.numOnlineUsers;
	std::cout << skCrypt("\n Number of keys: ") << KeyAuthApp.data.numKeys;
	std::cout << skCrypt("\n Application Version: ") << KeyAuthApp.data.version;
	std::cout << skCrypt("\n Customer panel link: ") << KeyAuthApp.data.customerPanelLink;
	std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
	KeyAuthApp.check();
	std::cout << skCrypt("\n Current Session Validation Status: ") << KeyAuthApp.data.message;

	if (std::filesystem::exists("test.json")) //change test.txt to the path of your file :smile:
	{
		if (LoginFromFileWithUser("test.json") == "Failed") 
		{
			std::string key = LoginFromFileWithKey("test.json");
			KeyAuthApp.license(key);
			if (!KeyAuthApp.data.success)
			{
				std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
				Sleep(1500);
				exit(0);
			}
			std::cout << skCrypt("\nSuccessfully Automatically Logged In");
		}
		else
		{
			std::string username = LoginFromFileWithUser("test.json");
			std::string password = LoginFromFileWithPass("test.json");
			KeyAuthApp.login(username, password);
			if (!KeyAuthApp.data.success)
			{
				std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
				Sleep(1500);
				exit(0);
			}
			std::cout << skCrypt("\nSuccessfully Automatically Logged In");
		}
		//KeyAuthApp.log("Someone has Logged in")
	}
	else
	{
		std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

		int option;
		std::string username;
		std::string password;
		std::string key;

		std::cin >> option;
		switch (option)
		{
		case 1:
			std::cout << skCrypt("\n\n Enter username: ");
			std::cin >> username;
			std::cout << skCrypt("\n Enter password: ");
			std::cin >> password;
			KeyAuthApp.login(username, password);
			break;
		case 2:
			std::cout << skCrypt("\n\n Enter username: ");
			std::cin >> username;
			std::cout << skCrypt("\n Enter password: ");
			std::cin >> password;
			std::cout << skCrypt("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.regstr(username, password, key);
			break;
		case 3:
			std::cout << skCrypt("\n\n Enter username: ");
			std::cin >> username;
			std::cout << skCrypt("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.upgrade(username, key);
			break;
		case 4:
			std::cout << skCrypt("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.license(key);
			break;
		default:
			std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
			Sleep(3000);
			exit(0);
		}

		if (!KeyAuthApp.data.success)
		{
			std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
			Sleep(1500);
			exit(0);
		}
		if (username.empty() || password.empty())
		{
			WriteKey("test.json", key);
			std::cout << skCrypt("Successfully Created File For Auto Login");
		}
		else
		{
			WriteUserPass("test.json", username, password);
			std::cout << skCrypt("Successfully Created File For Auto Login");
		}


	}
	
	std::cout << skCrypt("\n User data:");
	std::cout << skCrypt("\n Username: ") << KeyAuthApp.data.username;
	std::cout << skCrypt("\n IP address: ") << KeyAuthApp.data.ip;
	std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.data.hwid;
	std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.createdate)));
	std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.lastlogin)));
	std::cout << skCrypt("\n Subscription name(s): ");
	std::string subs;
	for (std::string value : KeyAuthApp.data.subscriptions)subs += value + " ";
	std::cout << subs;
	std::cout << skCrypt("\n Subscription expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.expiry)));
	std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
	KeyAuthApp.check();
	std::cout << skCrypt("\n Current Session Validation Status: ") << KeyAuthApp.data.message;
	
	/*
	std::cout << "\n Waiting for user to login";
	KeyAuthApp.web_login();

	std::cout << "\n Waiting for button to be clicked";
	KeyAuthApp.button("close");
	*/

	/*
	for (std::string subs : KeyAuthApp.data.subscriptions)
	{
		if (subs == "default")
		{
			std::cout << skCrypt("\n User has subscription with name: default");
		}
	}
	*/

	
	/*
	// download file, change file.exe to whatever you want.
	// remember, certain paths like windows folder will require you to turn on auto run as admin https://stackoverflow.com/a/19617989

	std::vector<std::uint8_t> bytes = KeyAuthApp.download("362906");

	if (!KeyAuthApp.data.success) // check whether file downloaded correctly
	{
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file("file.dll", std::ios_base::out | std::ios_base::binary);
	file.write((char*)bytes.data(), bytes.size());
	file.close();
	*/
	

	// KeyAuthApp.setvar("discord", "test#0001"); // set the value of user variable 'discord' to 'test#0001'
	// std::cout << "\n user variable - " + KeyAuthApp.getvar("discord"); // get value of the user variable 'discord'
	
	// let's say you want to send request to https://keyauth.win/api/seller/?sellerkey=f43795eb89d6060b74cdfc56978155ef&type=black&ip=1.1.1.1&hwid=abc
	// but doing that from inside the loader is a bad idea as the link could get leaked.
	// Instead, you should create a webhook with the https://keyauth.win/api/seller/?sellerkey=f43795eb89d6060b74cdfc56978155ef part as the URL
	// then in your loader, put the rest of the link (the other paramaters) in your loader. And then it will send request from KeyAuth server and return response in string resp
	
	/*
	// you have to replace the & sign with %26
	// you have to replace the = sign with %3D
	std::string resp = KeyAuthApp.webhook("Sh1j25S5iX", "");
	if (!KeyAuthApp.data.success) // check whether webhook request sent correctly
	{
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}
	std::cout << "\n Response recieved from webhook request: " + resp;
	*/

	// get data from global variable with name 'status'
	// std::cout << "\n status - " + KeyAuthApp.var("status");

	// KeyAuthApp.log("user logged in"); // send event to logs. if you set discord webhook in app settings, it will send there instead of dashboard
	// KeyAuthApp.ban(); // ban the current user, must be logged in
	// KeyAuthApp.ban("Don't try to crack my loader, cunt."); // ban the current user (with a reason), must be logged in

	std::cout << skCrypt("\n\n Closing in ten seconds...");
	Sleep(10000);
	exit(0);
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
