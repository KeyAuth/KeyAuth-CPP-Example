#include <Windows.h>
#include "auth.hpp"
#include <string>
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;

std::string name = ""; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = ""; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = ""; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website

/*
	Video on what ownerid and secret are https://youtu.be/uJ0Umy_C6Fg

	Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA

	Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version);

int main()
{

	SetConsoleTitleA("Loader");
	std::cout << "\n\n Connecting..";
	KeyAuthApp.init();
	if (!KeyAuthApp.data.success)
	{
		std::cout << "\n Status: " + KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::cout << "\n\n App data:";
	std::cout << "\n Number of users: " + KeyAuthApp.data.numUsers;
	std::cout << "\n Number of online users: " + KeyAuthApp.data.numOnlineUsers;
	std::cout << "\n Number of keys: " + KeyAuthApp.data.numKeys;
	std::cout << "\n Application Version: " + KeyAuthApp.data.version;
	std::cout << "\n Customer panel link: " + KeyAuthApp.data.customerPanelLink;

	std::cout << "\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ";

	int option;
	std::string username;
	std::string password;
	std::string key;

	std::cin >> option;
	switch (option)
	{
	case 1:
		std::cout << "\n\n Enter username: ";
		std::cin >> username;
		std::cout << "\n Enter password: ";
		std::cin >> password;
		KeyAuthApp.login(username, password);
		break;
	case 2:
		std::cout << "\n\n Enter username: ";
		std::cin >> username;
		std::cout << "\n Enter password: ";
		std::cin >> password;
		std::cout << "\n Enter license: ";
		std::cin >> key;
		KeyAuthApp.regstr(username, password, key);
		break;
	case 3:
		std::cout << "\n\n Enter username: ";
		std::cin >> username;
		std::cout << "\n Enter license: ";
		std::cin >> key;
		KeyAuthApp.upgrade(username, key);
		break;
	case 4:
		std::cout << "\n Enter license: ";
		std::cin >> key;
		KeyAuthApp.license(key);
		break;
	default:
		std::cout << "\n\n Status: Failure: Invalid Selection";
		Sleep(3000);
		exit(0);
	}

	if (!KeyAuthApp.data.success)
	{
		std::cout << "\n Status: " + KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::cout << "\n User data:";
	std::cout << "\n Username: " + KeyAuthApp.data.username;
	std::cout << "\n IP address: " + KeyAuthApp.data.ip;
	std::cout << "\n Hardware-Id: " + KeyAuthApp.data.hwid;
	std::cout << "\n Create date: " + tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.createdate)));
	std::cout << "\n Last login: " + tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.lastlogin)));

	/*
	KeyAuthApp.web_login();

	std::cout << "\n Waiting for button to be clicked";
	KeyAuthApp.button("close");
	*/


	/*
	// download file, change file.exe to whatever you want.
	// remember, certain paths like windows folder will require you to turn on auto run as admin https://stackoverflow.com/a/19617989

	std::vector<std::uint8_t> bytes = KeyAuthApp.download("167212");
	std::ofstream file("file.exe", std::ios_base::out | std::ios_base::binary);
	file.write((char*)bytes.data(), bytes.size());
	file.close();
	*/

	// KeyAuthApp.setvar("discord", "test#0001"); // set the variable 'discord' to 'test#0001'
	// std::cout << "\n\n User variable data: " + KeyAuthApp.getvar("discord"); // display the user variable witn name 'discord'

	// let's say you want to send request to https://keyauth.com/api/seller/?sellerkey=f43795eb89d6060b74cdfc56978155ef&type=black&ip=1.1.1.1&hwid=abc
	// but doing that from inside the loader is a bad idea as the link could get leaked.
	// Instead, you should create a webhook with the https://keyauth.com/api/seller/?sellerkey=f43795eb89d6060b74cdfc56978155ef part as the URL
	// then in your loader, put the rest of the link (the other paramaters) in your loader. And then it will send request from KeyAuth server and return response in string resp

	// you have to encode the & sign with %26
	// std::string resp = KeyAuthApp.webhook("P5NHesuZyf", "%26type=black%26ip=1.1.1.1%26hwid=abc");
	// std::cout << "\n Response recieved from webhook request: " + resp;

	// KeyAuthApp.log("user logged in"); // send event to logs. if you set discord webhook in app settings, it will send there too
	// KeyAuthApp.ban(); // ban the current user, must be logged in

	std::cout << "\n\n Closing in ten seconds...";
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