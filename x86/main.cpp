#include <Windows.h>
#include <string>
#include <auth.hpp>
#include "utils.hpp"
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;

std::string name = skCrypt("name").decrypt();
std::string ownerid = skCrypt("ownerid").decrypt();
std::string secret = skCrypt("secret").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
std::string path = skCrypt("path (optional)").decrypt();

api KeyAuthApp(name, ownerid, secret, version, url, path);

int main()
{
    // Freeing memory to prevent memory leak or memory scraping
    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

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
        exit(1);
    }

    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    KeyAuthApp.chatget("testing");

    for (int i = 0; i < KeyAuthApp.response.channeldata.size(); i++)
    {
        std::cout << "\n Author:" + KeyAuthApp.response.channeldata[i].author + " | Message:" + KeyAuthApp.response.channeldata[i].message + " | Send Time:" + tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.response.channeldata[i].timestamp)));
    }
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
