#include <Windows.h>
#include "lib/auth.hpp"
#include "skStr.h"
#include "lib/utils.hpp"
#include <chrono>
#include <ctime>
#include <iostream>
#include <limits>
#include <string>

using namespace KeyAuth;

namespace {

std::string tm_to_readable_time(std::tm ctx);
std::string remaining_until(const std::string& timestamp);

bool read_int(int& out) {
    std::cin >> out;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return false; // bad input read. -nigel
    }
    return true;
}

void print_user_data(const api& app) {
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << app.user_data.username;
    std::cout << skCrypt("\n IP address: ") << app.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << app.user_data.hwid;
    std::cout << skCrypt("\n Create date: ")
              << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(app.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ")
              << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(app.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (size_t i = 0; i < app.user_data.subscriptions.size(); i++) {
        const auto& sub = app.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ")
                  << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(sub.expiry)));
        std::cout << skCrypt(" (") << remaining_until(sub.expiry) << skCrypt(")");
    }
}
} // namespace

const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

std::string name = skCrypt("name").decrypt();
std::string ownerid = skCrypt("ownerid").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt(); // optional, set a path if you're using the token validation setting

api KeyAuthApp(name, ownerid, version, url, path);
api::lockout_state login_guard{};

int main()
{
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        KeyAuthApp.init_fail_delay();
        exit(1);
    }

    name.clear(); ownerid.clear(); version.clear(); url.clear(); // reduce exposure in memory. -nigel

    if (api::lockout_active(login_guard)) {
        std::cout << skCrypt("\n Status: Too many attempts. Try again in ")
                  << api::lockout_remaining_ms(login_guard) << skCrypt(" ms.");
        KeyAuthApp.close_delay();
        return 0;
    }

    std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

    int option = 0;
    std::string username;
    std::string password;
    std::string key;

    if (!read_int(option))
    {
        std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
        KeyAuthApp.bad_input_delay();
        exit(1);
    }

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
        KeyAuthApp.bad_input_delay();
        exit(1);
    }

    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        api::record_login_fail(login_guard);
        KeyAuthApp.init_fail_delay();
        exit(1);
    }
    api::reset_lockout(login_guard);

    print_user_data(KeyAuthApp);

    std::cout << skCrypt("\n\n Closing in five seconds...");
    KeyAuthApp.close_delay();

    return 0;
}

std::string tm_to_readable_time(std::tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

std::string remaining_until(const std::string& timestamp) {
    return api::expiry_remaining(timestamp);
}
