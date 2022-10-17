# KeyAuth-CPP-Example

KeyAuth CPP Example For The https://keyauth.cc Authentication system.

The source code of the static library for KeyAuth is here https://github.com/KeyAuth/keyauth-cpp-library

**Security practices**

* Utilize obfuscation provided by companies such as VMProtect or Themida (utilize their SDKs too for greater protection)
* Preform frequent integrity checks to ensure the memory of the program has not been modified
* Don't write the bytes of a file you've downloaded to disk if you don't want that file to be retrieved by the user. Rather, execute the file in memory and erase it from memory the moment execution finishes

*KeyAuth is provided in Source Code Form. The burden of client-side protection is on you the software developer, as it would be with any authentication system.*

**What is KeyAuth?**

KeyAuth is an Open source authentication system with cloud hosting plans as well. Client SDKs available for C++, C#, Python, Rust, PHP, and VB.NET.
KeyAuth several unique features such as memory streaming, webhook function where you can send requests to API without leaking the API, discord webhook notifications, ban the user securely through the application at your discretion.
Feel free to join https://discord.gg/keyauth if you have questions or suggestions.

**Customer connection issues?**

This is common amongst all authentication systems. Program obfuscation causes false positives in virus scanners, and with the scale of KeyAuth this is perceived as a malicious domain. So, `keyauth.com` and `keyauth.win` have been blocked by many internet providers. for dashbord, reseller panel, customer panel, use `keyauth.cc`

For API, `keyauth.cc` will not work because I purposefully blocked it on there so `keyauth.cc` doesn't get blocked also. So, you should create your own domain and follow this tutorial video https://www.youtube.com/watch?v=a2SROFJ0eYc. The tutorial video shows you how to create a domain name for 100% free if you don't want to purchase one.

**`KeyAuthApp` instance definition**

Visit and select your application, then click on the **C++** tab

It'll provide you with the code which you should replace with in the `Program.cs` file (or `Login.cs` file if using Form example)

```cpp
std::string name = "example"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = "JjPMBVlIOd"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = "db40d586f4b189e04e5c18c3c94b7e72221be3f6551995adc05236948d1762bc"; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website
std::string url = "https://keyauth.win/api/1.2/"; // change if you're self-hosting

api KeyAuthApp(name, ownerid, secret, version, url);
```

**Initialize application**

You must call this function prior to using any other KeyAuth function. Otherwise the other KeyAuth function won't work.

```cpp
KeyAuthApp.init();
if (!KeyAuthApp.data.success)
{
	std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
	Sleep(1500);
	exit(0);
}
```

**Display application information**

```cpp
std::cout << skCrypt("\n\n App data:");
std::cout << skCrypt("\n Number of users: ") << KeyAuthApp.data.numUsers;
std::cout << skCrypt("\n Number of online users: ") << KeyAuthApp.data.numOnlineUsers;
std::cout << skCrypt("\n Number of keys: ") << KeyAuthApp.data.numKeys;
std::cout << skCrypt("\n Application Version: ") << KeyAuthApp.data.version;
std::cout << skCrypt("\n Customer panel link: ") << KeyAuthApp.data.customerPanelLink;
```

**Check session validation**

Use this to see if the user is logged in or not.

```cpp
std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
KeyAuthApp.check();
std::cout << skCrypt("\n Current Session Validation Status: ") << KeyAuthApp.data.message;
```

**Check blacklist status**

Check if HWID or IP Address is blacklisted. You can add this if you want, just to make sure nobody can open your program for less than a second if they're blacklisted. Though, if you don't mind a blacklisted user having the program for a few seconds until they try to login and register, and you care about having the quickest program for your users, you shouldn't use this function then. If a blacklisted user tries to login/register, the KeyAuth server will check if they're blacklisted and deny entry if so. So the check blacklist function is just auxiliary function that's optional.

```cpp
if (KeyAuthApp.checkblack()) {
	abort();
}
```

**Login with username/password**

```cpp
std::string username;
std::string password;
std::cout << skCrypt("\n\n Enter username: ");
std::cin >> username;
std::cout << skCrypt("\n Enter password: ");
std::cin >> password;
KeyAuthApp.login(username, password);
if (!KeyAuthApp.data.success)
{
	std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
	Sleep(1500);
	exit(0);
}
```

**Register with username/password/key**

```cpp
std::string username;
std::string password;
std::string key;
std::cout << skCrypt("\n\n Enter username: ");
std::cin >> username;
std::cout << skCrypt("\n Enter password: ");
std::cin >> password;
std::cout << skCrypt("\n Enter license: ");
std::cin >> key;
KeyAuthApp.regstr(username, password, key);
if (!KeyAuthApp.data.success)
{
	std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
	Sleep(1500);
	exit(0);
}
```

**Upgrade user username/key**

Used so the user can add extra time to their account by claiming new key.

> **Warning**
> No password is needed to upgrade account. So, unlike login, register, and license functions - you should **not** log user in after successful upgrade.

```cpp
std::string username;
std::string key;
std::cout << skCrypt("\n\n Enter username: ");
std::cin >> username;
std::cout << skCrypt("\n Enter license: ");
std::cin >> key;
KeyAuthApp.upgrade(username, key);
```

**Login with just license key**

Users can use this function if their license key has never been used before, and if it has been used before. So if you plan to just allow users to use keys, you can remove the login and register functions from your code.

```cpp
std::string key;
std::cout << skCrypt("\n Enter license: ");
std::cin >> key;
KeyAuthApp.license(key);
if (!KeyAuthApp.data.success)
{
	std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
	Sleep(1500);
	exit(0);
}
```

**Login with web loader**

Have your users login through website. Tutorial video here https://www.youtube.com/watch?v=9-qgmsUUCK4 you can use your own domain for customer panel also, https://www.youtube.com/watch?v=iHQe4GLvgaE

```cpp
std::cout << "\n Waiting for user to login";
KeyAuthApp.web_login();
std::cout << "\n Waiting for button to be clicked";
KeyAuthApp.button("close");
```

**User Data**

Show information for current logged-in user.

```cpp
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
```

**Check subscription name of user**

If you want to wall off parts of your app to only certain users, you can have multiple subscriptions with different names. Then, when you create licenses that correspond to the level of that subscription, users who use those licenses will get a subscription with the name of the subscription that corresponds to the level of the license key they used. The `SubExist` function is in the `Program.cs` file

```cpp
for (std::string subs : KeyAuthApp.data.subscriptions)
{
	if (subs == "default")
	{
		std::cout << skCrypt("\n User has subscription with name: default");
	}
}
```

**Application variables**

A string that is kept on the server-side of KeyAuth. On the dashboard you can choose for each variable to be authenticated (only logged in users can access), or not authenticated (any user can access before login). These are global and static for all users, unlike User Variables which will be dicussed below this section.

```cpp
// get data from global variable with name 'status'
std::cout << "\n status - " + KeyAuthApp.var("status");
```

**User Variables**

User variables are strings kept on the server-side of KeyAuth. They are specific to users. They can be set on Dashboard in the Users tab, via SellerAPI, or via your loader using the code below. `discord` is the user variable name you fetch the user variable by. `test#0001` is the variable data you get when fetching the user variable.

```cpp
std::cout << "\n user variable - " + KeyAuthApp.getvar("discord"); // get value of the user variable 'discord'
```

And here's how you fetch the user variable:

```cpp
KeyAuthApp.setvar("discord", "test#0001"); // set the value of user variable 'discord' to 'test#0001'
```

**Application Logs**

Can be used to log data. Good for anti-debug alerts and maybe error debugging. If you set Discord webhook in the app settings of the Dashboard, it will send log messages to your Discord webhook rather than store them on site. It's recommended that you set Discord webhook, as logs on site may be deleted after a couple months of their creation.

You can use the log function before login & after login.

```cpp
KeyAuthApp.log("user logged in"); // send event to logs. if you set discord webhook in app settings, it will send there instead of dashboard
```

**Ban the user**

Ban the user and blacklist their HWID and IP Address. Good function to call upon if you use anti-debug and have detected an intrusion attempt.

Function only works after login.

```cpp
KeyAuthApp.ban();
```

**Server-sided webhooks**

Tutorial video https://www.youtube.com/watch?v=ENRaNPPYJbc

Send HTTP requests to URLs securely without leaking the URL in your application. You should definitely use if you want to send requests to SellerAPI from your application, otherwise if you don't use you'll be leaking your seller key to everyone. And then someone can mess up your application.

```cpp
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
```

**Download file**

Keep files secure by providing KeyAuth your file download link on the KeyAuth dashboard. Make sure this is a direct download link (as soon as you go to the link, it starts downloading without you clicking anything). The KeyAuth download function provides the bytes, and then you get to decide what to do with those. This example shows how to write it to a file named `text.txt` in the same folder as the program, though you could execute with RunPE or whatever you want.

`362906` is the webhook ID you get from the dashboard after adding file.

```cpp
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
```

**Chat channels**

Allow users to communicate amongst themselves in your program.

There's a console example here https://github.com/nuss31/KeyAuth-Cpp-Chat-Libary-Example

And in our Discord server https://discord.gg/keyauth (after verifying for chat), you can see this ImGui example https://discord.com/channels/824397012685291520/824399478232055848/927262833031393313
