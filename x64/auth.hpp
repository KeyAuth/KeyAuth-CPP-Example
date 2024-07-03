#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>

struct channel_struct
{
	std::string author;
	std::string message;
	std::string timestamp;
};

namespace KeyAuth {
	class api {
	public:

		std::string name, ownerid, secret, version, url, path;

		api(std::string name, std::string ownerid, std::string secret, std::string version, std::string url, std::string path) : name(name), ownerid(ownerid), secret(secret), version(version), url(url), path(path) {}

		void ban(std::string reason = "");
		void init();
		void check();
		void log(std::string msg);
		void license(std::string key);
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params, std::string body = "", std::string contenttype = "");
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password);
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key, std::string email = "");
		void chatget(std::string channel);
		bool chatsend(std::string message, std::string channel);
		void changeUsername(std::string newusername);
		std::string fetchonline();
		void fetchstats();
		void forgot(std::string username, std::string email);
		void logout();

		class subscriptions_class {
		public:
			std::string name;
			std::string expiry;
		};

		class userdata {
		public:

			// user data
			std::string username;
			std::string ip;
			std::string hwid;
			std::string createdate;
			std::string lastlogin;

			std::vector<subscriptions_class> subscriptions;
		};

		class appdata {
		public:
			// app data
			std::string numUsers;
			std::string numOnlineUsers;
			std::string numKeys;
			std::string version;
			std::string customerPanelLink;
		};

		class responsedata {
		public:
			// response data
			std::vector<channel_struct> channeldata;
			bool success{};
			std::string message;
		};

		userdata user_data;
		appdata app_data;
		responsedata response;

	private:
		std::string sessionid, enckey;
	};
}
