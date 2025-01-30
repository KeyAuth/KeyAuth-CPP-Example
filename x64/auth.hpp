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

		std::string name, ownerid, version, url, path; 
		static bool debug;
		
		api(std::string name, std::string ownerid, std::string version, std::string url, std::string path, bool debugParameter = false) 
		: name(name), ownerid(ownerid), version(version), url(url), path(path)
		{
			setDebug(debugParameter);
		}
		
		void ban(std::string reason = "");
		void init();
		void check(bool check_paid = false);
		void log(std::string msg);
		void license(std::string key, std::string code = "");
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params, std::string body = "", std::string contenttype = "");
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password, std::string code = "");
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
			std::string downloadLink;
		};
		
		class responsedata {
		public:
			// response data
			std::vector<channel_struct> channeldata;
			bool success{};
			std::string message;
			bool isPaid{};
		};
		
		bool activate = false;
		class Tfa {
		public:
			std::string secret;
			std::string link;
			Tfa& handleInput(KeyAuth::api& apiInstance);
		private:
			void QrCode();
		};
		
		Tfa& enable2fa(std::string code = "");
		Tfa& disable2fa(std::string code = "");
		
		userdata user_data;
		appdata app_data;
		responsedata response;
		Tfa tfa;

	private:
		std::string sessionid, enckey;
		static void setDebug(bool value);
	};
}
