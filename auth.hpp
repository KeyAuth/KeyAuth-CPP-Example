#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>

namespace KeyAuth {
	class api {
	public:

		std::string name, ownerid, secret, version;

		api(std::string name, std::string ownerid, std::string secret, std::string version) : name(name), ownerid(ownerid), secret(secret), version(version) {}

		void ban();
		void init();
		void log(std::string msg);
		void license(std::string key);
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params);
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password);
		void web_login();
		void button(std::string value);
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key);

		class user_data_class {
		public:
			std::string username;
			std::string ip;
			std::string hwid;
			std::string timeleft;
		};
		user_data_class user_data;
	private:
		std::string sessionid, enckey;
	};
}