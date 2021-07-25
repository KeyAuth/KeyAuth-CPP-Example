#pragma once
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/ccm.h>

#include <atlsecurity.h> 
#include <strsafe.h> 
#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>

#include <curl/curl.h>

#include <shellapi.h>

#include <sstream> 
#include <iomanip> 
#include "../xorstr.hpp"
#include <fstream> 

#include <nlohmann/json.hpp>

#pragma comment(lib, "rpcrt4.lib")

namespace KeyAuth {

	class encryption {
	public:
		std::string name;
		static std::string encrypt_string(const std::string& plain_text, const std::string& key, const std::string& iv) {
			std::string cipher_text;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
				encryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

				CryptoPP::StringSource encryptor(plain_text, true,
					new CryptoPP::StreamTransformationFilter(encryption,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(cipher_text),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}
			return cipher_text;
		}

		static std::string decrypt_string(const std::string& cipher_text, const std::string& key, const std::string& iv) {
			std::string plain_text;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
				decryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

				CryptoPP::StringSource decryptor(cipher_text, true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StreamTransformationFilter(decryption,
							new CryptoPP::StringSink(plain_text)
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}
			return plain_text;
		}

		static std::string sha256(const std::string& plain_text) {
			std::string hashed_text;
			CryptoPP::SHA256 hash;

			try {
				CryptoPP::StringSource hashing(plain_text, true,
					new CryptoPP::HashFilter(hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(hashed_text),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}

			return hashed_text;
		}

		static std::string encode(const std::string& plain_text) {
			std::string encoded_text;

			try {
				CryptoPP::StringSource encoding(plain_text, true,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(encoded_text),
						false
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}

			return encoded_text;
		}

		static std::string decode(const std::string& encoded_text) {
			std::string out;

			try {
				CryptoPP::StringSource decoding(encoded_text, true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StringSink(out)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}

			return out;
		}

		static std::string iv_key() {
			UUID uuid = { 0 };
			std::string guid;

			::UuidCreate(&uuid);

			RPC_CSTR szUuid = NULL;
			if (::UuidToStringA(&uuid, &szUuid) == RPC_S_OK)
			{
				guid = (char*)szUuid;
				::RpcStringFreeA(&szUuid);
			}

			return guid.substr(0, 16);
		}

		static std::string encrypt(std::string message, std::string enc_key, std::string iv) {
			enc_key = sha256(enc_key).substr(0, 32);
			iv = sha256(iv).substr(0, 16);
			return encrypt_string(message, enc_key, iv);
		}

		static std::string decrypt(std::string message, std::string enc_key, std::string iv) {
			enc_key = sha256(enc_key).substr(0, 32);

			iv = sha256(iv).substr(0, 16);

			return decrypt_string(message, enc_key, iv);
		}
	};

	class utils {
	public:

		static std::string get_hwid() {
			ATL::CAccessToken accessToken;
			ATL::CSid currentUserSid;
			if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
				accessToken.GetUser(&currentUserSid))
				return std::string(CT2A(currentUserSid.Sid()));
		}

		static std::time_t string_to_timet(std::string timestamp) {
			auto cv = strtol(timestamp.c_str(), NULL, 10);

			return (time_t)cv;
		}

		static std::tm timet_to_tm(time_t timestamp) {
			std::tm context;

			localtime_s(&context, &timestamp);

			return context;
		}

	};


	auto iv = encryption::sha256(encryption::iv_key());
	class api {


	public:

		std::string name, ownerid, secret, version;

		api(std::string name, std::string ownerid, std::string secret, std::string version)
			: name(name), ownerid(ownerid), secret(secret), version(version) {}

		void init()
		{
			enckey = encryption::sha256(encryption::iv_key());
			if (ownerid.length() != 10 || secret.length() != 64)
			{
				std::cout << XorStr("\n\n Application Not Setup Correctly. Please Watch Video Linked in Main.cpp");
				Sleep(4500);
				exit(0);
			}

			auto data =
				XorStr("type=").c_str() + encryption::encode(XorStr("init").c_str()) +
				XorStr("&ver=").c_str() + encryption::encrypt(version, secret, iv) +
				XorStr("&enckey=").c_str() + encryption::encrypt(enckey, secret, iv) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;

			auto response = req(data);

			response = encryption::decrypt(response, secret, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				sessionid = json[("sessionid")];
				// optional success message
			}
			else if (json[("message")] == "invalidver")
			{
				std::string dl = json[("download")];
				ShellExecuteA(0, "open", dl.c_str(), 0, 0, SW_SHOWNORMAL);
				exit(0);
			}
			else
			{
				std::cout << "\n\n ";
				std::cout << std::string(json[("message")]);
				Sleep(4500);
				exit(0);
			}
		}

		void login(std::string username, std::string password)
		{
			std::string hwid = utils::get_hwid();
			auto iv = encryption::sha256(encryption::iv_key());
			auto data =
				XorStr("type=").c_str() + encryption::encode("login") +
				XorStr("&username=").c_str() + encryption::encrypt(username, enckey, iv) +
				XorStr("&pass=").c_str() + encryption::encrypt(password, enckey, iv) +
				XorStr("&hwid=").c_str() + encryption::encrypt(hwid, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				// optional success message
				load_user_data(json[("info")]);
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
				Sleep(3500);
				exit(0);
			}
		}

		void regstr(std::string username, std::string password, std::string key) {

			std::string hwid = utils::get_hwid();
			auto iv = encryption::sha256(encryption::iv_key());
			auto data =
				XorStr("type=").c_str() + encryption::encode("register") +
				XorStr("&username=").c_str() + encryption::encrypt(username, enckey, iv) +
				XorStr("&pass=").c_str() + encryption::encrypt(password, enckey, iv) +
				XorStr("&key=").c_str() + encryption::encrypt(key, enckey, iv) +
				XorStr("&hwid=").c_str() + encryption::encrypt(hwid, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				// optional success message
				load_user_data(json[("info")]);
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
				Sleep(3500);
				exit(0);
			}
		}

		void upgrade(std::string username, std::string key) {

			auto iv = encryption::sha256(encryption::iv_key());
			auto data =
				XorStr("type=").c_str() + encryption::encode("upgrade") +
				XorStr("&username=").c_str() + encryption::encrypt(username, enckey, iv) +
				XorStr("&key=").c_str() + encryption::encrypt(key, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				// optional success message
				load_user_data(json[("info")]);
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
				Sleep(3500);
				exit(0);
			}
		}

		void license(std::string key) {

			auto iv = encryption::sha256(encryption::iv_key());
			std::string hwid = utils::get_hwid();
			auto data =
				XorStr("type=").c_str() + encryption::encode("license") +
				XorStr("&key=").c_str() + encryption::encrypt(key, enckey, iv) +
				XorStr("&hwid=").c_str() + encryption::encrypt(hwid, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				// optional success message
				load_user_data(json[("info")]);
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
				Sleep(3500);
				exit(0);
			}
		}

		std::string var(std::string varid) {

			auto iv = encryption::sha256(encryption::iv_key());
			auto data =
				XorStr("type=").c_str() + encryption::encode("var") +
				XorStr("&varid=").c_str() + encryption::encrypt(varid, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				return json[("message")];
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
			}
		}

		void log(std::string message) {

			auto iv = encryption::sha256(encryption::iv_key());

			char acUserName[100];
			DWORD nUserName = sizeof(acUserName);
			GetUserNameA(acUserName, &nUserName);
			std::string UsernamePC = acUserName;

			std::string data =
				XorStr("type=").c_str() + encryption::encode(XorStr("log").c_str()) +
				XorStr("&pcuser=").c_str() + encryption::encrypt(UsernamePC, enckey, iv) +
				XorStr("&message=").c_str() + encryption::encrypt(message, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;

			req(data);
		}

		std::vector<unsigned char> download(std::string fileid) {
			auto iv = encryption::sha256(encryption::iv_key());
			auto to_uc_vector = [](std::string value) {
				return std::vector<unsigned char>(value.data(), value.data() + value.length() + 1);
			};

			auto data =
				XorStr("type=").c_str() + encryption::encode("file") +
				XorStr("&fileid=").c_str() + encryption::encrypt(fileid, enckey, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;

			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (!json["success"])
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
			}

			auto file = encryption::decode(json["contents"]);

			return to_uc_vector(file);
		}

		void webhook(std::string id, std::string params) {

			auto iv = encryption::sha256(encryption::iv_key());
			std::string hwid = utils::get_hwid();

			std::string data =
				XorStr("type=").c_str() + encryption::encode(XorStr("webhook").c_str()) +
				XorStr("&webid=").c_str() + encryption::encrypt(id, secret, iv) +
				XorStr("&params=").c_str() + encryption::encrypt(params, secret, iv) +
				XorStr("&sessionid=").c_str() + encryption::encode(sessionid) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;

			auto response = req(data);
			response = encryption::decrypt(response, enckey, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				// optional success message
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
			}
		}


		class user_data_class {
		public:
			std::string username;
			std::tm expiry;
			std::string subscription;
		};

		user_data_class user_data;

	private:
		std::string sessionid, enckey;

		static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
			((std::string*)userp)->append((char*)contents, size * nmemb);
			return size * nmemb;
		}

		static std::string req(std::string data) {
			CURL* curl = curl_easy_init();

			if (!curl)
				return "null";

			std::string to_return;

			curl_easy_setopt(curl, CURLOPT_URL, XorStr("https://keyauth.com/api/1.0/").c_str());
			curl_easy_setopt(curl, CURLOPT_USERAGENT, XorStr("KeyAuth").c_str());

			curl_easy_setopt(curl, CURLOPT_NOPROXY, XorStr("keyauth.com").c_str());

			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
			
			curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, XorStr("1.1.1.1,1.0.0.1").c_str()); // resolve ISP blockage issues caused by false domain report https://github.com/mitchellkrogza/Phishing.Database/issues/194
			
			curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//zaXl1uxtEA6FAR8KKoew4FYX+X3Khlfd/zjVD+SdMpc=");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);

			auto code = curl_easy_perform(curl);

			if (code != CURLE_OK)
				MessageBoxA(0, curl_easy_strerror(code), 0, MB_ICONERROR);

			return to_return;
		}

		class user_data_structure {
		public:
			std::string username;
			std::string expiry;
			std::string subscription;
		};

		void load_user_data(nlohmann::json data) {
			user_data.username = data["username"];
			user_data.expiry = utils::timet_to_tm(
				utils::string_to_timet(data["subscriptions"][0]["expiry"])
			);
			user_data.subscription = data["subscriptions"][0]["subscription"];
		}

		nlohmann::json response_decoder;

	};
}
