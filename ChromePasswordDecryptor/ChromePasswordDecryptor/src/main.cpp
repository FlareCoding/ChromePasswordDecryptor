#include "ChromePassDecryptor.h"

int main()
{
	ChromePassDecryptor decryptor;
	decryptor.Initialize();
	decryptor.Run();

	std::ofstream log("chrome_passwords.txt");

	for (auto& entry : decryptor.GetPasswordEntries())
	{
		log << "URL       : " << entry.URL << "\n";
		log << "Username  : " << entry.Username << "\n";
		log << "Password  : " << entry.Password << "\n";
		log << "===============================================\n";
	}

	return 0;
}
