#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <streambuf>

namespace Utils
{
	std::string base64_decode(std::string const& encoded_string);
	std::string get_app_data_path();

	void delete_file(const std::string& path);
}
