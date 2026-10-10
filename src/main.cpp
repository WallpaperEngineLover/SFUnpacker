#include "installer.h"

#include <iostream>

namespace fs = std::filesystem;

// Stored names are treated as Latin-1
static std::string latin1ToUtf8(const std::string& in)
{
	std::string out;
	for (unsigned char c : in)
	{
		if (c < 0x80)
		{
			out += static_cast<char>(c);
		}
		else
		{
			out += static_cast<char>(0xC0 | (c >> 6));
			out += static_cast<char>(0x80 | (c & 0x3F));
		}
	}
	return out;
}

// Empty result means the path would escape the output directory
static fs::path safeRelativePath(const std::string& stored)
{
	fs::path result;
	std::string part;

	auto flush = [&]() {
		if (part.empty() || part == ".")
		{
			part.clear();
			return true;
		}
		if (part == "..") return false;
		for (char& c : part)
		{
			if (static_cast<unsigned char>(c) < 0x20 || std::string("<>:\"|?*").find(c) != std::string::npos)
				c = '_';
		}
		result /= fs::u8path(part);
		part.clear();
		return true;
	};

	for (char c : latin1ToUtf8(stored))
	{
		if (c == '\\' || c == '/')
		{
			if (!flush()) return {};
		}
		else
		{
			part += c;
		}
	}
	if (!flush()) return {};

	return result;
}

int main(int argc, char* argv[])
{
	if (argc < 2 || argc > 3)
	{
		std::cerr << "usage: " << argv[0] << " <installer.exe> [output-dir]\n";
		return 1;
	}

	fs::path outDir = argc == 3 ? fs::path(argv[2]) : fs::path("extracted");

	std::unique_ptr<sf::Installer> installer;
	try
	{
		installer = sf::Installer::open(fs::path(argv[1]));
	}
	catch (const std::exception& ex)
	{
		std::cerr << "Cannot read installer: " << ex.what() << "\n";
		return 1;
	}

	std::cout << "Setup Factory " << installer->version();
	if (installer->version() >= 8) std::cout << "." << installer->minorVersion();
	std::cout << "\nCompression: " << sf::compressionName(installer->compression()) << "\n";

	const auto& files = installer->files();
	if (files.empty())
	{
		std::cerr << "No files\n";
		return 1;
	}
	std::cout << "File count: " << files.size() << "\n";

	std::vector<std::string> failed;
	for (const sf::Entry& entry : files)
	{
		fs::path rel = safeRelativePath(entry.path);
		if (rel.empty())
		{
			std::cerr << "Skipping unsafe path: " << entry.path << "\n";
			failed.push_back(entry.path);
			continue;
		}

		fs::path target = outDir / rel;
		try
		{
			fs::create_directories(target.parent_path());
			std::ofstream out(target, std::ios::binary | std::ios::trunc);
			if (!out) throw sf::Error("cannot create " + target.string());

			installer->extract(entry, out);
			std::cout << "Extracted " << rel.string() << "\n";
		}
		catch (const std::exception& ex)
		{
			std::cerr << "Failed " << rel.string() << ": " << ex.what() << "\n";
			failed.push_back(entry.path);
		}
	}

	if (failed.empty())
	{
		std::cout << "All files extracted successfully!\n";
		return 0;
	}

	std::cerr << failed.size() << " files failed to extract.\n";
	return 1;
}
