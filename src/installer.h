#pragma once

#include "codec.h"
#include "io.h"
#include "pe.h"

#include <filesystem>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace sf {

struct Entry
{
	std::string path;
	uint64_t packedSize = 0;
	uint64_t unpackedSize = 0;
	Compression compression = Compression::Unknown;
	uint64_t dataOffset = 0;
	uint32_t crc = 0;
	bool xored = false;
};

class Installer
{
public:
	static std::unique_ptr<Installer> open(const std::filesystem::path& path);

	int version() const { return version_; }
	int minorVersion() const { return minor_; }
	Compression compression() const { return base_; }
	const std::vector<Entry>& files() const { return files_; }

	void extract(const Entry& entry, std::ostream& out);

private:
	struct ScriptLayout
	{
		bool wideSizes;
		size_t afterAttrSkip;
		size_t afterDirSkip;
		size_t beforeFlagsSkip;
	};

	explicit Installer(const std::filesystem::path& path) : file_(path) {}

	bool probeSf7(const PeFile::Overlay& ovl);
	bool probeSf8(PeFile& pe, const PeFile::Overlay& ovl);
	void readSf7();
	void readSf8();

	void addSpecialFile(const char* name, bool xored, uint64_t size);
	void addServiceFile(const std::string& name, uint64_t packedSize, uint32_t crc, Compression method, bool verifyCrc);
	void parseScript(const ScriptLayout& layout, uint64_t dataStart);

	FileReader file_;
	std::vector<Entry> files_;
	Bytes script_;
	int version_ = 0;
	int minor_ = 0;
	Compression base_ = Compression::Unknown;
	uint64_t start_ = 0;
};

}
