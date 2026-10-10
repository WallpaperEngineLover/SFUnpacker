#pragma once

#include "io.h"

#include <optional>
#include <string>
#include <vector>

namespace sf {

struct VersionInfo
{
	unsigned major = 0;
	unsigned minor = 0;
	std::string productName;
};

class PeFile
{
public:
	explicit PeFile(FileReader& file);

	struct Overlay
	{
		uint64_t start;
		uint64_t size;
	};

	std::optional<Overlay> overlay();
	std::optional<Bytes> resource(uint32_t type, uint32_t id);

	std::string manifest();
	std::optional<VersionInfo> versionInfo();

private:
	struct Section
	{
		uint32_t virtualSize;
		uint32_t virtualAddress;
		uint32_t rawSize;
		uint32_t rawOffset;
	};

	struct DataDir
	{
		uint32_t rva = 0;
		uint32_t size = 0;
	};

	std::optional<uint64_t> rvaToOffset(uint32_t rva) const;
	std::optional<uint32_t> findEntry(uint64_t dirOffset, uint32_t id);

	FileReader& file_;
	std::vector<Section> sections_;
	std::vector<DataDir> dirs_;
};

}
