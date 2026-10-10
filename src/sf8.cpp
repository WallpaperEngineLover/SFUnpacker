#include "installer.h"

#include <cstdio>

namespace sf {

static const uint8_t kSignature[16] = { 0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5, 0xE5, 0xE6, 0xE6, 0xE7, 0xE7 };

constexpr size_t kNameSize = 264;

static bool versionFromManifest(const std::string& manifest, int& major, int& minor)
{
	size_t ident = manifest.find("<assemblyIdentity");
	if (ident == std::string::npos) return false;

	size_t vers = manifest.find("version=", ident);
	if (vers == std::string::npos || vers + 9 >= manifest.size()) return false;

	int rev, build;
	return std::sscanf(manifest.c_str() + vers + 9, "%d.%d.%d.%d", &major, &minor, &rev, &build) == 4;
}

static Compression detectCompression(FileReader& file)
{
	uint8_t head[2];
	file.read(head, sizeof(head));
	file.skip(-2);

	if (head[0] == 0x00 && head[1] == 0x06) return Compression::PkWare;
	if (head[0] == 0x5D && head[1] == 0x00) return Compression::Lzma;
	if (head[0] == 0x18) return Compression::Lzma2;
	return Compression::Unknown;
}

bool Installer::probeSf8(PeFile& pe, const PeFile::Overlay& ovl)
{
	file_.seek(ovl.start);

	uint8_t sig[sizeof(kSignature)];
	if (ovl.size < sizeof(sig)) return false;
	file_.read(sig, sizeof(sig));
	if (std::memcmp(sig, kSignature, sizeof(sig)) != 0) return false;

	start_ = ovl.start + sizeof(kSignature);

	const std::string manifest = pe.manifest();
	auto manifestHas = [&manifest](const char* text) {
		return manifest.find(text) != std::string::npos;
	};

	if (manifestHas("<description>Setup Factory 8.0 Run-time</description>"))
	{
		version_ = 8;
		minor_ = 0;
		return true;
	}

	// 9.5 and later use "Setup Factory Run-time"
	if (manifestHas("<description>Setup Factory 9 Run-time</description>") ||
		manifestHas("<description>Setup Factory Run-time</description>"))
	{
		return versionFromManifest(manifest, version_, minor_) && (version_ == 9 || version_ == 10);
	}

	// Some manifests are bogus, the version resource is still right
	if (manifestHas("<description>Setup</description>"))
	{
		auto info = pe.versionInfo();
		if (info && (info->major == 9 || info->major == 10) && info->productName == "Setup Factory Runtime")
		{
			version_ = int(info->major);
			minor_ = int(info->minor);
			return true;
		}
	}

	return false;
}

void Installer::readSf8()
{
	file_.seek(start_);
	file_.skip(10);
	addSpecialFile("irsetup.exe", true, file_.get<uint64_t>());

	uint32_t numFiles = file_.get<uint32_t>();

	// A huge count is really the size of a bundled Lua dll
	if (numFiles > 1000)
	{
		file_.skip(-4);
		addSpecialFile("lua5.1.dll", false, file_.get<uint64_t>());
		numFiles = file_.get<uint32_t>();
	}

	for (uint32_t i = 0; i < numFiles; i++)
	{
		char name[kNameSize];
		file_.read(name, sizeof(name));
		uint64_t size = file_.get<uint64_t>();
		uint32_t crc = file_.get<uint32_t>();
		file_.skip(4);

		if (base_ == Compression::Unknown)
			base_ = detectCompression(file_);

		if (base_ != Compression::Lzma && base_ != Compression::Lzma2)
			throw Error(std::string("unsupported compression in Setup Factory ") + std::to_string(version_) + ": " + compressionName(base_));

		addServiceFile(std::string(name, strnlen(name, sizeof(name))), size, crc, base_, true);
	}

	bool v93 = version_ >= 10 || (version_ == 9 && minor_ >= 3);
	parseScript({ true, 61, v93 ? size_t(11) : size_t(10), version_ >= 10 ? size_t(4) : size_t(3) }, file_.pos());
}

}
