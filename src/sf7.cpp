#include "installer.h"

namespace sf {

static const uint8_t kSignature[8] = { 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7 };

constexpr size_t kNameSize = 260;

bool Installer::probeSf7(const PeFile::Overlay& ovl)
{
	file_.seek(ovl.start);

	uint8_t sig[sizeof(kSignature)];
	if (ovl.size < sizeof(sig) + 4) return false;
	file_.read(sig, sizeof(sig));
	if (std::memcmp(sig, kSignature, sizeof(sig)) != 0) return false;

	// A file size here; versions 5 and 6 have a small file count instead
	if (file_.get<uint32_t>() <= 100) return false;

	version_ = 7;
	base_ = Compression::PkWare;
	start_ = ovl.start + sizeof(kSignature);
	return true;
}

void Installer::readSf7()
{
	file_.seek(start_);

	// Not every installer has this extra byte, not investigated
	file_.skip(1);
	addSpecialFile("irsetup.exe", true, file_.get<uint32_t>());

	uint32_t numFiles = file_.get<uint32_t>();
	for (uint32_t i = 0; i < numFiles; i++)
	{
		char name[kNameSize];
		file_.read(name, sizeof(name));
		uint32_t size = file_.get<uint32_t>();
		uint32_t crc = file_.get<uint32_t>();

		addServiceFile(std::string(name, strnlen(name, sizeof(name))), size, crc, Compression::PkWare, false);
	}

	parseScript({ false, 37, 10, 3 }, file_.pos());
}

}
