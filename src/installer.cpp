#include "installer.h"

#include <algorithm>

namespace sf {

static const char kScriptFile[] = "irsetup.dat";
static const char kFileBlockClass[] = "CSetupFileData";

std::unique_ptr<Installer> Installer::open(const std::filesystem::path& path)
{
	std::unique_ptr<Installer> inst(new Installer(path));

	PeFile pe(inst->file_);
	auto overlay = pe.overlay();
	if (!overlay) throw Error("no installer data found after the PE image");

	if (inst->probeSf7(*overlay))
		inst->readSf7();
	else if (inst->probeSf8(pe, *overlay))
		inst->readSf8();
	else
		throw Error("not a supported Setup Factory installer (7, 8 and 9 are handled)");

	return inst;
}

void Installer::addSpecialFile(const char* name, bool xored, uint64_t size)
{
	Entry e;
	e.path = name;
	e.packedSize = size;
	e.unpackedSize = size;
	e.compression = Compression::None;
	e.dataOffset = file_.pos();
	e.xored = xored;
	files_.push_back(e);

	if (size > file_.size() - file_.pos()) throw Error("embedded file runs past the end of the installer");
	file_.skip(static_cast<int64_t>(size));
}

// Unpacked only to get the real size and to keep the script
void Installer::addServiceFile(const std::string& name, uint64_t packedSize, uint32_t crc, Compression method, bool verifyCrc)
{
	Entry e;
	e.path = name;
	e.packedSize = packedSize;
	e.crc = crc;
	e.compression = method;
	e.dataOffset = file_.pos();

	Bytes data = unpack(method, file_.readBytes(packedSize));
	if (verifyCrc && crc != 0 && crc32(data.data(), data.size()) != crc)
		throw Error("CRC mismatch in service file " + name);

	e.unpackedSize = data.size();
	if (name == kScriptFile) script_ = std::move(data);
	files_.push_back(e);
}

void Installer::parseScript(const ScriptLayout& layout, uint64_t dataStart)
{
	if (script_.empty()) return;

	auto found = std::search(script_.begin(), script_.end(), std::begin(kFileBlockClass), std::end(kFileBlockClass) - 1);
	if (found == script_.end()) return;

	size_t blockPos = static_cast<size_t>(found - script_.begin());
	if (blockPos < 8) throw Error("script file table is truncated");

	ByteReader r(script_);
	r.seek(blockPos - 8);

	uint16_t numEntries = r.get<uint16_t>();
	r.skip(4);
	uint16_t classNameLen = r.get<uint16_t>();
	if (r.readChars(classNameLen) != kFileBlockClass) throw Error("unexpected layout of the installer script");
	r.skip(5);

	uint64_t offset = dataStart;
	for (uint16_t i = 0; i < numEntries; i++)
	{
		r.skipString(); // source path
		std::string baseName = r.readString();
		r.skipString(); // source directory
		r.skipString();
		r.skipString();
		r.skipString();
		r.skip(2);
		uint64_t unpackedSize = layout.wideSizes ? r.get<uint64_t>() : r.get<uint32_t>();
		r.skip(1); // attributes
		r.skip(layout.afterAttrSkip);
		std::string destDir = r.readString();
		r.skip(layout.afterDirSkip);
		for (int s = 0; s < 5; s++)
			r.skipString(); // shortcut fields
		r.skip(1);
		r.skipString(); // icon
		r.skip(8);
		r.skipString(); // font name
		r.skip(layout.beforeFlagsSkip);
		bool compressed = r.get<uint8_t>() != 0;
		r.skip(2); // attribute flags

		r.skip(10);
		uint16_t skipChars = r.get<uint16_t>();
		r.skip(size_t(skipChars) * 2);

		r.skipString(); // condition
		r.skip(2);
		r.skipString();
		r.skipString();
		uint16_t numPackages = r.get<uint16_t>();
		for (uint16_t p = 0; p < numPackages; p++)
			r.skipString();
		r.skipString();
		uint64_t packedSize = layout.wideSizes ? r.get<uint64_t>() : r.get<uint32_t>();
		uint32_t crc = r.get<uint32_t>();
		r.skip(8);

		Entry e;
		e.path = destDir.empty() ? baseName : (destDir.back() == '\\' ? destDir : destDir + '\\') + baseName;
		e.packedSize = packedSize;
		e.unpackedSize = unpackedSize;
		e.compression = compressed ? base_ : Compression::None;
		e.dataOffset = offset;
		e.crc = crc;
		files_.push_back(e);

		offset += packedSize;
	}
}

void Installer::extract(const Entry& entry, std::ostream& out)
{
	if (entry.packedSize == 0) return;

	file_.seek(entry.dataOffset);
	Bytes data = unpack(entry.compression, file_.readBytes(entry.packedSize));

	if (entry.crc != 0 && crc32(data.data(), data.size()) != entry.crc)
		throw Error("CRC mismatch");

	// irsetup.exe has its first 2000 bytes xor-ed
	if (entry.xored)
	{
		size_t n = std::min<size_t>(data.size(), 2000);
		for (size_t i = 0; i < n; i++)
			data[i] ^= 0x07;
	}

	out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
	if (!out) throw Error("write error");
}

}
