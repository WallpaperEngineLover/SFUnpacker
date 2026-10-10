#include "pe.h"

#include <algorithm>

namespace sf {

namespace {

constexpr uint16_t kDosMagic = 0x5A4D;
constexpr uint32_t kNtSignature = 0x00004550;
constexpr uint16_t kOptMagic32 = 0x10B;
constexpr uint16_t kOptMagic64 = 0x20B;

constexpr size_t kDirDebug = 6;
constexpr size_t kDirResource = 2;
constexpr size_t kDirSecurity = 4;

constexpr uint32_t kResManifest = 24;
constexpr uint32_t kResVersion = 16;

constexpr uint32_t kMaxResourceSize = 64 * 1024 * 1024;

std::string narrow(const std::u16string& s)
{
	std::string out;
	for (char16_t c : s)
		out += c < 0x80 ? static_cast<char>(c) : '?';
	return out;
}

struct VerBlock
{
	std::u16string key;
	size_t valueOffset = 0;
	size_t valueLength = 0;
	size_t childOffset = 0;
	size_t end = 0;
};

size_t align4(size_t v)
{
	return (v + 3) & ~size_t(3);
}

VerBlock readVerBlock(const Bytes& data, size_t offset, size_t limit)
{
	ByteReader r(data.data(), limit);
	r.seek(offset);

	VerBlock b;
	size_t length = r.get<uint16_t>();
	size_t valueLen = r.get<uint16_t>();
	uint16_t type = r.get<uint16_t>();

	for (;;)
	{
		char16_t c = r.get<char16_t>();
		if (c == 0) break;
		b.key += c;
	}

	b.end = std::min(offset + length, limit);
	b.valueOffset = align4(r.pos());
	b.valueLength = type == 1 ? valueLen * 2 : valueLen;
	b.childOffset = align4(b.valueOffset + b.valueLength);
	if (b.valueOffset + b.valueLength > b.end) throw Error("bad version block");
	b.childOffset = std::min(b.childOffset, b.end);
	return b;
}

std::vector<VerBlock> readVerChildren(const Bytes& data, const VerBlock& parent)
{
	std::vector<VerBlock> out;
	size_t off = parent.childOffset;
	while (off + 6 <= parent.end)
	{
		VerBlock child = readVerBlock(data, off, parent.end);
		if (child.end <= off) break;
		out.push_back(child);
		off = align4(child.end);
	}
	return out;
}

}

PeFile::PeFile(FileReader& file) : file_(file)
{
	file_.seek(0);
	if (file_.size() < 0x40 || file_.get<uint16_t>() != kDosMagic) throw Error("not a PE file");

	file_.seek(0x3C);
	uint32_t peOffset = file_.get<uint32_t>();
	file_.seek(peOffset);
	if (file_.get<uint32_t>() != kNtSignature) throw Error("not a PE file");

	file_.skip(2);
	uint16_t numSections = file_.get<uint16_t>();
	file_.skip(12);
	uint16_t optSize = file_.get<uint16_t>();
	file_.skip(2);

	Bytes opt = file_.readBytes(optSize);
	ByteReader o(opt);
	uint16_t magic = o.get<uint16_t>();
	size_t dirCountOffset;
	if (magic == kOptMagic32) dirCountOffset = 92;
	else if (magic == kOptMagic64) dirCountOffset = 108;
	else throw Error("unknown PE optional header");

	o.seek(dirCountOffset);
	uint32_t numDirs = std::min<uint32_t>(o.get<uint32_t>(), 16);
	for (uint32_t i = 0; i < numDirs; i++)
	{
		DataDir d;
		d.rva = o.get<uint32_t>();
		d.size = o.get<uint32_t>();
		dirs_.push_back(d);
	}

	if (numSections == 0) throw Error("PE file has no sections");
	for (uint16_t i = 0; i < numSections; i++)
	{
		Bytes raw = file_.readBytes(40);
		ByteReader s(raw);
		s.seek(8);
		Section sec;
		sec.virtualSize = s.get<uint32_t>();
		sec.virtualAddress = s.get<uint32_t>();
		sec.rawSize = s.get<uint32_t>();
		sec.rawOffset = s.get<uint32_t>();
		sections_.push_back(sec);
	}
}

std::optional<uint64_t> PeFile::rvaToOffset(uint32_t rva) const
{
	for (const Section& s : sections_)
	{
		uint32_t span = s.virtualSize ? s.virtualSize : s.rawSize;
		if (rva >= s.virtualAddress && rva - s.virtualAddress < span)
		{
			uint64_t off = uint64_t(s.rawOffset) + (rva - s.virtualAddress);
			if (off < file_.size()) return off;
		}
	}
	return std::nullopt;
}

std::optional<PeFile::Overlay> PeFile::overlay()
{
	const uint64_t fileSize = file_.size();

	uint64_t maxLimit = 0;
	for (const Section& s : sections_)
	{
		uint64_t limit = uint64_t(s.rawOffset) + s.rawSize;
		if (limit > fileSize) return std::nullopt;
		maxLimit = std::max(maxLimit, limit);
	}

	int64_t start = static_cast<int64_t>(maxLimit);
	int64_t size = static_cast<int64_t>(fileSize) - start;
	if (size <= 0) return std::nullopt;

	// Debug data can sit between the last section and the overlay
	if (dirs_.size() > kDirDebug && dirs_[kDirDebug].size >= 28)
	{
		auto dbgOffset = rvaToOffset(dirs_[kDirDebug].rva);
		if (!dbgOffset) return std::nullopt;

		file_.seek(*dbgOffset);
		uint32_t count = dirs_[kDirDebug].size / 28;
		for (uint32_t i = 0; i < count && size > 0; i++)
		{
			Bytes raw = file_.readBytes(28);
			ByteReader d(raw);
			d.seek(16);
			uint32_t dataSize = d.get<uint32_t>();
			d.skip(4);
			uint32_t dataOffset = d.get<uint32_t>();

			int64_t end = int64_t(dataOffset) + dataSize;
			if (end > start)
			{
				size -= end - start;
				start = end;
			}
		}
	}
	if (size <= 0) return std::nullopt;

	// Certificate table is always at the end of the file
	if (dirs_.size() > kDirSecurity) size -= dirs_[kDirSecurity].size;
	if (size <= 0) return std::nullopt;

	return Overlay{ uint64_t(start), uint64_t(size) };
}

// Returns the raw offset field (high bit set means subdirectory)
std::optional<uint32_t> PeFile::findEntry(uint64_t dirOffset, uint32_t id)
{
	file_.seek(dirOffset);
	Bytes header = file_.readBytes(16);
	ByteReader h(header);
	h.seek(12);
	uint16_t numNamed = h.get<uint16_t>();
	uint16_t numIds = h.get<uint16_t>();

	file_.skip(int64_t(numNamed) * 8);
	for (uint16_t i = 0; i < numIds; i++)
	{
		uint32_t entryId = file_.get<uint32_t>();
		uint32_t offset = file_.get<uint32_t>();
		if (entryId == id) return offset;
	}
	return std::nullopt;
}

std::optional<Bytes> PeFile::resource(uint32_t type, uint32_t id)
{
	if (dirs_.size() <= kDirResource || dirs_[kDirResource].rva == 0) return std::nullopt;

	auto base = rvaToOffset(dirs_[kDirResource].rva);
	if (!base) return std::nullopt;

	try
	{
		auto typeEntry = findEntry(*base, type);
		if (!typeEntry || !(*typeEntry & 0x80000000u)) return std::nullopt;

		auto nameEntry = findEntry(*base + (*typeEntry & 0x7FFFFFFFu), id);
		if (!nameEntry || !(*nameEntry & 0x80000000u)) return std::nullopt;

		// Third level is the language, take the first
		uint64_t langDir = *base + (*nameEntry & 0x7FFFFFFFu);
		file_.seek(langDir);
		Bytes header = file_.readBytes(16);
		ByteReader h(header);
		h.seek(12);
		uint32_t numEntries = uint32_t(h.get<uint16_t>()) + h.get<uint16_t>();
		if (numEntries == 0) return std::nullopt;

		file_.skip(4);
		uint32_t dataEntry = file_.get<uint32_t>();
		if (dataEntry & 0x80000000u) return std::nullopt;

		file_.seek(*base + dataEntry);
		uint32_t dataRva = file_.get<uint32_t>();
		uint32_t dataSize = file_.get<uint32_t>();

		auto dataOffset = rvaToOffset(dataRva);
		if (!dataOffset || dataSize > kMaxResourceSize || file_.size() - *dataOffset < dataSize)
			return std::nullopt;

		file_.seek(*dataOffset);
		return file_.readBytes(dataSize);
	}
	catch (const Error&)
	{
		return std::nullopt;
	}
}

std::string PeFile::manifest()
{
	auto data = resource(kResManifest, 1);
	return data ? std::string(data->begin(), data->end()) : std::string();
}

std::optional<VersionInfo> PeFile::versionInfo()
{
	auto data = resource(kResVersion, 1);
	if (!data) return std::nullopt;

	try
	{
		VerBlock root = readVerBlock(*data, 0, data->size());
		if (root.key != u"VS_VERSION_INFO") return std::nullopt;

		VersionInfo info;

		if (root.valueLength >= 52)
		{
			ByteReader v(data->data(), data->size());
			v.seek(root.valueOffset);
			if (v.get<uint32_t>() == 0xFEEF04BD)
			{
				v.skip(4);
				uint32_t fileVersionMS = v.get<uint32_t>();
				info.major = fileVersionMS >> 16;
				info.minor = fileVersionMS & 0xFFFF;
			}
		}

		for (const VerBlock& infoBlock : readVerChildren(*data, root))
		{
			if (infoBlock.key != u"StringFileInfo") continue;

			for (const VerBlock& table : readVerChildren(*data, infoBlock))
			{
				for (const VerBlock& str : readVerChildren(*data, table))
				{
					if (str.key != u"ProductName") continue;

					std::u16string value;
					for (size_t i = 0; i + 1 < str.valueLength; i += 2)
					{
						char16_t c = char16_t(data->at(str.valueOffset + i) | (data->at(str.valueOffset + i + 1) << 8));
						if (c == 0) break;
						value += c;
					}
					info.productName = narrow(value);
					return info;
				}
				break;
			}
		}
		return info;
	}
	catch (const Error&)
	{
		return std::nullopt;
	}
}

}
