#include "io.h"

#include <array>

namespace sf {

static const std::array<uint32_t, 256>& crcTable()
{
	static const auto table = [] {
		std::array<uint32_t, 256> t{};
		for (uint32_t i = 0; i < 256; i++)
		{
			uint32_t c = i;
			for (int k = 0; k < 8; k++)
				c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
			t[i] = c;
		}
		return t;
	}();
	return table;
}

uint32_t crc32(const uint8_t* data, size_t size, uint32_t crc)
{
	const auto& table = crcTable();
	crc = ~crc;
	for (size_t i = 0; i < size; i++)
		crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
	return ~crc;
}

FileReader::FileReader(const std::filesystem::path& path) : file_(path, std::ios::binary)
{
	if (!file_) throw Error("cannot open " + path.string());

	file_.seekg(0, std::ios::end);
	std::streamoff end = file_.tellg();
	if (end < 0) throw Error("cannot determine size of " + path.string());
	size_ = static_cast<uint64_t>(end);
	file_.seekg(0);
}

void FileReader::seek(uint64_t offset)
{
	if (offset > size_) throw Error("seek past end of file");
	pos_ = offset;
}

void FileReader::skip(int64_t delta)
{
	int64_t target = static_cast<int64_t>(pos_) + delta;
	if (target < 0) throw Error("seek before start of file");
	seek(static_cast<uint64_t>(target));
}

void FileReader::read(void* buf, size_t count)
{
	if (size_ - pos_ < count) throw Error("unexpected end of file");
	file_.clear();
	file_.seekg(static_cast<std::streamoff>(pos_));
	file_.read(static_cast<char*>(buf), static_cast<std::streamsize>(count));
	if (!file_) throw Error("read error");
	pos_ += count;
}

Bytes FileReader::readBytes(uint64_t count)
{
	if (size_ - pos_ < count) throw Error("unexpected end of file");
	Bytes out(static_cast<size_t>(count));
	read(out.data(), out.size());
	return out;
}

}
