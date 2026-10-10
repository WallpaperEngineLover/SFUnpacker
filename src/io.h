#pragma once

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sf {

using Bytes = std::vector<uint8_t>;

struct Error : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

uint32_t crc32(const uint8_t* data, size_t size, uint32_t crc = 0);

class FileReader
{
public:
	explicit FileReader(const std::filesystem::path& path);

	uint64_t size() const { return size_; }
	uint64_t pos() const { return pos_; }

	void seek(uint64_t offset);
	void skip(int64_t delta);
	void read(void* buf, size_t count);
	Bytes readBytes(uint64_t count);

	template <typename T>
	T get()
	{
		T value;
		read(&value, sizeof(value));
		return value;
	}

private:
	std::ifstream file_;
	uint64_t size_ = 0;
	uint64_t pos_ = 0;
};

class ByteReader
{
public:
	ByteReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}
	explicit ByteReader(const Bytes& bytes) : ByteReader(bytes.data(), bytes.size()) {}

	size_t pos() const { return pos_; }
	size_t size() const { return size_; }
	const uint8_t* data() const { return data_; }

	void seek(size_t offset)
	{
		if (offset > size_) throw Error("seek past end of buffer");
		pos_ = offset;
	}

	void skip(size_t count) { seek(pos_ + count); }

	template <typename T>
	T get()
	{
		if (size_ - pos_ < sizeof(T)) throw Error("unexpected end of buffer");
		T value;
		std::memcpy(&value, data_ + pos_, sizeof(T));
		pos_ += sizeof(T);
		return value;
	}

	std::string readChars(size_t count)
	{
		if (size_ - pos_ < count) throw Error("unexpected end of buffer");
		std::string s(reinterpret_cast<const char*>(data_ + pos_), count);
		pos_ += count;
		return s;
	}

	// length byte followed by the characters
	std::string readString() { return readChars(get<uint8_t>()); }

	void skipString() { skip(get<uint8_t>()); }

private:
	const uint8_t* data_;
	size_t size_;
	size_t pos_ = 0;
};

}
