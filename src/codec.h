#pragma once

#include "io.h"

namespace sf {

enum class Compression
{
	Unknown,
	None,
	PkWare,
	Lzma,
	Lzma2,
};

const char* compressionName(Compression c);

Bytes unpack(Compression method, const Bytes& packed);

}
