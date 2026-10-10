#include "codec.h"

extern "C"
{
#include "blast.h"
#include "Alloc.h"
#include "Lzma2Dec.h"
#include "LzmaDec.h"
}

#include <new>

namespace sf {

const char* compressionName(Compression c)
{
	switch (c)
	{
	case Compression::None: return "None";
	case Compression::PkWare: return "PKWare DCL";
	case Compression::Lzma: return "LZMA";
	case Compression::Lzma2: return "LZMA2";
	default: return "Unknown";
	}
}

namespace {

struct BlastState
{
	const Bytes* in;
	Bytes out;
};

unsigned blastIn(void* how, unsigned char** buf)
{
	auto* st = static_cast<BlastState*>(how);
	*buf = const_cast<unsigned char*>(st->in->data());
	return static_cast<unsigned>(st->in->size());
}

int blastOut(void* how, unsigned char* buf, unsigned len)
{
	auto* st = static_cast<BlastState*>(how);
	st->out.insert(st->out.end(), buf, buf + len);
	return 0;
}

Bytes explode(const Bytes& packed)
{
	BlastState st{ &packed, {} };
	if (blast(blastIn, &st, blastOut, &st) != 0) throw Error("PKWare DCL stream is corrupt");
	return std::move(st.out);
}

// Layout for both variants: props, int64 unpacked size, raw stream
template <size_t PropsSize, typename DecodeFn>
Bytes decodeSized(const Bytes& packed, DecodeFn decode)
{
	constexpr size_t headerSize = PropsSize + sizeof(int64_t);
	if (packed.size() < headerSize) throw Error("compressed stream is too short");

	int64_t unpackedSize;
	std::memcpy(&unpackedSize, packed.data() + PropsSize, sizeof(unpackedSize));
	if (unpackedSize < 0) throw Error("invalid unpacked size");

	Bytes out;
	try
	{
		out.resize(static_cast<size_t>(unpackedSize));
	}
	catch (const std::bad_alloc&)
	{
		throw Error("unpacked size is too large");
	}

	size_t outLen = out.size();
	size_t inLen = packed.size() - headerSize;
	ELzmaStatus status;
	SRes res = decode(out.data(), &outLen, packed.data() + headerSize, &inLen, packed.data(), &status);
	if (res != SZ_OK) throw Error("LZMA stream is corrupt");

	out.resize(outLen);
	return out;
}

}

Bytes unpack(Compression method, const Bytes& packed)
{
	switch (method)
	{
	case Compression::None:
		return packed;

	case Compression::PkWare:
		return explode(packed);

	case Compression::Lzma:
		return decodeSized<LZMA_PROPS_SIZE>(packed, [](Byte* dest, SizeT* destLen, const Byte* src, SizeT* srcLen, const Byte* props, ELzmaStatus* status) {
			return LzmaDecode(dest, destLen, src, srcLen, props, LZMA_PROPS_SIZE, LZMA_FINISH_ANY, status, &g_Alloc);
		});

	case Compression::Lzma2:
		return decodeSized<1>(packed, [](Byte* dest, SizeT* destLen, const Byte* src, SizeT* srcLen, const Byte* props, ELzmaStatus* status) {
			return Lzma2Decode(dest, destLen, src, srcLen, props[0], LZMA_FINISH_ANY, status, &g_Alloc);
		});

	default:
		throw Error("unknown compression method");
	}
}

}
