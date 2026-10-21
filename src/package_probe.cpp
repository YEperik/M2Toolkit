#include <array>
#include <algorithm>
#include <map>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

namespace {
constexpr std::size_t kDescriptorStart = 0x20U;
constexpr std::size_t kDescriptorSize = 0x20U;
constexpr std::size_t kHeaderSize = 0x20U;
constexpr std::uintmax_t kMaxInputBytes = 128ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxDescriptorCount = 1024U;

std::string hexValue(std::uint64_t value, int width = 0) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0');
    if (width > 0) out << std::setw(width);
    out << value;
    return out.str();
}

Bytes readFile(const fs::path& path) {
    std::error_code ec;
    const auto fileSize = fs::file_size(path, ec);
    if (ec) throw std::runtime_error("Tidak dapat membaca ukuran file '" + path.string() + "': " + ec.message());
    if (fileSize > kMaxInputBytes) throw std::runtime_error("File melewati batas pembacaan aman 128 MiB.");
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Tidak dapat membuka input: " + path.string());
    Bytes bytes;
    bytes.reserve(static_cast<std::size_t>(fileSize));
    char ch = 0;
    while (input.get(ch)) bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
    if (!input.eof() || bytes.size() != static_cast<std::size_t>(fileSize)) {
        throw std::runtime_error("Pembacaan file tidak lengkap: " + path.string());
    }
    return bytes;
}

void requireRange(const Bytes& bytes, const std::size_t offset, const std::size_t length, const std::string& context) {
    if (offset > bytes.size() || length > bytes.size() - offset) {
        throw std::runtime_error(context + ": rentang di luar file pada " + hexValue(offset) +
                                 " panjang " + hexValue(length));
    }
}

std::uint32_t readU32LE(const Bytes& bytes, const std::size_t offset, const std::string& context) {
    requireRange(bytes, offset, 4U, context);
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

std::string csvEscape(const std::string& value) {
    std::string out = "\"";
    for (const char ch : value) {
        if (ch == '"') out += "\"\"";
        else out += ch;
    }
    out += '"';
    return out;
}

std::string byteHex(const Bytes& bytes, const std::size_t begin, const std::size_t length) {
    requireRange(bytes, begin, length, "byteHex");
    std::ostringstream out;
    out << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0U; i < length; ++i) {
        if (i != 0U) out << ' ';
        out << std::setw(2) << static_cast<unsigned int>(bytes[begin + i]);
    }
    return out.str();
}

struct Descriptor {
    std::size_t index{};
    std::size_t descriptorOffset{};
    std::size_t start{};
    std::size_t partASize{};
    std::size_t partBSize{};
    std::array<std::uint32_t, 5U> extra{};
    std::size_t end{};
};

std::vector<Descriptor> parseDescriptors(const Bytes& bytes, std::uint32_t& tableEnd) {
    requireRange(bytes, 0U, kHeaderSize, "PACKAGE header");
    tableEnd = readU32LE(bytes, 0U, "PACKAGE table-end candidate");
    if (tableEnd <= kDescriptorStart || tableEnd > bytes.size()) {
        throw std::runtime_error("Nilai header +0x00 bukan batas tabel yang valid: " + hexValue(tableEnd));
    }
    const std::size_t tableLength = static_cast<std::size_t>(tableEnd) - kDescriptorStart;
    if ((tableLength % kDescriptorSize) != 0U) {
        throw std::runtime_error("Rentang descriptor tidak habis dibagi 0x20 byte.");
    }
    const std::size_t count = tableLength / kDescriptorSize;
    if (count == 0U || count > kMaxDescriptorCount) {
        throw std::runtime_error("Jumlah descriptor berada di luar batas aman.");
    }

    std::vector<Descriptor> result;
    result.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
        const std::size_t row = kDescriptorStart + i * kDescriptorSize;
        const std::uint32_t start32 = readU32LE(bytes, row, "descriptor start");
        const std::uint32_t partA32 = readU32LE(bytes, row + 4U, "descriptor Part A size");
        const std::uint32_t partB32 = readU32LE(bytes, row + 8U, "descriptor Part B size");
        const std::size_t start = static_cast<std::size_t>(start32);
        const std::size_t partA = static_cast<std::size_t>(partA32);
        const std::size_t partB = static_cast<std::size_t>(partB32);
        if (start < static_cast<std::size_t>(tableEnd) || start >= bytes.size()) {
            throw std::runtime_error("Start descriptor " + std::to_string(i) + " tidak valid: " + hexValue(start));
        }
        if (partA > std::numeric_limits<std::size_t>::max() - partB) {
            throw std::runtime_error("Overflow saat menjumlahkan ukuran descriptor " + std::to_string(i));
        }
        const std::size_t combined = partA + partB;
        if (combined > bytes.size() - start) {
            throw std::runtime_error("Part A+B descriptor " + std::to_string(i) + " melampaui file.");
        }

        Descriptor d;
        d.index = i;
        d.descriptorOffset = row;
        d.start = start;
        d.partASize = partA;
        d.partBSize = partB;
        for (std::size_t field = 0U; field < d.extra.size(); ++field) {
            d.extra[field] = readU32LE(bytes, row + 12U + field * 4U, "descriptor extra field");
        }
        d.end = start + combined;
        result.push_back(d);
    }

    for (std::size_t i = 0U; i < result.size(); ++i) {
        const std::size_t expectedEnd = (i + 1U < result.size()) ? result[i + 1U].start : bytes.size();
        if (i > 0U && result[i].start <= result[i - 1U].start) {
            throw std::runtime_error("Offset descriptor tidak naik secara ketat.");
        }
        if (result[i].end != expectedEnd) {
            throw std::runtime_error("Ukuran Part A+B descriptor " + std::to_string(i) +
                                     " tidak cocok dengan batas berikutnya: end=" + hexValue(result[i].end) +
                                     ", expected=" + hexValue(expectedEnd));
        }
    }
    return result;
}

void writeAll(const fs::path& path, const char* data, const std::size_t length) {
    if (fs::exists(path)) throw std::runtime_error("Menolak menimpa file output yang sudah ada: " + path.string());
    std::ofstream out(path, std::ios::binary | std::ios::out);
    if (!out) throw std::runtime_error("Tidak dapat membuat output: " + path.string());
    out.write(data, static_cast<std::streamsize>(length));
    if (!out) throw std::runtime_error("Gagal menulis output: " + path.string());
}

void writeText(const fs::path& path, const std::string& text) {
    writeAll(path, text.data(), text.size());
}

std::string makeCsv(const Bytes& bytes, const std::vector<Descriptor>& rows) {
    std::ostringstream out;
    out << "index,descriptor_offset_hex,chunk_start_hex,part_a_size_bytes,part_b_size_bytes,part_a_start_hex,part_b_start_hex,chunk_end_hex,next_start_hex,boundary_matches,part_a_first16_hex,part_b_first16_hex,extra0_raw_hex,extra1_raw_hex,extra2_raw_hex,extra3_raw_hex,extra4_raw_hex\n";
    for (std::size_t i = 0U; i < rows.size(); ++i) {
        const auto& r = rows[i];
        const std::size_t nextStart = (i + 1U < rows.size()) ? rows[i + 1U].start : bytes.size();
        out << r.index << ',' << csvEscape(hexValue(r.descriptorOffset, 4)) << ','
            << csvEscape(hexValue(r.start, 8)) << ',' << r.partASize << ',' << r.partBSize << ','
            << csvEscape(hexValue(r.start, 8)) << ','
            << csvEscape(hexValue(r.start + r.partASize, 8)) << ','
            << csvEscape(hexValue(r.end, 8)) << ',' << csvEscape(hexValue(nextStart, 8)) << ','
            << (r.end == nextStart ? "true" : "false") << ','
            << csvEscape(byteHex(bytes, r.start, std::min<std::size_t>(16U, r.partASize))) << ','
            << csvEscape(byteHex(bytes, r.start + r.partASize, std::min<std::size_t>(16U, r.partBSize)));
        for (const auto extra : r.extra) out << ',' << csvEscape(hexValue(extra, 8));
        out << '\n';
    }
    return out.str();
}

std::uint64_t readU64LE(const Bytes& bytes, const std::size_t offset, const std::string& context) {
    const std::uint64_t low = readU32LE(bytes, offset, context);
    const std::uint64_t high = readU32LE(bytes, offset + 4U, context);
    return low | (high << 32U);
}

struct DmaTagRecord {
    std::size_t chunkIndex{};
    std::size_t tagIndex{};
    std::size_t offsetInPartA{};
    std::size_t sourcePackageOffset{};
    std::uint32_t word0{};
    std::uint32_t qwc{};
    std::uint32_t id{};
    std::uint32_t word1{};
    std::uint32_t word2{};
    std::uint32_t word3{};
    std::size_t payloadOffsetInPartA{};
    std::size_t payloadBytes{};
    std::size_t nextTagOffsetInPartA{};
    bool hasNextTag{};
    std::string role;
};

struct TextureUpload {
    std::size_t index{};
    std::size_t chunkIndex{};
    std::size_t setupTagOffsetInPartA{};
    std::size_t dataTagOffsetInPartA{};
    std::size_t payloadOffsetInPartA{};
    std::size_t payloadOffsetInPackage{};
    std::size_t payloadBytes{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t psm{};
    std::uint32_t bitsPerPixel{};
    std::uint32_t dbp{};
    std::uint32_t dbw{};
    std::uint64_t bitbltbuf{};
    std::uint64_t trxpos{};
    std::uint64_t trxreg{};
    std::uint64_t trxdir{};
    std::uint32_t gifImageNloop{};
    std::uint32_t gifImageFlg{};
    std::uint32_t gifImageEop{};
    std::uint64_t expectedBytes{};
    std::string payloadFilename;
};

struct DmaAnalysis {
    std::vector<DmaTagRecord> tags;
    std::vector<TextureUpload> textures;
    std::map<std::uint32_t, std::size_t> psmCounts;
};

std::string psmName(const std::uint32_t psm) {
    switch (psm) {
        case 0x00U: return "PSMCT32";
        case 0x13U: return "PSMT8";
        case 0x14U: return "PSMT4";
        default: return "PSM_UNKNOWN";
    }
}

std::string dmaIdName(const std::uint32_t id) {
    switch (id) {
        case 0U: return "REFE";
        case 1U: return "CNT";
        case 2U: return "NEXT";
        case 3U: return "REF";
        case 4U: return "REFS";
        case 5U: return "CALL";
        case 6U: return "RET";
        case 7U: return "END";
        default: return "UNKNOWN";
    }
}

DmaAnalysis analyzeDmaAndTextures(const Bytes& bytes, const std::vector<Descriptor>& descriptors) {
    DmaAnalysis result;
    for (const auto& descriptor : descriptors) {
        const std::size_t base = descriptor.start;
        const std::size_t partSize = descriptor.partASize;
        std::size_t offset = 0U;
        std::size_t localTagIndex = 0U;
        bool foundRet = false;

        while (offset < partSize) {
            requireRange(bytes, base + offset, 16U, "DMA tag pada Part A chunk " + std::to_string(descriptor.index));
            const std::uint32_t word0 = readU32LE(bytes, base + offset, "DMA tag word0");
            const std::uint32_t word1 = readU32LE(bytes, base + offset + 4U, "DMA tag word1");
            const std::uint32_t word2 = readU32LE(bytes, base + offset + 8U, "DMA tag word2");
            const std::uint32_t word3 = readU32LE(bytes, base + offset + 12U, "DMA tag word3");
            const std::uint32_t qwc = word0 & 0xFFFFU;
            const std::uint32_t id = (word0 >> 28U) & 0x7U;

            if (id == 6U) { // RET; the supplied chains end with an empty return/stop tag.
                if (qwc != 0U || offset + 16U != partSize || word1 != 0U || word2 != 0U || word3 != 0U) {
                    throw std::runtime_error("Tag RET tidak berada sebagai tag 16-byte terakhir pada Part A chunk " +
                                             std::to_string(descriptor.index) + " di " + hexValue(offset));
                }
                result.tags.push_back(DmaTagRecord{descriptor.index, localTagIndex, offset, base + offset,
                    word0, qwc, id, word1, word2, word3, offset + 16U, 0U, 0U, false, "RET terminal"});
                ++localTagIndex;
                offset += 16U;
                foundRet = true;
                break;
            }

            // This exact sample uses inline CNT tags which wrap a VIF FLUSHA + DIRECT 6 setup packet,
            // followed by a second CNT tag that carries one GIF IMAGE payload.
            if (id != 1U || qwc != 6U || word2 != 0x13000000U || word3 != 0x50000006U) {
                throw std::runtime_error("Tag Part A tidak cocok dengan pola CNT/FLUSHA/DIRECT terukur pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(offset) +
                                         "; parser berhenti tanpa menebak tipe tag lain.");
            }
            const std::size_t setupPayload = base + offset + 16U;
            constexpr std::size_t kSetupPayloadBytes = 6U * 16U;
            requireRange(bytes, setupPayload, kSetupPayloadBytes, "payload setup VIF/GIF");

            const std::uint64_t setupGifTag = readU64LE(bytes, setupPayload, "GIFtag setup");
            const std::uint32_t setupNloop = static_cast<std::uint32_t>(setupGifTag & 0x7FFFU);
            const std::uint32_t setupEop = static_cast<std::uint32_t>((setupGifTag >> 15U) & 0x1U);
            const std::uint32_t setupFlg = static_cast<std::uint32_t>((setupGifTag >> 58U) & 0x3U);
            const std::uint32_t setupNreg = static_cast<std::uint32_t>((setupGifTag >> 60U) & 0xFU);
            const std::uint64_t setupRegDesc = readU64LE(bytes, setupPayload + 8U, "GIFtag register descriptor");
            if (setupNloop != 4U || setupEop != 0U || setupFlg != 0U || setupNreg != 1U || setupRegDesc != 0xEU) {
                throw std::runtime_error("GIFtag setup bukan pola PACKED NLOOP=4/NREG=1/A+D pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(offset));
            }

            std::array<std::uint64_t, 4U> gsValues{};
            for (std::size_t regIndex = 0U; regIndex < gsValues.size(); ++regIndex) {
                const std::size_t qword = setupPayload + (regIndex + 1U) * 16U;
                gsValues[regIndex] = readU64LE(bytes, qword, "GS A+D value");
                const std::uint64_t registerId = readU64LE(bytes, qword + 8U, "GS A+D register id");
                const std::uint64_t expectedRegister = 0x50U + regIndex;
                if (registerId != expectedRegister) {
                    throw std::runtime_error("Register A+D tidak berurutan BITBLTBUF/TRXPOS/TRXREG/TRXDIR pada chunk " +
                                             std::to_string(descriptor.index) + " di " + hexValue(offset));
                }
            }
            const std::uint64_t bitbltbuf = gsValues[0];
            const std::uint64_t trxpos = gsValues[1];
            const std::uint64_t trxreg = gsValues[2];
            const std::uint64_t trxdir = gsValues[3];
            if (trxdir != 0U) {
                throw std::runtime_error("TRXDIR bukan transfer host-to-local yang terduga pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(offset));
            }
            const std::uint32_t width = static_cast<std::uint32_t>(trxreg & 0xFFFU);
            const std::uint32_t height = static_cast<std::uint32_t>((trxreg >> 32U) & 0xFFFU);
            const std::uint32_t psm = static_cast<std::uint32_t>((bitbltbuf >> 56U) & 0x3FU);
            std::uint32_t bitsPerPixel = 0U;
            switch (psm) {
                case 0x00U: bitsPerPixel = 32U; break;
                case 0x13U: bitsPerPixel = 8U; break;
                case 0x14U: bitsPerPixel = 4U; break;
                default:
                    throw std::runtime_error("PSM belum didukung dalam validasi ukuran pixel: " + hexValue(psm) +
                                             " pada chunk " + std::to_string(descriptor.index));
            }
            if (width == 0U || height == 0U) {
                throw std::runtime_error("TRXREG memiliki lebar/tinggi nol pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(offset));
            }

            const std::size_t imageTagOffset = setupPayload + 5U * 16U;
            const std::uint64_t imageGifTag = readU64LE(bytes, imageTagOffset, "GIFtag IMAGE");
            const std::uint32_t imageNloop = static_cast<std::uint32_t>(imageGifTag & 0x7FFFU);
            const std::uint32_t imageEop = static_cast<std::uint32_t>((imageGifTag >> 15U) & 0x1U);
            const std::uint32_t imageFlg = static_cast<std::uint32_t>((imageGifTag >> 58U) & 0x3U);
            if (imageNloop == 0U || imageEop != 1U || imageFlg != 2U) {
                throw std::runtime_error("GIFtag payload bukan IMAGE dengan EOP pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(offset));
            }

            const std::size_t dataTagOffset = offset + 16U + kSetupPayloadBytes;
            requireRange(bytes, base + dataTagOffset, 16U, "DMA tag data image");
            const std::uint32_t dataWord0 = readU32LE(bytes, base + dataTagOffset, "DMA data word0");
            const std::uint32_t dataWord1 = readU32LE(bytes, base + dataTagOffset + 4U, "DMA data word1");
            const std::uint32_t dataWord2 = readU32LE(bytes, base + dataTagOffset + 8U, "DMA data word2");
            const std::uint32_t dataWord3 = readU32LE(bytes, base + dataTagOffset + 12U, "DMA data word3");
            const std::uint32_t dataQwc = dataWord0 & 0xFFFFU;
            const std::uint32_t dataId = (dataWord0 >> 28U) & 0x7U;
            if (dataId != 1U || dataQwc != imageNloop || dataWord2 != 0U ||
                dataWord3 != (0x50000000U | dataQwc)) {
                throw std::runtime_error("DMA/VIF DIRECT count tidak sama dengan GIF IMAGE NLOOP pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(dataTagOffset));
            }
            const std::size_t payloadBytes = static_cast<std::size_t>(dataQwc) * 16U;
            const std::size_t payloadOffset = dataTagOffset + 16U;
            requireRange(bytes, base + payloadOffset, payloadBytes, "payload pixel GS");

            const std::uint64_t expectedBits = static_cast<std::uint64_t>(width) *
                                               static_cast<std::uint64_t>(height) *
                                               static_cast<std::uint64_t>(bitsPerPixel);
            if ((expectedBits % 8U) != 0U) {
                throw std::runtime_error("Ukuran pixel tidak sejajar byte pada chunk " +
                                         std::to_string(descriptor.index));
            }
            const std::uint64_t expectedBytes = expectedBits / 8U;
            if (expectedBytes != payloadBytes) {
                throw std::runtime_error("Ukuran payload tidak cocok dengan TRXREG/PSM pada chunk " +
                                         std::to_string(descriptor.index) + " di " + hexValue(offset) +
                                         ": payload=" + std::to_string(payloadBytes) +
                                         ", expected=" + std::to_string(expectedBytes));
            }

            const std::size_t absoluteTagOffset = base + offset;
            const std::size_t nextTagAfterSetup = dataTagOffset;
            result.tags.push_back(DmaTagRecord{descriptor.index, localTagIndex, offset, absoluteTagOffset,
                word0, qwc, id, word1, word2, word3, offset + 16U, kSetupPayloadBytes,
                nextTagAfterSetup, true, "VIF FLUSHA + DIRECT setup"});
            ++localTagIndex;
            const std::size_t nextTagAfterData = payloadOffset + payloadBytes;
            result.tags.push_back(DmaTagRecord{descriptor.index, localTagIndex, dataTagOffset,
                base + dataTagOffset, dataWord0, dataQwc, dataId, dataWord1, dataWord2, dataWord3,
                payloadOffset, payloadBytes, nextTagAfterData, true, "VIF DIRECT + GIF IMAGE payload"});
            ++localTagIndex;

            TextureUpload upload;
            upload.index = result.textures.size();
            upload.chunkIndex = descriptor.index;
            upload.setupTagOffsetInPartA = offset;
            upload.dataTagOffsetInPartA = dataTagOffset;
            upload.payloadOffsetInPartA = payloadOffset;
            upload.payloadOffsetInPackage = base + payloadOffset;
            upload.payloadBytes = payloadBytes;
            upload.width = width;
            upload.height = height;
            upload.psm = psm;
            upload.bitsPerPixel = bitsPerPixel;
            upload.dbp = static_cast<std::uint32_t>((bitbltbuf >> 32U) & 0x3FFFU);
            upload.dbw = static_cast<std::uint32_t>((bitbltbuf >> 48U) & 0x3FU);
            upload.bitbltbuf = bitbltbuf;
            upload.trxpos = trxpos;
            upload.trxreg = trxreg;
            upload.trxdir = trxdir;
            upload.gifImageNloop = imageNloop;
            upload.gifImageFlg = imageFlg;
            upload.gifImageEop = imageEop;
            upload.expectedBytes = expectedBytes;
            std::ostringstream payloadName;
            payloadName << "tex_" << std::setw(4) << std::setfill('0') << upload.index
                        << "_chunk_" << std::setw(2) << std::setfill('0') << upload.chunkIndex
                        << '_' << upload.width << 'x' << upload.height << '_' << psmName(upload.psm) << ".bin";
            upload.payloadFilename = payloadName.str();
            result.psmCounts[psm] += 1U;
            result.textures.push_back(upload);

            offset = nextTagAfterData;
        }
        if (!foundRet || offset != partSize) {
            throw std::runtime_error("Rantai DMA Part A tidak berhenti tepat pada RET terakhir di chunk " +
                                     std::to_string(descriptor.index));
        }
    }
    return result;
}

std::string makeTextureCsv(const DmaAnalysis& analysis) {
    std::ostringstream out;
    out << "texture_index,chunk_index,setup_tag_offset_in_part_a_hex,data_tag_offset_in_part_a_hex,payload_offset_in_part_a_hex,payload_offset_in_package_hex,payload_size_bytes,width,height,psm_code_hex,psm_name,bits_per_pixel,dbp_units,dbw_units,bitbltbuf_raw_hex,trxpos_raw_hex,trxreg_raw_hex,trxdir_raw_hex,gif_image_nloop,gif_image_flg,gif_image_eop,expected_size_bytes,dimensions_match,payload_file\n";
    for (const auto& t : analysis.textures) {
        out << t.index << ',' << t.chunkIndex << ','
            << csvEscape(hexValue(t.setupTagOffsetInPartA, 8)) << ','
            << csvEscape(hexValue(t.dataTagOffsetInPartA, 8)) << ','
            << csvEscape(hexValue(t.payloadOffsetInPartA, 8)) << ','
            << csvEscape(hexValue(t.payloadOffsetInPackage, 8)) << ','
            << t.payloadBytes << ',' << t.width << ',' << t.height << ','
            << csvEscape(hexValue(t.psm, 2)) << ',' << psmName(t.psm) << ',' << t.bitsPerPixel << ','
            << t.dbp << ',' << t.dbw << ','
            << csvEscape(hexValue(t.bitbltbuf, 16)) << ','
            << csvEscape(hexValue(t.trxpos, 16)) << ','
            << csvEscape(hexValue(t.trxreg, 16)) << ','
            << csvEscape(hexValue(t.trxdir, 16)) << ','
            << t.gifImageNloop << ',' << t.gifImageFlg << ',' << t.gifImageEop << ','
            << t.expectedBytes << ",true," << csvEscape(t.payloadFilename) << '\n';
    }
    return out.str();
}

std::string makeDmaTagsCsv(const DmaAnalysis& analysis) {
    std::ostringstream out;
    out << "chunk_index,tag_index,part_a_offset_hex,source_package_offset_hex,word0_raw_hex,qwc,id,id_name,word1_raw_hex,word2_raw_hex,word3_raw_hex,payload_offset_in_part_a_hex,payload_bytes,next_tag_offset_in_part_a_hex,role\n";
    for (const auto& t : analysis.tags) {
        out << t.chunkIndex << ',' << t.tagIndex << ','
            << csvEscape(hexValue(t.offsetInPartA, 8)) << ','
            << csvEscape(hexValue(t.sourcePackageOffset, 8)) << ','
            << csvEscape(hexValue(t.word0, 8)) << ',' << t.qwc << ',' << t.id << ',' << dmaIdName(t.id) << ','
            << csvEscape(hexValue(t.word1, 8)) << ',' << csvEscape(hexValue(t.word2, 8)) << ','
            << csvEscape(hexValue(t.word3, 8)) << ',';
        if (t.id == 6U) out << ',';
        else out << csvEscape(hexValue(t.payloadOffsetInPartA, 8)) << ',';
        out << t.payloadBytes << ',';
        if (t.hasNextTag) out << csvEscape(hexValue(t.nextTagOffsetInPartA, 8));
        out << ',' << csvEscape(t.role) << '\n';
    }
    return out.str();
}

std::string makeReport(const Bytes& bytes, const std::vector<Descriptor>& rows, const std::uint32_t tableEnd,
                       const DmaAnalysis& analysis) {
    std::ostringstream out;
    out << "PACKAGE.BIN — laporan pemetaan chunk dan transfer tekstur read-only\n"
        << "===============================================================\n\n"
        << "Ukuran file: " << bytes.size() << " byte (" << hexValue(bytes.size()) << ")\n"
        << "Header +0x00 (batas akhir tabel kandidat): " << hexValue(tableEnd) << "\n"
        << "Header +0x04 (nilai mentah): " << hexValue(readU32LE(bytes, 4U, "header")) << "\n"
        << "Header +0x08 (nilai mentah): " << hexValue(readU32LE(bytes, 8U, "header")) << "\n"
        << "Descriptor mulai 0x20, stride 0x20, jumlah " << rows.size() << ".\n"
        << "Rentang sebelum chunk pertama: " << hexValue(rows.front().start - tableEnd)
        << " byte setelah akhir descriptor table.\n\n"
        << "Validasi batas chunk:\n";
    std::size_t totalA = 0U;
    std::size_t totalB = 0U;
    std::size_t samePrefix32 = 0U;
    for (const auto& r : rows) {
        totalA += r.partASize;
        totalB += r.partBSize;
        if (r.start + 32U <= bytes.size() && r.partASize >= 32U &&
            byteHex(bytes, r.start, 32U) == byteHex(bytes, rows.front().start, 32U)) ++samePrefix32;
    }
    out << "  Chunk: " << rows.size() << "/" << rows.size() << " memiliki batas end yang sama persis dengan start berikutnya/EOF.\n"
        << "  Jumlah Part A: " << totalA << " byte.\n"
        << "  Jumlah Part B: " << totalB << " byte.\n"
        << "  Awalan 32 byte Part A yang identik dengan chunk pertama: " << samePrefix32 << "/" << rows.size() << ".\n"
        << "  Semua potongan mentah identik dengan rentang sumber; tidak ada dekompresi atau penulisan balik ke game.\n\n"
        << "Validasi rantai PS2 VIF/DMA/GIF pada Part A:\n"
        << "  Tag DMA terpetakan: " << analysis.tags.size() << ".\n"
        << "  Transfer image terpetakan: " << analysis.textures.size() << ".\n"
        << "  Semua Part A berakhir pada tag RET berukuran 16 byte dengan QWC=0 tepat di EOF bagian.\n"
        << "  Setiap transfer memiliki pola VIF FLUSHA + DIRECT 6, GIF PACKED A+D dengan register 0x50..0x53,\n"
        << "  GIF IMAGE (FLG=2/EOP=1), dan tag DIRECT berikutnya dengan QWC sama dengan GIF NLOOP.\n"
        << "  Payload byte cocok tepat dengan lebar × tinggi × bits-per-pixel yang ditentukan TRXREG dan PSM.\n"
        << "  Distribusi format pixel (PSM):\n";
    for (const auto& [psm, count] : analysis.psmCounts) {
        out << "    " << psmName(psm) << " (" << hexValue(psm, 2) << "): " << count << " transfer.\n";
    }
    out << "\nBatas interpretasi:\n"
        << "  * Kesimpulan Part A sebagai rangkaian transfer gambar GS didukung oleh bitfield PS2 DMA/VIF/GIF,\n"
        << "    register BITBLTBUF/TRXPOS/TRXREG/TRXDIR, dan kecocokan ukuran pada seluruh transfer sampel ini.\n"
        << "  * File payload .bin adalah byte image-transfer mentah, bukan PNG dan tidak menyertakan palette hasil decode.\n"
        << "  * Nilai DBP/DBW menunjukkan lokasi/stride tujuan GS; hubungan ke material atau model belum dipetakan.\n"
        << "  * Part B, field descriptor lainnya, teks/dialog, video, serta model/mesh masih belum terpecahkan.\n"
        << "  * Keberhasilan ekstraksi tidak berarti file hasil perubahan akan kompatibel dengan game.\n\n"
        << "Output: package_catalog.csv, package_report.txt, dma_chain_tags.csv, texture_uploads.csv,\n"
        << "chunk_NN_part_a.bin, chunk_NN_part_b.bin, dan texture_payloads/*.bin.\n";
    return out.str();
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            std::cerr << "Pemakaian: " << argv[0] << " <PACKAGE.BIN> <direktori-output-baru-atau-kosong>\n";
            return 2;
        }
        const fs::path inputPath(argv[1]);
        const fs::path outputDir(argv[2]);
        if (fs::exists(outputDir) && !fs::is_directory(outputDir)) {
            throw std::runtime_error("Path output bukan direktori: " + outputDir.string());
        }
        if (fs::exists(outputDir) && fs::directory_iterator(outputDir) != fs::directory_iterator()) {
            throw std::runtime_error("Direktori output harus kosong agar tidak menimpa atau mencampur hasil lama.");
        }

        const Bytes bytes = readFile(inputPath);
        std::uint32_t tableEnd = 0U;
        const auto rows = parseDescriptors(bytes, tableEnd);
        // Analyze the entire DMA/image pattern before creating outputs. Unknown patterns fail closed.
        const DmaAnalysis analysis = analyzeDmaAndTextures(bytes, rows);
        fs::create_directories(outputDir);
        const fs::path textureDir = outputDir / "texture_payloads";
        fs::create_directory(textureDir);

        for (const auto& r : rows) {
            std::ostringstream name;
            name << "chunk_" << std::setw(2) << std::setfill('0') << r.index;
            const fs::path partAPath = outputDir / (name.str() + "_part_a.bin");
            const fs::path partBPath = outputDir / (name.str() + "_part_b.bin");
            writeAll(partAPath, reinterpret_cast<const char*>(bytes.data() + r.start), r.partASize);
            writeAll(partBPath, reinterpret_cast<const char*>(bytes.data() + r.start + r.partASize), r.partBSize);
        }
        writeText(outputDir / "package_catalog.csv", makeCsv(bytes, rows));
        writeText(outputDir / "package_report.txt", makeReport(bytes, rows, tableEnd, analysis));
        writeText(outputDir / "dma_chain_tags.csv", makeDmaTagsCsv(analysis));
        writeText(outputDir / "texture_uploads.csv", makeTextureCsv(analysis));
        for (const auto& texture : analysis.textures) {
            writeAll(textureDir / texture.payloadFilename,
                     reinterpret_cast<const char*>(bytes.data() + texture.payloadOffsetInPackage),
                     texture.payloadBytes);
        }

        std::cout << "PACKAGE.BIN dianalisis read-only: " << rows.size() << " chunk, "
                  << (rows.size() * 2U) << " bagian mentah, " << analysis.textures.size()
                  << " payload transfer gambar, dan " << analysis.tags.size() << " tag DMA tercatat.\n"
                  << "Semua payload transfer diekstrak byte-per-byte; file sumber tidak diubah.\n"
                  << "Output: " << fs::absolute(outputDir).string() << "\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << '\n';
        return 1;
    }
}
