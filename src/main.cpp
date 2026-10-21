#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

namespace {
constexpr std::uintmax_t kMaxInputBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::size_t kU16Bytes = 2U;
constexpr std::size_t kU32Bytes = 4U;
constexpr std::size_t kMaxBlockCount = 32U;

enum class FormatKind { Words, Wordseve };

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
    if (ec) {
        throw std::runtime_error("Tidak dapat membaca ukuran file '" + path.string() + "': " + ec.message());
    }
    if (fileSize > kMaxInputBytes) {
        throw std::runtime_error("File melewati batas aman pembacaan 256 MiB: " + path.string());
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Tidak dapat membuka file: " + path.string());

    Bytes bytes;
    bytes.reserve(static_cast<std::size_t>(fileSize));
    char ch = 0;
    while (input.get(ch)) bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
    if (!input.eof()) throw std::runtime_error("Gagal membaca seluruh file: " + path.string());
    if (bytes.size() != static_cast<std::size_t>(fileSize)) {
        throw std::runtime_error("Ukuran hasil baca tidak sama dengan ukuran file: " + path.string());
    }
    return bytes;
}

void requireRange(const Bytes& bytes, std::size_t offset, std::size_t length, const std::string& context) {
    if (offset > bytes.size() || length > bytes.size() - offset) {
        throw std::runtime_error(context + ": rentang di luar file (offset=" + hexValue(offset) +
                                 ", length=" + hexValue(length) + ", file_size=" + hexValue(bytes.size()) + ")");
    }
}

std::uint16_t readU16LE(const Bytes& bytes, std::size_t offset, const std::string& context) {
    requireRange(bytes, offset, kU16Bytes, context);
    const auto lo = static_cast<std::uint16_t>(bytes[offset]);
    const auto hi = static_cast<std::uint16_t>(bytes[offset + 1U]);
    return static_cast<std::uint16_t>(lo | static_cast<std::uint16_t>(hi << 8U));
}

std::uint32_t readU32LE(const Bytes& bytes, std::size_t offset, const std::string& context) {
    requireRange(bytes, offset, kU32Bytes, context);
    const std::uint32_t b0 = static_cast<std::uint32_t>(bytes[offset]);
    const std::uint32_t b1 = static_cast<std::uint32_t>(bytes[offset + 1U]);
    const std::uint32_t b2 = static_cast<std::uint32_t>(bytes[offset + 2U]);
    const std::uint32_t b3 = static_cast<std::uint32_t>(bytes[offset + 3U]);
    return b0 | (b1 << 8U) | (b2 << 16U) | (b3 << 24U);
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

void writeTextFile(const fs::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Tidak dapat membuat output: " + path.string());
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) throw std::runtime_error("Gagal menulis output: " + path.string());
}

bool isPrintableAscii(const Bytes& bytes, std::size_t begin, std::size_t end) {
    if (end < begin || end > bytes.size()) return false;
    for (std::size_t i = begin; i < end; ++i) {
        if (bytes[i] < 0x20U || bytes[i] > 0x7EU) return false;
    }
    return true;
}

struct BlockInfo {
    std::size_t index{};
    std::size_t base{};
    std::size_t end{};
    std::uint32_t nextPointer{};
    std::vector<std::uint32_t> sectionOffsets;
    std::size_t tableBeginRelative{};
    std::size_t tableEndRelative{};
};

std::vector<BlockInfo> walkBlockChain(const Bytes& bytes, FormatKind kind, const std::string& fileLabel) {
    std::vector<BlockInfo> blocks;
    std::set<std::size_t> visited;
    std::size_t base = 0U;

    while (true) {
        if (blocks.size() >= kMaxBlockCount) {
            throw std::runtime_error(fileLabel + ": melebihi batas aman " + std::to_string(kMaxBlockCount) + " blok.");
        }
        if (!visited.insert(base).second) {
            throw std::runtime_error(fileLabel + ": pointer blok membentuk siklus pada " + hexValue(base) + ".");
        }
        requireRange(bytes, base, 0x24U, fileLabel + " block header candidate");

        const std::uint32_t next = readU32LE(bytes, base, fileLabel + " first-word pointer candidate");
        std::vector<std::uint32_t> sections;
        sections.reserve(7U);
        for (std::size_t field = 0x04U; field <= 0x1CU; field += kU32Bytes) {
            sections.push_back(readU32LE(bytes, base + field, fileLabel + " section-offset candidate"));
        }
        for (std::size_t i = 0U; i < sections.size(); ++i) {
            if (i > 0U && sections[i] <= sections[i - 1U]) {
                throw std::runtime_error(fileLabel + ": kandidat batas bagian tidak naik pada blok " + hexValue(base) + ".");
            }
        }

        std::size_t tableBeginRelative = 0U;
        std::size_t tableEndRelative = 0U;
        if (kind == FormatKind::Words) {
            // Supplied WORDS sample: the candidate uint16 region lies between relative offsets 0x338 and 0x4F8.
            tableBeginRelative = static_cast<std::size_t>(sections.at(5U));
            tableEndRelative = static_cast<std::size_t>(sections.at(6U));
        } else {
            // Supplied WORDSEVE sample: offset table starts at the last header candidate; its end is u32 at block + 0x20.
            tableBeginRelative = static_cast<std::size_t>(sections.back());
            tableEndRelative = static_cast<std::size_t>(readU32LE(bytes, base + 0x20U, fileLabel + " table-end candidate"));
        }
        if (tableBeginRelative >= tableEndRelative) {
            throw std::runtime_error(fileLabel + ": kandidat rentang tabel tidak valid pada blok " + hexValue(base) + ".");
        }
        if (base > bytes.size() || tableEndRelative > bytes.size() - base) {
            throw std::runtime_error(fileLabel + ": rentang tabel melewati akhir file pada blok " + hexValue(base) + ".");
        }
        if (((tableEndRelative - tableBeginRelative) % kU16Bytes) != 0U) {
            throw std::runtime_error(fileLabel + ": rentang kandidat tabel bukan kelipatan 2 byte pada blok " + hexValue(base) + ".");
        }

        const std::size_t end = next == 0U ? bytes.size() : static_cast<std::size_t>(next);
        if (end <= base || end > bytes.size()) {
            throw std::runtime_error(fileLabel + ": pointer blok berikutnya di luar file atau tidak maju: " + hexValue(next) + ".");
        }
        if (base + tableEndRelative > end) {
            throw std::runtime_error(fileLabel + ": rentang tabel melintasi batas blok yang dikandidatkan pada " + hexValue(base) + ".");
        }

        BlockInfo info;
        info.index = blocks.size();
        info.base = base;
        info.end = end;
        info.nextPointer = next;
        info.sectionOffsets = sections;
        info.tableBeginRelative = tableBeginRelative;
        info.tableEndRelative = tableEndRelative;
        blocks.push_back(std::move(info));

        if (next == 0U) break;
        const std::size_t nextBase = static_cast<std::size_t>(next);
        if (nextBase <= base || nextBase >= bytes.size()) {
            throw std::runtime_error(fileLabel + ": kandidat pointer blok berikutnya tidak valid: " + hexValue(next) + ".");
        }
        base = nextBase;
    }

    return blocks;
}

struct ParsedString {
    std::size_t blockIndex{};
    std::size_t tableIndex{};
    std::size_t tableEntryOffset{};
    std::uint16_t relativeOffset{};
    std::size_t absoluteOffset{};
    std::size_t length{};
    std::string text;
};

std::optional<std::vector<ParsedString>> tryParseWordseveStringOffsets(const Bytes& bytes, const BlockInfo& block) {
    const std::size_t tableBegin = block.base + block.tableBeginRelative;
    const std::size_t tableEnd = block.base + block.tableEndRelative;
    const std::size_t tableBytes = tableEnd - tableBegin;
    const std::size_t entryCount = tableBytes / kU16Bytes;
    if (entryCount == 0U || entryCount > 4096U) return std::nullopt;

    // Candidate design: four bytes after the offset table precede a possible NUL-terminated string pool.
    constexpr std::size_t kObservedStringPreambleBytes = 4U;
    if (block.tableEndRelative > block.end - block.base ||
        kObservedStringPreambleBytes > block.end - (block.base + block.tableEndRelative)) {
        return std::nullopt;
    }
    const std::size_t stringBase = block.base + block.tableEndRelative + kObservedStringPreambleBytes;

    std::vector<ParsedString> parsed;
    parsed.reserve(entryCount);
    for (std::size_t i = 0U; i < entryCount; ++i) {
        const std::size_t entryOffset = tableBegin + i * kU16Bytes;
        const std::uint16_t relative = readU16LE(bytes, entryOffset, "WORDSEVE offset table entry");
        const std::size_t relativeSize = static_cast<std::size_t>(relative);
        if (stringBase > block.end || relativeSize > block.end - stringBase) return std::nullopt;
        const std::size_t absolute = stringBase + relativeSize;
        const auto blockBegin = bytes.begin() + static_cast<std::ptrdiff_t>(block.base);
        const auto blockEnd = bytes.begin() + static_cast<std::ptrdiff_t>(block.end);
        const auto nul = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(absolute), blockEnd, 0U);
        if (nul == blockEnd) return std::nullopt;
        const std::size_t end = static_cast<std::size_t>(std::distance(bytes.begin(), nul));
        if (end == absolute || !isPrintableAscii(bytes, absolute, end)) return std::nullopt;
        if (absolute != stringBase && bytes[absolute - 1U] != 0U) return std::nullopt;
        if (absolute < block.base || absolute >= block.end) return std::nullopt;
        (void)blockBegin;

        ParsedString row;
        row.blockIndex = block.index;
        row.tableIndex = i;
        row.tableEntryOffset = entryOffset;
        row.relativeOffset = relative;
        row.absoluteOffset = absolute;
        row.length = end - absolute;
        row.text.assign(reinterpret_cast<const char*>(bytes.data() + absolute), row.length);
        parsed.push_back(std::move(row));
    }
    return parsed;
}

struct RawU16 {
    std::size_t blockIndex{};
    std::size_t blockBase{};
    std::size_t sourceOffset{};
    std::size_t relativeOffset{};
    std::uint16_t value{};
};

std::vector<RawU16> parseRawU16Tables(const Bytes& bytes, const std::vector<BlockInfo>& blocks, const std::string& label) {
    std::vector<RawU16> rows;
    for (const auto& block : blocks) {
        const std::size_t begin = block.base + block.tableBeginRelative;
        const std::size_t end = block.base + block.tableEndRelative;
        const std::size_t count = (end - begin) / kU16Bytes;
        if (count > 65536U) throw std::runtime_error(label + ": terlalu banyak nilai pada tabel raw.");
        for (std::size_t i = 0U; i < count; ++i) {
            const std::size_t sourceOffset = begin + i * kU16Bytes;
            rows.push_back(RawU16{block.index, block.base, sourceOffset,
                                  block.tableBeginRelative + i * kU16Bytes,
                                  readU16LE(bytes, sourceOffset, label + " raw table")});
        }
    }
    return rows;
}

std::string makeWordseveStringCsv(const std::vector<ParsedString>& rows) {
    std::ostringstream out;
    out << "block_index,table_index,table_entry_offset_hex,relative_offset_hex,absolute_offset_hex,byte_length,string\n";
    for (const auto& row : rows) {
        out << row.blockIndex << ',' << row.tableIndex << ','
            << csvEscape(hexValue(row.tableEntryOffset, 4)) << ','
            << csvEscape(hexValue(row.relativeOffset, 4)) << ','
            << csvEscape(hexValue(row.absoluteOffset, 4)) << ','
            << row.length << ',' << csvEscape(row.text) << '\n';
    }
    return out.str();
}

std::string makeRawU16Csv(const std::vector<RawU16>& rows) {
    std::ostringstream out;
    out << "block_index,block_base_hex,relative_offset_hex,source_offset_hex,value_hex,value_decimal\n";
    for (const auto& row : rows) {
        out << row.blockIndex << ','
            << csvEscape(hexValue(row.blockBase, 4)) << ','
            << csvEscape(hexValue(row.relativeOffset, 4)) << ','
            << csvEscape(hexValue(row.sourceOffset, 4)) << ','
            << csvEscape(hexValue(row.value, 4)) << ',' << row.value << '\n';
    }
    return out.str();
}

std::string makeBlockCsv(const std::string& label, const std::vector<BlockInfo>& blocks) {
    std::ostringstream out;
    out << "file,block_index,block_base_hex,first_word_pointer_candidate_hex,candidate_block_end_hex,candidate_block_length_bytes,section_offset_candidates_relative,raw_table_range_candidate_relative,raw_table_entry_count\n";
    for (const auto& block : blocks) {
        std::ostringstream sectionValues;
        for (std::size_t i = 0U; i < block.sectionOffsets.size(); ++i) {
            if (i > 0U) sectionValues << ';';
            sectionValues << hexValue(block.sectionOffsets[i]);
        }
        const std::size_t count = (block.tableEndRelative - block.tableBeginRelative) / kU16Bytes;
        out << csvEscape(label) << ',' << block.index << ','
            << csvEscape(hexValue(block.base, 4)) << ','
            << csvEscape(hexValue(block.nextPointer, 4)) << ','
            << csvEscape(hexValue(block.end, 4)) << ',' << (block.end - block.base) << ','
            << csvEscape(sectionValues.str()) << ','
            << csvEscape(hexValue(block.tableBeginRelative) + ".." + hexValue(block.tableEndRelative)) << ','
            << count << '\n';
    }
    return out.str();
}

void writeReport(const fs::path& path,
                 const Bytes& words,
                 const Bytes& wordseve,
                 const std::vector<BlockInfo>& wordsBlocks,
                 const std::vector<BlockInfo>& wordseveBlocks,
                 const std::vector<ParsedString>& wordseveStrings,
                 const bool secondWordseveStringTableValid,
                 const std::vector<RawU16>& wordsValues,
                 const std::vector<RawU16>& wordseveRawValues) {
    std::set<std::uint16_t> distinctOffsets;
    std::set<std::string> uniqueTexts;
    for (const auto& row : wordseveStrings) {
        distinctOffsets.insert(row.relativeOffset);
        uniqueTexts.insert(row.text);
    }

    std::ostringstream report;
    report << "DATASE text probe — laporan struktur blok dan tabel mentah\n"
           << "==========================================================\n\n"
           << "Semua field yang belum dibuktikan semantiknya disebut sebagai kandidat. Parser hanya membaca input.\n\n"
           << "Kandidat chain blok\n"
           << "  WORDS.BIN: " << wordsBlocks.size() << " blok ditemukan pada base ";
    for (std::size_t i = 0U; i < wordsBlocks.size(); ++i) {
        if (i > 0U) report << ", ";
        report << hexValue(wordsBlocks[i].base);
    }
    report << ". First-word pointer values: ";
    for (std::size_t i = 0U; i < wordsBlocks.size(); ++i) {
        if (i > 0U) report << ", ";
        report << hexValue(wordsBlocks[i].nextPointer);
    }
    report << "\n  WORDSEVE.BIN: " << wordseveBlocks.size() << " blok ditemukan pada base ";
    for (std::size_t i = 0U; i < wordseveBlocks.size(); ++i) {
        if (i > 0U) report << ", ";
        report << hexValue(wordseveBlocks[i].base);
    }
    report << ". First-word pointer values: ";
    for (std::size_t i = 0U; i < wordseveBlocks.size(); ++i) {
        if (i > 0U) report << ", ";
        report << hexValue(wordseveBlocks[i].nextPointer);
    }
    report << "\n  Fakta pendukung: pointer blok pertama cocok dengan offset awal blok berikutnya; blok target dimulai dengan pointer 0 dan header lokal yang mirip.\n"
           << "  Interpretasi sebagai linked-block chain: keyakinan tinggi, tetapi arti pointer belum dibuktikan dari kode game.\n\n"
           << "WORDSEVE.BIN — tabel offset string yang tervalidasi\n"
           << "  ukuran file: " << wordseve.size() << " byte (" << hexValue(wordseve.size()) << ")\n"
           << "  blok 0: base 0x0; tabel relatif " << hexValue(wordseveBlocks.at(0U).tableBeginRelative)
           << ".." << hexValue(wordseveBlocks.at(0U).tableEndRelative) << "\n"
           << "  ukuran tabel: " << wordseveBlocks.at(0U).tableEndRelative - wordseveBlocks.at(0U).tableBeginRelative
           << " byte; " << wordseveStrings.size() << " nilai uint16\n"
           << "  pool string kandidat: " << hexValue(wordseveBlocks.at(0U).tableEndRelative + 4U)
           << " (section + preamble 4 byte)\n"
           << "  hasil validasi: " << wordseveStrings.size() << "/" << wordseveStrings.size()
           << " entry mengarah ke string ASCII printable berterminator NUL dan batas string yang terlihat\n"
           << "  offset relatif unik: " << distinctOffsets.size() << "; isi string unik: " << uniqueTexts.size() << "\n"
           << "  blok 1: tabel kandidat relatif " << hexValue(wordseveBlocks.at(1U).tableBeginRelative)
           << ".." << hexValue(wordseveBlocks.at(1U).tableEndRelative) << " berisi "
           << (wordseveBlocks.at(1U).tableEndRelative - wordseveBlocks.at(1U).tableBeginRelative) / 2U
           << " nilai uint16; validasi menyatakan "
           << (secondWordseveStringTableValid ? "tabel ini juga memenuhi uji string ASCII" : "tabel ini TIDAK memenuhi uji offset string ASCII")
           << ", jadi nilai mentahnya tetap diekspor untuk menghindari salah tafsir.\n"
           << "  keyakinan: tinggi untuk tabel offset string pada blok 0; belum ada kesimpulan semantik untuk tabel blok 1.\n\n"
           << "WORDS.BIN — region uint16 mentah\n"
           << "  ukuran file: " << words.size() << " byte (" << hexValue(words.size()) << ")\n"
           << "  jumlah blok: " << wordsBlocks.size() << "; tiap blok memiliki kandidat region relatif "
           << hexValue(wordsBlocks.at(0U).tableBeginRelative) << ".." << hexValue(wordsBlocks.at(0U).tableEndRelative) << "\n"
           << "  nilai uint16 diekspor: " << wordsValues.size() << " total ("
           << (wordsBlocks.at(0U).tableEndRelative - wordsBlocks.at(0U).tableBeginRelative) / 2U
           << " per blok)\n"
           << "  awalan blok 0: 0x0000, 0x00DD, 0x0000\n"
           << "  awalan blok 1: 0x0001, 0x00DD, 0x0000\n"
           << "  indeks 1..107 tabel 16-bit sama antara dua blok; indeks 0 dan indeks 108..223 berbeda. Ini hanya hasil perbandingan nilai mentah.\n"
           << "  awalan pool data: blok 0 di " << hexValue(wordsBlocks.at(0U).base + wordsBlocks.at(0U).tableEndRelative)
           << " memiliki byte 46 0C 00 00 3F 00; teks ASCII pertama yang terlihat mulai di "
           << hexValue(wordsBlocks.at(0U).base + wordsBlocks.at(0U).tableEndRelative + 6U) << ".\n"
           << "  blok 1 pool data mulai di " << hexValue(wordsBlocks.at(1U).base + wordsBlocks.at(1U).tableEndRelative)
           << " dengan byte C5 0B 00 00 3F 00; teks ASCII pertama yang terlihat mulai 6 byte sesudahnya.\n"
           << "  keyakinan: tinggi untuk batas/count; arti tabel uint16 dan 6 byte preamble belum diketahui.\n\n"
           << "WORDSEVE raw table values: " << wordseveRawValues.size() << " row diekspor, mencakup tabel kedua yang belum ditafsirkan.\n\n"
           << "Uji dan batasan\n"
           << "  Input dibaca dalam binary mode; offset, count, panjang, pointer chain, NUL terminator, dan ASCII printable divalidasi.\n"
           << "  Program menolak pointer di luar file, siklus blok, rentang tabel tidak valid, string tak berterminator, atau target yang bukan batas string.\n"
           << "  Tidak ada writer; tidak ada klaim bahwa hasil bisa dibaca kembali oleh game; identitas platform tetap belum dikonfirmasi.\n";
    writeTextFile(path, report.str());
}

void printUsage(const char* exe) {
    std::cerr << "Pemakaian: " << exe << " <direktori DATASE/BIN> <direktori-output>\n"
              << "Contoh: " << exe << " ./DATASE/BIN ./probe-output\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            printUsage(argv[0]);
            return 2;
        }
        const fs::path binDir(argv[1]);
        const fs::path outputDir(argv[2]);
        if (!fs::is_directory(binDir)) throw std::runtime_error("Direktori input tidak ditemukan: " + binDir.string());
        fs::create_directories(outputDir);

        const Bytes words = readFile(binDir / "WORDS.BIN");
        const Bytes wordseve = readFile(binDir / "WORDSEVE.BIN");
        const auto wordsBlocks = walkBlockChain(words, FormatKind::Words, "WORDS.BIN");
        const auto wordseveBlocks = walkBlockChain(wordseve, FormatKind::Wordseve, "WORDSEVE.BIN");
        if (wordsBlocks.size() != 2U || wordseveBlocks.size() != 2U) {
            throw std::runtime_error("Jumlah blok pada sampel berubah dari pola dua-blok yang sedang diuji; tinjau struktur sebelum melanjutkan.");
        }

        const auto firstWordseveTable = tryParseWordseveStringOffsets(wordseve, wordseveBlocks.at(0U));
        if (!firstWordseveTable.has_value()) {
            throw std::runtime_error("WORDSEVE block 0 no longer satisfies the observed string-offset structure.");
        }
        std::vector<ParsedString> wordseveStrings = firstWordseveTable.value();
        const auto secondWordseveTable = tryParseWordseveStringOffsets(wordseve, wordseveBlocks.at(1U));
        const bool secondWordseveStringTableValid = secondWordseveTable.has_value();
        if (secondWordseveTable.has_value()) {
            const auto& extraRows = secondWordseveTable.value();
            wordseveStrings.insert(wordseveStrings.end(), extraRows.begin(), extraRows.end());
        }
        const auto wordsValues = parseRawU16Tables(words, wordsBlocks, "WORDS.BIN");
        const auto wordseveRawValues = parseRawU16Tables(wordseve, wordseveBlocks, "WORDSEVE.BIN");

        const std::string wordsBlockCsv = makeBlockCsv("WORDS.BIN", wordsBlocks);
        const std::string wordseveBlockCsv = makeBlockCsv("WORDSEVE.BIN", wordseveBlocks);
        const auto firstNewline = wordseveBlockCsv.find('\n');
        if (firstNewline == std::string::npos) throw std::runtime_error("Internal error: invalid CSV header.");
        writeTextFile(outputDir / "block_chain.csv", wordsBlockCsv + wordseveBlockCsv.substr(firstNewline + 1U));
        writeTextFile(outputDir / "WORDSEVE_offsets.csv", makeWordseveStringCsv(wordseveStrings));
        writeTextFile(outputDir / "WORDSEVE_tables_raw_u16.csv", makeRawU16Csv(wordseveRawValues));
        writeTextFile(outputDir / "WORDS_u16_region.csv", makeRawU16Csv(wordsValues));
        writeReport(outputDir / "probe_report.txt", words, wordseve, wordsBlocks, wordseveBlocks,
                    wordseveStrings, secondWordseveStringTableValid, wordsValues, wordseveRawValues);

        std::set<std::uint16_t> distinctOffsets;
        for (const auto& row : wordseveStrings) distinctOffsets.insert(row.relativeOffset);
        std::cout << "Probe selesai (read-only).\n"
                  << "WORDS.BIN: " << wordsBlocks.size() << " blok kandidat; " << wordsValues.size()
                  << " nilai u16 diekspor tanpa interpretasi semantik.\n"
                  << "WORDSEVE.BIN: " << wordseveBlocks.size() << " blok kandidat; " << wordseveStrings.size()
                  << " offset string tervalidasi pada blok 0 (" << distinctOffsets.size() << " offset unik); "
                  << wordseveRawValues.size() << " nilai u16 raw.\n"
                  << "Output: " << fs::absolute(outputDir).string() << "\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << '\n';
        return 1;
    }
}
