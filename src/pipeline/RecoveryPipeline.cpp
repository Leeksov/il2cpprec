#include <il2cpprec/pipeline/RecoveryPipeline.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <list>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

using CodeBuffer = std::vector<uint8_t>;
using SharedCodeBuffer = std::shared_ptr<const CodeBuffer>;

using ProfileHash = std::array<uint8_t, 32>;

struct CacheKey {
    Architecture architecture = Architecture::Arm64;
    uint64_t address = 0;
    uint64_t codeHash = 0;
    size_t codeSize = 0;
    ProfileHash sourceProfileHash{};
    Arm32Mode arm32Mode = Arm32Mode::Arm;

    bool operator==(const CacheKey&) const = default;
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& key) const noexcept {
        size_t hash = std::hash<Architecture>{}(key.architecture);
        const auto combine = [&hash](size_t value) {
            hash ^= value + static_cast<size_t>(0x9E3779B97F4A7C15ULL) + (hash << 6) + (hash >> 2);
        };
        combine(std::hash<uint64_t>{}(key.address));
        combine(std::hash<uint64_t>{}(key.codeHash));
        combine(std::hash<size_t>{}(key.codeSize));
        combine(std::hash<Arm32Mode>{}(key.arm32Mode));
        for (const uint8_t byte : key.sourceProfileHash) combine(byte);
        return hash;
    }
};

uint64_t hashCode(const uint8_t* code, size_t size) noexcept {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= code[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

size_t queueCharge(const FunctionImage& image) noexcept {
    if (image.name.size() > std::numeric_limits<size_t>::max() - image.size) {
        return std::numeric_limits<size_t>::max();
    }
    return image.size + image.name.size();
}

struct Job {
    FunctionImage image;
    SharedCodeBuffer ownedCode;
    CacheKey key;
    size_t queueBytes = 0;
};

struct Batch {
    Batch(size_t size, std::stop_token cancellation)
        : results(size), cancellation(cancellation) {}

    bool isCancelled() const noexcept {
        return cancelRequested.load(std::memory_order_acquire) || cancellation.stop_requested();
    }

    std::vector<RecoveryResult> results;
    std::stop_token cancellation;
    std::atomic<bool> cancelRequested = false;
    std::mutex mutex;
    std::condition_variable finished;
    size_t pending = 0;
};

struct Task {
    std::shared_ptr<Batch> batch;
    size_t index = 0;
    Job job;
};

struct CacheEntry {
    std::list<CacheKey>::iterator lruPosition;
    std::shared_ptr<const RecoveredFunction> function;
    SharedCodeBuffer code;
    uint64_t expressionCount = 0;
    uint64_t statementCount = 0;
    std::vector<RecoveryDiagnostic> recoveryDiagnostics;
    flow::ExceptionRegionAnalysis exceptionAnalysis;
};

struct IrShape {
    uint64_t expressionCount = 0;
    uint64_t statementCount = 0;
};

ExpressionPtr cloneExpression(
    const ExpressionPtr& expression,
    std::unordered_map<const Expression*, ExpressionPtr>& clones) {
    if (!expression) return nullptr;
    const auto existing = clones.find(expression.get());
    if (existing != clones.end()) return existing->second;

    auto clone = std::make_shared<Expression>(*expression);
    clones.emplace(expression.get(), clone);
    for (auto& argument : clone->arguments) {
        argument = cloneExpression(argument, clones);
    }
    return clone;
}

RecoveredFunction cloneRecoveredFunction(const RecoveredFunction& function, IrShape* shape = nullptr) {
    std::unordered_map<const Expression*, ExpressionPtr> clones;
    RecoveredFunction clone;
    clone.architecture = function.architecture;
    clone.address = function.address;
    clone.name = function.name;
    clone.blocks = function.blocks;
    clone.exceptionRegions = function.exceptionRegions;
    for (auto& block : clone.blocks) {
        for (auto& statement : block.statements) {
            statement.destination = cloneExpression(statement.destination, clones);
            statement.value = cloneExpression(statement.value, clones);
            statement.condition = cloneExpression(statement.condition, clones);
            statement.target = cloneExpression(statement.target, clones);
            for (auto& argument : statement.arguments) {
                argument = cloneExpression(argument, clones);
            }
        }
    }
    if (shape) {
        shape->expressionCount = clones.size();
        for (const auto& block : function.blocks) shape->statementCount += block.statements.size();
    }
    return clone;
}

constexpr uint32_t diskCacheSchemaVersion = 4;
constexpr uint32_t sourceProfileSchemaVersion = 2;
constexpr size_t maxDiskCacheFileSize = 256 * 1024 * 1024;
constexpr uint64_t nullExpressionIndex = std::numeric_limits<uint64_t>::max();
constexpr std::array<uint8_t, 8> diskCacheMagic = {'I', 'L', '2', 'R', 'P', 'C', '0', '4'};

uint32_t rotateRight(uint32_t value, unsigned bits) noexcept {
    return (value >> bits) | (value << (32 - bits));
}

class Sha256 {
public:
    void update(const uint8_t* data, size_t size) noexcept {
        if (size == 0) return;
        totalBytes_ += static_cast<uint64_t>(size);
        if (bufferSize_ != 0) {
            const size_t copied = std::min(size, buffer_.size() - bufferSize_);
            std::copy_n(data, copied, buffer_.begin() + bufferSize_);
            bufferSize_ += copied;
            data += copied;
            size -= copied;
            if (bufferSize_ == buffer_.size()) {
                transform(buffer_.data());
                bufferSize_ = 0;
            }
        }
        while (size >= buffer_.size()) {
            transform(data);
            data += buffer_.size();
            size -= buffer_.size();
        }
        if (size != 0) {
            std::copy_n(data, size, buffer_.begin());
            bufferSize_ = size;
        }
    }

    std::array<uint8_t, 32> finish() noexcept {
        const uint64_t bitSize = totalBytes_ * 8;
        const uint8_t padding = 0x80;
        update(&padding, 1);
        const uint8_t zero = 0;
        while (bufferSize_ != 56) update(&zero, 1);

        std::array<uint8_t, 8> length{};
        for (size_t i = 0; i < length.size(); ++i) {
            length[i] = static_cast<uint8_t>(bitSize >> (56 - i * 8));
        }
        update(length.data(), length.size());

        std::array<uint8_t, 32> digest{};
        for (size_t i = 0; i < state_.size(); ++i) {
            for (size_t byte = 0; byte < 4; ++byte) {
                digest[i * 4 + byte] = static_cast<uint8_t>(state_[i] >> (24 - byte * 8));
            }
        }
        return digest;
    }

private:
    void transform(const uint8_t* block) noexcept {
        static constexpr std::array<uint32_t, 64> constants = {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
        };
        std::array<uint32_t, 64> words{};
        for (size_t i = 0; i < 16; ++i) {
            words[i] = (static_cast<uint32_t>(block[i * 4]) << 24)
                | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
                | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
                | static_cast<uint32_t>(block[i * 4 + 3]);
        }
        for (size_t i = 16; i < words.size(); ++i) {
            const uint32_t s0 = rotateRight(words[i - 15], 7) ^ rotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3);
            const uint32_t s1 = rotateRight(words[i - 2], 17) ^ rotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }

        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];
        uint32_t e = state_[4];
        uint32_t f = state_[5];
        uint32_t g = state_[6];
        uint32_t h = state_[7];
        for (size_t i = 0; i < words.size(); ++i) {
            const uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const uint32_t choice = (e & f) ^ (~e & g);
            const uint32_t temporary1 = h + s1 + choice + constants[i] + words[i];
            const uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temporary2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<uint32_t, 8> state_ = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };
    std::array<uint8_t, 64> buffer_{};
    size_t bufferSize_ = 0;
    uint64_t totalBytes_ = 0;
};

template <typename Integer>
void hashInteger(Sha256& hash, Integer value) noexcept {
    std::array<uint8_t, sizeof(Integer)> bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
    }
    hash.update(bytes.data(), bytes.size());
}

void hashString(Sha256& hash, const std::string& value) noexcept {
    hashInteger(hash, static_cast<uint64_t>(value.size()));
    hash.update(reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

void hashMetadataSection(Sha256& hash, const MetadataSectionModel& section) noexcept {
    hashInteger(hash, static_cast<uint32_t>(section.offset));
    hashInteger(hash, static_cast<uint32_t>(section.sectionSize));
    hashInteger(hash, static_cast<uint32_t>(section.count));
}

ProfileHash hashSourceProfile(const RecoverySourceProfile& profile) noexcept {
    Sha256 hash;
    hashInteger(hash, sourceProfileSchemaVersion);
    hashString(hash, profile.unityMetadataVersion);
    hashString(hash, profile.binaryIdentity);
    hashString(hash, profile.codeRegistrationIdentity);
    hashString(hash, profile.methodPointersIdentity);
    hashInteger(hash, profile.lifterSemanticsVersion);
    hashString(hash, profile.profileIdentity);
    hashString(hash, profile.layoutIdentity);
    hashInteger(hash, static_cast<uint32_t>(profile.rawMetadataVersion));
    hashInteger(hash, std::bit_cast<uint64_t>(profile.preciseMetadataVersion));
    hashInteger(hash, std::bit_cast<uint64_t>(profile.registrationVersion));
    hashMetadataSection(hash, profile.generatedMethodTypeInfos);
    hashMetadataSection(hash, profile.generatedMethodTokens);
    hashInteger(hash, profile.exceptionSemanticsVersion);
    hashInteger(hash, profile.vectorSemanticsVersion);
    return hash.finish();
}

std::string hexDigest(const std::array<uint8_t, 32>& digest) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(digest.size() * 2, '0');
    for (size_t i = 0; i < digest.size(); ++i) {
        result[i * 2] = digits[digest[i] >> 4];
        result[i * 2 + 1] = digits[digest[i] & 0x0F];
    }
    return result;
}

std::filesystem::path diskCachePath(const std::filesystem::path& directory, const Job& job) {
    Sha256 hash;
    hash.update(diskCacheMagic.data(), diskCacheMagic.size());
    hashInteger(hash, diskCacheSchemaVersion);
    hash.update(job.key.sourceProfileHash.data(), job.key.sourceProfileHash.size());
    hashInteger(hash, static_cast<uint32_t>(job.image.architecture));
    hashInteger(hash, static_cast<uint32_t>(job.image.arm32Mode));
    hashInteger(hash, job.image.address);
    hashInteger(hash, static_cast<uint64_t>(job.image.size));
    hash.update(job.image.code, job.image.size);
    return directory / (hexDigest(hash.finish()) + ".il2cpprec-cache");
}

class BinaryWriter {
public:
    void write(const void* data, size_t size) {
        if (size == 0) return;
        if (bytes_.size() > maxDiskCacheFileSize || size > maxDiskCacheFileSize - bytes_.size()) {
            throw std::length_error("Persistent cache entry is too large");
        }
        const auto* begin = static_cast<const uint8_t*>(data);
        bytes_.insert(bytes_.end(), begin, begin + size);
    }

    void writeU8(uint8_t value) {
        write(&value, 1);
    }

    void writeU16(uint16_t value) {
        writeInteger(value);
    }

    void writeU32(uint32_t value) {
        writeInteger(value);
    }

    void writeU64(uint64_t value) {
        writeInteger(value);
    }

    void writeString(const std::string& value) {
        writeU64(value.size());
        write(value.data(), value.size());
    }

    const std::vector<uint8_t>& bytes() const noexcept {
        return bytes_;
    }

    std::vector<uint8_t> take() noexcept {
        return std::move(bytes_);
    }

private:
    template <typename Integer>
    void writeInteger(Integer value) {
        std::array<uint8_t, sizeof(Integer)> bytes{};
        for (size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = static_cast<uint8_t>(value >> (i * 8));
        }
        write(bytes.data(), bytes.size());
    }

    std::vector<uint8_t> bytes_;
};

class BinaryReader {
public:
    BinaryReader(const uint8_t* data, size_t size) noexcept
        : data_(data), size_(size) {}

    size_t remaining() const noexcept {
        return size_ - offset_;
    }

    bool read(void* output, size_t size) noexcept {
        if (size > remaining()) return false;
        if (size != 0) {
            const auto* begin = data_ + offset_;
            std::copy(begin, begin + size, static_cast<uint8_t*>(output));
        }
        offset_ += size;
        return true;
    }

    bool skip(size_t size) noexcept {
        if (size > remaining()) return false;
        offset_ += size;
        return true;
    }

    bool readU8(uint8_t& value) noexcept {
        return read(&value, 1);
    }

    bool readU16(uint16_t& value) noexcept {
        return readInteger(value);
    }

    bool readU32(uint32_t& value) noexcept {
        return readInteger(value);
    }

    bool readU64(uint64_t& value) noexcept {
        return readInteger(value);
    }

    bool readString(std::string& value) {
        uint64_t size = 0;
        if (!readU64(size) || size > std::numeric_limits<size_t>::max()) return false;
        const auto count = static_cast<size_t>(size);
        if (count > remaining()) return false;
        const auto* begin = reinterpret_cast<const char*>(data_ + offset_);
        value.assign(begin, count);
        offset_ += count;
        return true;
    }

    bool readCount(uint64_t& count, size_t minimumRecordSize) noexcept {
        if (!readU64(count) || count > std::numeric_limits<size_t>::max()) return false;
        return minimumRecordSize == 0 || count <= remaining() / minimumRecordSize;
    }

private:
    template <typename Integer>
    bool readInteger(Integer& value) noexcept {
        std::array<uint8_t, sizeof(Integer)> bytes{};
        if (!read(bytes.data(), bytes.size())) return false;
        value = 0;
        for (size_t i = 0; i < bytes.size(); ++i) {
            value |= static_cast<Integer>(bytes[i]) << (i * 8);
        }
        return true;
    }

    const uint8_t* data_;
    size_t size_;
    size_t offset_ = 0;
};

std::vector<uint8_t> serializeDiskCache(
    const Job& job,
    const RecoveryOutcome& outcome,
    const RecoverySourceProfile& sourceProfile) {
    const auto& function = outcome.function;
    std::vector<const Expression*> expressions;
    std::unordered_map<const Expression*, uint64_t> expressionIndices;
    const auto expressionIndex = [&expressions, &expressionIndices](const ExpressionPtr& expression) -> uint64_t {
        if (!expression) return nullExpressionIndex;
        const auto [existing, inserted] = expressionIndices.emplace(expression.get(), expressions.size());
        if (inserted) expressions.push_back(expression.get());
        return existing->second;
    };

    for (const auto& block : function.blocks) {
        for (const auto& statement : block.statements) {
            expressionIndex(statement.destination);
            expressionIndex(statement.value);
            expressionIndex(statement.condition);
            expressionIndex(statement.target);
            for (const auto& argument : statement.arguments) expressionIndex(argument);
        }
    }
    for (size_t i = 0; i < expressions.size(); ++i) {
        for (const auto& argument : expressions[i]->arguments) expressionIndex(argument);
    }

    BinaryWriter writer;
    writer.write(diskCacheMagic.data(), diskCacheMagic.size());
    writer.writeU32(diskCacheSchemaVersion);
    writer.writeU64(sourceProfile.lifterSemanticsVersion);
    writer.writeU64(sourceProfile.exceptionSemanticsVersion);
    writer.writeU64(sourceProfile.vectorSemanticsVersion);
    writer.writeU32(static_cast<uint32_t>(job.image.architecture));
    writer.writeU32(static_cast<uint32_t>(job.image.arm32Mode));
    writer.writeU32(0);
    writer.writeU64(job.image.address);
    writer.writeU64(job.image.size);
    writer.writeString(sourceProfile.unityMetadataVersion);
    writer.writeString(sourceProfile.binaryIdentity);
    writer.writeString(sourceProfile.codeRegistrationIdentity);
    writer.writeString(sourceProfile.methodPointersIdentity);
    writer.writeString(sourceProfile.profileIdentity);
    writer.writeString(sourceProfile.layoutIdentity);
    writer.writeU32(static_cast<uint32_t>(sourceProfile.rawMetadataVersion));
    writer.writeU64(std::bit_cast<uint64_t>(sourceProfile.preciseMetadataVersion));
    writer.writeU64(std::bit_cast<uint64_t>(sourceProfile.registrationVersion));
    writer.writeU32(static_cast<uint32_t>(sourceProfile.generatedMethodTypeInfos.offset));
    writer.writeU32(static_cast<uint32_t>(sourceProfile.generatedMethodTypeInfos.sectionSize));
    writer.writeU32(static_cast<uint32_t>(sourceProfile.generatedMethodTypeInfos.count));
    writer.writeU32(static_cast<uint32_t>(sourceProfile.generatedMethodTokens.offset));
    writer.writeU32(static_cast<uint32_t>(sourceProfile.generatedMethodTokens.sectionSize));
    writer.writeU32(static_cast<uint32_t>(sourceProfile.generatedMethodTokens.count));
    writer.write(job.image.code, job.image.size);
    writer.writeU64(expressions.size());
    for (const Expression* expression : expressions) {
        writer.writeU8(static_cast<uint8_t>(expression->kind));
        writer.writeU8(static_cast<uint8_t>(expression->type.kind));
        writer.writeU16(expression->type.bits);
        writer.writeU32(0);
        writer.writeU64(expression->constant);
        writer.writeString(expression->name);
        writer.writeString(expression->op);
        writer.writeU64(expression->arguments.size());
        for (const auto& argument : expression->arguments) writer.writeU64(expressionIndex(argument));
    }

    writer.writeU64(function.blocks.size());
    for (const auto& block : function.blocks) {
        writer.writeU64(block.address);
        writer.writeU64(block.statements.size());
        for (const auto& statement : block.statements) {
            writer.writeU8(static_cast<uint8_t>(statement.kind));
            const std::array<uint8_t, 7> reserved{};
            writer.write(reserved.data(), reserved.size());
            writer.writeU64(statement.address);
            writer.writeU64(expressionIndex(statement.destination));
            writer.writeU64(expressionIndex(statement.value));
            writer.writeU64(expressionIndex(statement.condition));
            writer.writeU64(expressionIndex(statement.target));
            writer.writeU64(statement.arguments.size());
            for (const auto& argument : statement.arguments) writer.writeU64(expressionIndex(argument));
        }
    }

    writer.writeU64(function.exceptionRegions.size());
    for (const auto& region : function.exceptionRegions) {
        writer.writeU64(region.tryBegin);
        writer.writeU64(region.tryEnd);
        writer.writeU64(region.handler);
        writer.writeU64(region.leaveTarget);
        writer.writeU8(static_cast<uint8_t>(region.kind));
        const std::array<uint8_t, 7> reserved{};
        writer.write(reserved.data(), reserved.size());
    }

    writer.writeU64(outcome.diagnostics.size());
    for (const auto& diagnostic : outcome.diagnostics) {
        writer.writeU8(static_cast<uint8_t>(diagnostic.kind));
        const std::array<uint8_t, 7> reserved{};
        writer.write(reserved.data(), reserved.size());
        writer.writeU64(diagnostic.address);
        writer.writeU64(diagnostic.target);
    }

    writer.writeU64(outcome.exceptionAnalysis.regions.size());
    for (const auto& region : outcome.exceptionAnalysis.regions) {
        writer.writeU64(region.tryBegin);
        writer.writeU64(region.tryEnd);
        writer.writeU64(region.handler);
        writer.writeU64(region.leaveTarget);
        writer.writeU8(static_cast<uint8_t>(region.kind));
        const std::array<uint8_t, 7> reserved{};
        writer.write(reserved.data(), reserved.size());
    }
    writer.writeU64(outcome.exceptionAnalysis.rethrows.size());
    for (const uint64_t address : outcome.exceptionAnalysis.rethrows) writer.writeU64(address);
    writer.writeU64(outcome.exceptionAnalysis.diagnostics.size());
    for (const auto& diagnostic : outcome.exceptionAnalysis.diagnostics) {
        writer.writeU8(static_cast<uint8_t>(diagnostic.kind));
        const std::array<uint8_t, 7> reserved{};
        writer.write(reserved.data(), reserved.size());
        writer.writeU64(diagnostic.address);
        writer.writeString(diagnostic.message);
    }
    writer.writeU8(outcome.exceptionAnalysis.partial ? 1 : 0);
    const std::array<uint8_t, 7> outcomeReserved{};
    writer.write(outcomeReserved.data(), outcomeReserved.size());

    Sha256 checksumInput;
    checksumInput.update(writer.bytes().data(), writer.bytes().size());
    const auto checksum = checksumInput.finish();
    writer.write(checksum.data(), checksum.size());
    return writer.take();
}

struct ExpressionRecord {
    ExpressionPtr expression = std::make_shared<Expression>();
    std::vector<uint64_t> arguments;
};

struct DiskCacheData {
    RecoveredFunction function;
    SharedCodeBuffer code;
    uint64_t expressionCount = 0;
    uint64_t statementCount = 0;
    uint64_t serializedBytes = 0;
    std::vector<RecoveryDiagnostic> recoveryDiagnostics;
    flow::ExceptionRegionAnalysis exceptionAnalysis;
};

bool validExpressionKind(uint8_t kind) noexcept {
    return kind <= static_cast<uint8_t>(Expression::Kind::Select);
}

bool validScalarKind(uint8_t kind) noexcept {
    return kind <= static_cast<uint8_t>(ScalarKind::Vector);
}

bool validStatementKind(uint8_t kind) noexcept {
    return kind <= static_cast<uint8_t>(Statement::Kind::Return);
}

std::optional<DiskCacheData> deserializeDiskCache(
    const std::vector<uint8_t>& bytes,
    const Job& job,
    const RecoverySourceProfile& sourceProfile) {
    if (bytes.size() < 32 || bytes.size() > maxDiskCacheFileSize) return std::nullopt;
    Sha256 checksum;
    checksum.update(bytes.data(), bytes.size() - 32);
    const auto expectedChecksum = checksum.finish();
    if (!std::equal(expectedChecksum.begin(), expectedChecksum.end(), bytes.end() - 32)) return std::nullopt;

    BinaryReader reader(bytes.data(), bytes.size() - 32);
    std::array<uint8_t, 8> magic{};
    uint32_t schema = 0;
    uint64_t lifter = 0;
    uint64_t exceptionSemantics = 0;
    uint64_t vectorSemantics = 0;
    uint32_t architecture = 0;
    uint32_t arm32Mode = 0;
    uint32_t reserved = 0;
    uint64_t address = 0;
    uint64_t codeSize = 0;
    uint32_t rawMetadataVersion = 0;
    uint64_t preciseMetadataVersion = 0;
    uint64_t registrationVersion = 0;
    std::string unityMetadataVersion;
    std::string binaryIdentity;
    std::string codeRegistrationIdentity;
    std::string methodPointersIdentity;
    std::string profileIdentity;
    std::string layoutIdentity;
    MetadataSectionModel generatedMethodTypeInfos;
    MetadataSectionModel generatedMethodTokens;
    const auto readSection = [&reader](MetadataSectionModel& section) {
        uint32_t offset = 0;
        uint32_t size = 0;
        uint32_t count = 0;
        if (!reader.readU32(offset) || !reader.readU32(size) || !reader.readU32(count)) return false;
        section.offset = static_cast<int32_t>(offset);
        section.sectionSize = static_cast<int32_t>(size);
        section.count = static_cast<int32_t>(count);
        return true;
    };
    if (!reader.read(magic.data(), magic.size()) || magic != diskCacheMagic
        || !reader.readU32(schema) || !reader.readU64(lifter)
        || !reader.readU64(exceptionSemantics) || !reader.readU64(vectorSemantics)
        || !reader.readU32(architecture) || !reader.readU32(arm32Mode) || !reader.readU32(reserved)
        || !reader.readU64(address) || !reader.readU64(codeSize)
        || !reader.readString(unityMetadataVersion) || !reader.readString(binaryIdentity)
        || !reader.readString(codeRegistrationIdentity) || !reader.readString(methodPointersIdentity)
        || !reader.readString(profileIdentity) || !reader.readString(layoutIdentity)
        || !reader.readU32(rawMetadataVersion) || !reader.readU64(preciseMetadataVersion)
        || !reader.readU64(registrationVersion)
        || !readSection(generatedMethodTypeInfos) || !readSection(generatedMethodTokens)
        || schema != diskCacheSchemaVersion || lifter != sourceProfile.lifterSemanticsVersion
        || exceptionSemantics != sourceProfile.exceptionSemanticsVersion
        || vectorSemantics != sourceProfile.vectorSemanticsVersion || reserved != 0
        || architecture != static_cast<uint32_t>(job.image.architecture)
        || arm32Mode != static_cast<uint32_t>(job.image.arm32Mode) || address != job.image.address
        || codeSize != job.image.size || unityMetadataVersion != sourceProfile.unityMetadataVersion
        || binaryIdentity != sourceProfile.binaryIdentity
        || codeRegistrationIdentity != sourceProfile.codeRegistrationIdentity
        || methodPointersIdentity != sourceProfile.methodPointersIdentity
        || profileIdentity != sourceProfile.profileIdentity || layoutIdentity != sourceProfile.layoutIdentity
        || rawMetadataVersion != static_cast<uint32_t>(sourceProfile.rawMetadataVersion)
        || preciseMetadataVersion != std::bit_cast<uint64_t>(sourceProfile.preciseMetadataVersion)
        || registrationVersion != std::bit_cast<uint64_t>(sourceProfile.registrationVersion)
        || generatedMethodTypeInfos.offset != sourceProfile.generatedMethodTypeInfos.offset
        || generatedMethodTypeInfos.sectionSize != sourceProfile.generatedMethodTypeInfos.sectionSize
        || generatedMethodTypeInfos.count != sourceProfile.generatedMethodTypeInfos.count
        || generatedMethodTokens.offset != sourceProfile.generatedMethodTokens.offset
        || generatedMethodTokens.sectionSize != sourceProfile.generatedMethodTokens.sectionSize
        || generatedMethodTokens.count != sourceProfile.generatedMethodTokens.count
        || codeSize > std::numeric_limits<size_t>::max() || codeSize > reader.remaining()) {
        return std::nullopt;
    }

    const auto codeCount = static_cast<size_t>(codeSize);
    const uint8_t* code = bytes.data() + (bytes.size() - 32 - reader.remaining());
    if (codeCount != 0 && !std::equal(code, code + codeCount, job.image.code)) return std::nullopt;
    std::vector<uint8_t> codeCopy;
    if (codeCount != 0) codeCopy.assign(code, code + codeCount);
    if (!reader.skip(codeCount)) return std::nullopt;

    uint64_t expressionCount = 0;
    if (!reader.readCount(expressionCount, 40)) return std::nullopt;
    std::vector<ExpressionRecord> records;
    records.reserve(static_cast<size_t>(expressionCount));
    for (uint64_t i = 0; i < expressionCount; ++i) {
        ExpressionRecord record;
        uint8_t kind = 0;
        uint8_t scalarKind = 0;
        uint16_t bits = 0;
        uint64_t argumentCount = 0;
        auto& expression = *record.expression;
        if (!reader.readU8(kind) || !reader.readU8(scalarKind)
            || !reader.readU16(bits) || !reader.readU32(reserved)
            || !reader.readU64(expression.constant)
            || !reader.readString(expression.name) || !reader.readString(expression.op)
            || !reader.readCount(argumentCount, 8)
            || !validExpressionKind(kind) || !validScalarKind(scalarKind) || reserved != 0) {
            return std::nullopt;
        }
        expression.kind = static_cast<Expression::Kind>(kind);
        expression.type.kind = static_cast<ScalarKind>(scalarKind);
        expression.type.bits = bits;
        record.arguments.reserve(static_cast<size_t>(argumentCount));
        for (uint64_t argument = 0; argument < argumentCount; ++argument) {
            uint64_t index = 0;
            if (!reader.readU64(index) || (index != nullExpressionIndex && index >= expressionCount)) return std::nullopt;
            record.arguments.push_back(index);
        }
        records.push_back(std::move(record));
    }

    std::vector<ExpressionPtr> expressions;
    expressions.reserve(records.size());
    for (const auto& record : records) expressions.push_back(record.expression);
    for (size_t i = 0; i < records.size(); ++i) {
        expressions[i]->arguments.reserve(records[i].arguments.size());
        for (const uint64_t index : records[i].arguments) {
            expressions[i]->arguments.push_back(index == nullExpressionIndex ? nullptr : expressions[index]);
        }
    }
    const auto expressionRef = [&expressions](uint64_t index) -> ExpressionPtr {
        return index == nullExpressionIndex ? nullptr : expressions[index];
    };

    DiskCacheData result;
    result.function.architecture = job.image.architecture;
    result.function.address = job.image.address;
    result.code = std::make_shared<const CodeBuffer>(std::move(codeCopy));
    result.expressionCount = expressionCount;
    result.serializedBytes = bytes.size();
    uint64_t blockCount = 0;
    if (!reader.readCount(blockCount, 16)) return std::nullopt;
    result.function.blocks.reserve(static_cast<size_t>(blockCount));
    for (uint64_t blockIndex = 0; blockIndex < blockCount; ++blockIndex) {
        BasicBlock block;
        uint64_t statementCount = 0;
        if (!reader.readU64(block.address) || !reader.readCount(statementCount, 56)) return std::nullopt;
        block.statements.reserve(static_cast<size_t>(statementCount));
        for (uint64_t statementIndex = 0; statementIndex < statementCount; ++statementIndex) {
            Statement statement;
            uint8_t kind = 0;
            std::array<uint8_t, 7> statementReserved{};
            uint64_t destination = 0;
            uint64_t value = 0;
            uint64_t condition = 0;
            uint64_t target = 0;
            uint64_t argumentCount = 0;
            if (!reader.readU8(kind) || !reader.read(statementReserved.data(), statementReserved.size())
                || !reader.readU64(statement.address)
                || !reader.readU64(destination) || !reader.readU64(value)
                || !reader.readU64(condition) || !reader.readU64(target)
                || !reader.readCount(argumentCount, 8) || !validStatementKind(kind)
                || std::any_of(statementReserved.begin(), statementReserved.end(), [](uint8_t byte) { return byte != 0; })) {
                return std::nullopt;
            }
            const auto validReference = [expressionCount](uint64_t index) {
                return index == nullExpressionIndex || index < expressionCount;
            };
            if (!validReference(destination) || !validReference(value)
                || !validReference(condition) || !validReference(target)) {
                return std::nullopt;
            }
            statement.kind = static_cast<Statement::Kind>(kind);
            statement.destination = expressionRef(destination);
            statement.value = expressionRef(value);
            statement.condition = expressionRef(condition);
            statement.target = expressionRef(target);
            statement.arguments.reserve(static_cast<size_t>(argumentCount));
            for (uint64_t argument = 0; argument < argumentCount; ++argument) {
                uint64_t index = 0;
                if (!reader.readU64(index) || !validReference(index)) return std::nullopt;
                statement.arguments.push_back(expressionRef(index));
            }
            block.statements.push_back(std::move(statement));
        }
        result.statementCount += statementCount;
        result.function.blocks.push_back(std::move(block));
    }

    uint64_t regionCount = 0;
    if (!reader.readCount(regionCount, 40)) return std::nullopt;
    result.function.exceptionRegions.reserve(static_cast<size_t>(regionCount));
    for (uint64_t regionIndex = 0; regionIndex < regionCount; ++regionIndex) {
        ExceptionRegion region;
        uint8_t kind = 0;
        std::array<uint8_t, 7> regionReserved{};
        if (!reader.readU64(region.tryBegin) || !reader.readU64(region.tryEnd)
            || !reader.readU64(region.handler) || !reader.readU64(region.leaveTarget)
            || !reader.readU8(kind) || !reader.read(regionReserved.data(), regionReserved.size())
            || kind > static_cast<uint8_t>(ExceptionRegionKind::Filter)
            || std::any_of(regionReserved.begin(), regionReserved.end(), [](uint8_t byte) { return byte != 0; })) {
            return std::nullopt;
        }
        region.kind = static_cast<ExceptionRegionKind>(kind);
        result.function.exceptionRegions.push_back(region);
    }

    uint64_t recoveryDiagnosticCount = 0;
    if (!reader.readCount(recoveryDiagnosticCount, 24)) return std::nullopt;
    result.recoveryDiagnostics.reserve(static_cast<size_t>(recoveryDiagnosticCount));
    for (uint64_t i = 0; i < recoveryDiagnosticCount; ++i) {
        RecoveryDiagnostic diagnostic;
        uint8_t kind = 0;
        std::array<uint8_t, 7> diagnosticReserved{};
        if (!reader.readU8(kind) || !reader.read(diagnosticReserved.data(), diagnosticReserved.size())
            || !reader.readU64(diagnostic.address) || !reader.readU64(diagnostic.target)
            || kind > static_cast<uint8_t>(RecoveryDiagnosticKind::InstructionBudgetExceeded)
            || std::any_of(diagnosticReserved.begin(), diagnosticReserved.end(), [](uint8_t byte) { return byte != 0; })) {
            return std::nullopt;
        }
        diagnostic.kind = static_cast<RecoveryDiagnosticKind>(kind);
        result.recoveryDiagnostics.push_back(diagnostic);
    }

    const auto readExceptionRegion = [&reader](ExceptionRegion& region) {
        uint8_t kind = 0;
        std::array<uint8_t, 7> regionReserved{};
        if (!reader.readU64(region.tryBegin) || !reader.readU64(region.tryEnd)
            || !reader.readU64(region.handler) || !reader.readU64(region.leaveTarget)
            || !reader.readU8(kind) || !reader.read(regionReserved.data(), regionReserved.size())
            || kind > static_cast<uint8_t>(ExceptionRegionKind::Filter)
            || std::any_of(regionReserved.begin(), regionReserved.end(), [](uint8_t byte) { return byte != 0; })) {
            return false;
        }
        region.kind = static_cast<ExceptionRegionKind>(kind);
        return true;
    };
    if (!reader.readCount(regionCount, 40)) return std::nullopt;
    result.exceptionAnalysis.regions.reserve(static_cast<size_t>(regionCount));
    for (uint64_t i = 0; i < regionCount; ++i) {
        ExceptionRegion region;
        if (!readExceptionRegion(region)) return std::nullopt;
        result.exceptionAnalysis.regions.push_back(region);
    }
    uint64_t rethrowCount = 0;
    if (!reader.readCount(rethrowCount, 8)) return std::nullopt;
    result.exceptionAnalysis.rethrows.reserve(static_cast<size_t>(rethrowCount));
    for (uint64_t i = 0; i < rethrowCount; ++i) {
        uint64_t address = 0;
        if (!reader.readU64(address)) return std::nullopt;
        result.exceptionAnalysis.rethrows.push_back(address);
    }
    uint64_t exceptionDiagnosticCount = 0;
    if (!reader.readCount(exceptionDiagnosticCount, 24)) return std::nullopt;
    result.exceptionAnalysis.diagnostics.reserve(static_cast<size_t>(exceptionDiagnosticCount));
    for (uint64_t i = 0; i < exceptionDiagnosticCount; ++i) {
        flow::ExceptionRegionDiagnostic diagnostic;
        uint8_t kind = 0;
        std::array<uint8_t, 7> diagnosticReserved{};
        if (!reader.readU8(kind) || !reader.read(diagnosticReserved.data(), diagnosticReserved.size())
            || !reader.readU64(diagnostic.address) || !reader.readString(diagnostic.message)
            || kind > static_cast<uint8_t>(flow::ExceptionRegionDiagnosticKind::AmbiguousRegion)
            || std::any_of(diagnosticReserved.begin(), diagnosticReserved.end(), [](uint8_t byte) { return byte != 0; })) {
            return std::nullopt;
        }
        diagnostic.kind = static_cast<flow::ExceptionRegionDiagnosticKind>(kind);
        result.exceptionAnalysis.diagnostics.push_back(std::move(diagnostic));
    }
    uint8_t partial = 0;
    std::array<uint8_t, 7> outcomeReserved{};
    if (!reader.readU8(partial) || partial > 1
        || !reader.read(outcomeReserved.data(), outcomeReserved.size())
        || std::any_of(outcomeReserved.begin(), outcomeReserved.end(), [](uint8_t byte) { return byte != 0; })) {
        return std::nullopt;
    }
    result.exceptionAnalysis.partial = partial != 0;
    if (reader.remaining() != 0) return std::nullopt;
    return result;
}

bool writeAtomically(const std::filesystem::path& target, const std::vector<uint8_t>& bytes) noexcept {
    static std::atomic<uint64_t> sequence = 0;
    std::filesystem::path temporary;
    struct TemporaryFileCleanup {
        ~TemporaryFileCleanup() {
            if (path.empty()) return;
            std::error_code error;
            std::filesystem::remove(path, error);
        }

        std::filesystem::path& path;
    } cleanup{temporary};

    try {
        std::error_code error;
        std::filesystem::create_directories(target.parent_path(), error);
        if (error) return false;

        const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
        temporary = target;
        temporary += ".tmp." + std::to_string(timestamp) + "."
            + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) + "."
            + std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
        {
            std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
            if (!output) return false;
            if (!bytes.empty()) {
                if (bytes.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) return false;
                output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            output.flush();
            if (!output) return false;
            output.close();
            if (output.fail()) return false;
        }
        std::filesystem::rename(temporary, target, error);
        if (error) return false;
        temporary.clear();
        return true;
    } catch (...) {
        return false;
    }
}

class ExactComparator {
public:
    ExactComparator(const RecoveredFunction& before, const RecoveredFunction& after, bool ignoreName)
        : before_(before), after_(after), ignoreName_(ignoreName) {}

    RecoveryExactComparison compare() {
        compareScalar(RecoveryExactMismatchKind::Architecture, "architecture",
            static_cast<uint64_t>(before_.architecture), static_cast<uint64_t>(after_.architecture));
        compareScalar(RecoveryExactMismatchKind::Address, "address", before_.address, after_.address);
        if (!ignoreName_ && before_.name != after_.name) {
            add(RecoveryExactMismatchKind::Name, "name", before_.name, after_.name);
        }
        compareScalar(RecoveryExactMismatchKind::BlockCount, "blocks.size",
            before_.blocks.size(), after_.blocks.size());
        const size_t blockCount = std::min(before_.blocks.size(), after_.blocks.size());
        for (size_t blockIndex = 0; blockIndex < blockCount; ++blockIndex) {
            compareBlock(before_.blocks[blockIndex], after_.blocks[blockIndex], "blocks[" + std::to_string(blockIndex) + "]");
        }
        compareScalar(RecoveryExactMismatchKind::ExceptionRegionCount, "exceptionRegions.size",
            before_.exceptionRegions.size(), after_.exceptionRegions.size());
        const size_t regionCount = std::min(before_.exceptionRegions.size(), after_.exceptionRegions.size());
        for (size_t regionIndex = 0; regionIndex < regionCount; ++regionIndex) {
            const auto path = "exceptionRegions[" + std::to_string(regionIndex) + "]";
            const auto& before = before_.exceptionRegions[regionIndex];
            const auto& after = after_.exceptionRegions[regionIndex];
            compareRegionField(path + ".tryBegin", before.tryBegin, after.tryBegin);
            compareRegionField(path + ".tryEnd", before.tryEnd, after.tryEnd);
            compareRegionField(path + ".handler", before.handler, after.handler);
            compareRegionField(path + ".leaveTarget", before.leaveTarget, after.leaveTarget);
            compareRegionField(path + ".kind", static_cast<uint64_t>(before.kind), static_cast<uint64_t>(after.kind));
        }
        return std::move(result_);
    }

private:
    void add(
        RecoveryExactMismatchKind kind,
        const std::string& path,
        std::string expected,
        std::string actual) {
        result_.mismatches.push_back({kind, path, std::move(expected), std::move(actual)});
    }

    void compareScalar(
        RecoveryExactMismatchKind kind,
        const std::string& path,
        uint64_t expected,
        uint64_t actual) {
        if (expected != actual) add(kind, path, std::to_string(expected), std::to_string(actual));
    }

    void compareRegionField(const std::string& path, uint64_t expected, uint64_t actual) {
        compareScalar(RecoveryExactMismatchKind::ExceptionRegion, path, expected, actual);
    }

    void compareBlock(const BasicBlock& before, const BasicBlock& after, const std::string& path) {
        compareScalar(RecoveryExactMismatchKind::BlockAddress, path + ".address", before.address, after.address);
        compareScalar(RecoveryExactMismatchKind::StatementCount, path + ".statements.size",
            before.statements.size(), after.statements.size());
        const size_t statementCount = std::min(before.statements.size(), after.statements.size());
        for (size_t statementIndex = 0; statementIndex < statementCount; ++statementIndex) {
            compareStatement(before.statements[statementIndex], after.statements[statementIndex],
                path + ".statements[" + std::to_string(statementIndex) + "]");
        }
    }

    void compareStatement(const Statement& before, const Statement& after, const std::string& path) {
        compareScalar(RecoveryExactMismatchKind::StatementKind, path + ".kind",
            static_cast<uint64_t>(before.kind), static_cast<uint64_t>(after.kind));
        compareScalar(RecoveryExactMismatchKind::StatementAddress, path + ".address", before.address, after.address);
        compareExpression(before.destination, after.destination, path + ".destination");
        compareExpression(before.value, after.value, path + ".value");
        compareExpression(before.condition, after.condition, path + ".condition");
        compareExpression(before.target, after.target, path + ".target");
        compareScalar(RecoveryExactMismatchKind::ExpressionArgumentCount, path + ".arguments.size",
            before.arguments.size(), after.arguments.size());
        const size_t argumentCount = std::min(before.arguments.size(), after.arguments.size());
        for (size_t argumentIndex = 0; argumentIndex < argumentCount; ++argumentIndex) {
            compareExpression(before.arguments[argumentIndex], after.arguments[argumentIndex],
                path + ".arguments[" + std::to_string(argumentIndex) + "]");
        }
    }

    void compareExpression(const ExpressionPtr& before, const ExpressionPtr& after, const std::string& path) {
        if (!before || !after) {
            if (static_cast<bool>(before) != static_cast<bool>(after)) {
                add(RecoveryExactMismatchKind::ExpressionPresence, path,
                    before ? "present" : "null", after ? "present" : "null");
            }
            return;
        }

        const auto previous = compared_.find(before.get());
        if (previous != compared_.end()) {
            if (previous->second != after.get()) {
                add(RecoveryExactMismatchKind::ExpressionSharing, path, "previous target", "different target");
            }
            return;
        }
        const auto reverse = reverseCompared_.find(after.get());
        if (reverse != reverseCompared_.end() && reverse->second != before.get()) {
            add(RecoveryExactMismatchKind::ExpressionSharing, path, "distinct source", "shared target");
            return;
        }
        compared_.emplace(before.get(), after.get());
        reverseCompared_.emplace(after.get(), before.get());

        compareScalar(RecoveryExactMismatchKind::ExpressionKind, path + ".kind",
            static_cast<uint64_t>(before->kind), static_cast<uint64_t>(after->kind));
        compareScalar(RecoveryExactMismatchKind::ScalarKind, path + ".type.kind",
            static_cast<uint64_t>(before->type.kind), static_cast<uint64_t>(after->type.kind));
        compareScalar(RecoveryExactMismatchKind::ScalarWidth, path + ".type.bits",
            before->type.bits, after->type.bits);
        compareScalar(RecoveryExactMismatchKind::ExpressionConstant, path + ".constant",
            before->constant, after->constant);
        if (before->name != after->name) {
            add(RecoveryExactMismatchKind::ExpressionName, path + ".name", before->name, after->name);
        }
        if (before->op != after->op) {
            add(RecoveryExactMismatchKind::ExpressionOperation, path + ".op", before->op, after->op);
        }
        compareScalar(RecoveryExactMismatchKind::ExpressionArgumentCount, path + ".arguments.size",
            before->arguments.size(), after->arguments.size());
        const size_t argumentCount = std::min(before->arguments.size(), after->arguments.size());
        for (size_t argumentIndex = 0; argumentIndex < argumentCount; ++argumentIndex) {
            compareExpression(before->arguments[argumentIndex], after->arguments[argumentIndex],
                path + ".arguments[" + std::to_string(argumentIndex) + "]");
        }
    }

    const RecoveredFunction& before_;
    const RecoveredFunction& after_;
    bool ignoreName_;
    RecoveryExactComparison result_;
    std::unordered_map<const Expression*, const Expression*> compared_;
    std::unordered_map<const Expression*, const Expression*> reverseCompared_;
};

class DurationMeasurement {
public:
    explicit DurationMeasurement(std::atomic<uint64_t>& target) noexcept
        : target(target), started(std::chrono::steady_clock::now()) {}

    ~DurationMeasurement() {
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started);
        target.fetch_add(static_cast<uint64_t>(elapsed.count()), std::memory_order_relaxed);
    }

    DurationMeasurement(const DurationMeasurement&) = delete;
    DurationMeasurement& operator=(const DurationMeasurement&) = delete;

private:
    std::atomic<uint64_t>& target;
    std::chrono::steady_clock::time_point started;
};

} // namespace

class RecoveryPipeline::Impl {
public:
    explicit Impl(const RecoveryPipelineOptions& options)
        : workerCount_(options.workerCount == 0
                ? std::max(1U, std::thread::hardware_concurrency())
                : options.workerCount),
          queueCapacity_(options.queueCapacity == 0 ? workerCount_ : options.queueCapacity),
          queueByteCapacity_(options.queueByteCapacity == 0 ? defaultQueueByteCapacity : options.queueByteCapacity),
          cacheCapacity_(options.cacheCapacity),
          codeOwnership_(options.codeOwnership),
          sourceProfile_(options.sourceProfile),
          sourceProfileHash_(hashSourceProfile(sourceProfile_)),
          cacheDirectory_(options.cacheDirectory) {
        workers_.reserve(workerCount_);
        try {
            for (size_t i = 0; i < workerCount_; ++i) {
                workers_.emplace_back([this] { workerLoop(); });
            }
        } catch (...) {
            {
                std::lock_guard lock(queueMutex_);
                stopping_ = true;
            }
            queueAvailable_.notify_all();
            queueConsumed_.notify_all();
            for (auto& worker : workers_) {
                if (worker.joinable()) worker.join();
            }
            throw;
        }
    }

    ~Impl() {
        {
            std::lock_guard lock(queueMutex_);
            stopping_ = true;
        }
        {
            std::lock_guard lock(activeMutex_);
            for (const auto& batch : activeBatches_) {
                batch->cancelRequested.store(true, std::memory_order_release);
            }
        }
        queueAvailable_.notify_all();
        queueConsumed_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable()) worker.join();
        }
    }

    std::vector<RecoveryResult> recover(
        const std::vector<FunctionImage>& images,
        std::stop_token cancellation) {
        DurationMeasurement totalTime(stats_.totalRecoverTime);
        stats_.recoverCalls.fetch_add(1, std::memory_order_relaxed);
        stats_.images.fetch_add(images.size(), std::memory_order_relaxed);

        auto batch = std::make_shared<Batch>(images.size(), cancellation);
        ActiveBatchGuard active(this, batch);

        try {
            for (size_t i = 0; i < images.size(); ++i) {
                if (batch->isCancelled() || stoppingRequested()) break;

                const auto& source = images[i];
                auto& result = batch->results[i];
                if (source.size != 0 && source.code == nullptr) {
                    result.status = RecoveryResultStatus::Error;
                    result.errorCategory = RecoveryErrorCategory::InvalidImage;
                    result.error = "Function image has a null code pointer with a non-zero size";
                    continue;
                }
                stats_.inputBytes.fetch_add(source.size, std::memory_order_relaxed);
                if (codeOwnership_ == RecoveryCodeOwnership::Borrow) {
                    stats_.borrowedCodeBytes.fetch_add(source.size, std::memory_order_relaxed);
                }

                Job job;
                job.image = source;
                job.key = CacheKey{
                    source.architecture, source.address, hashCode(source.code, source.size), source.size,
                    sourceProfileHash_, source.arm32Mode};
                job.queueBytes = queueCharge(source);

                if (auto cached = lookupCache(job, result)) {
                    if (batch->isCancelled()) break;
                    cached->name = source.name;
                    result.function = std::move(*cached);
                    result.status = RecoveryResultStatus::CacheHit;
                    populatePartialReasons(result);
                    continue;
                }

                if (job.queueBytes > queueByteCapacity_) {
                    result.status = RecoveryResultStatus::Error;
                    result.errorCategory = RecoveryErrorCategory::QueueCapacity;
                    result.error = "Function image requires " + std::to_string(job.queueBytes)
                        + " queue bytes, exceeding the capacity of " + std::to_string(queueByteCapacity_);
                    continue;
                }

                if (codeOwnership_ == RecoveryCodeOwnership::Copy) {
                    auto code = std::make_shared<CodeBuffer>();
                    if (source.size != 0) code->assign(source.code, source.code + source.size);
                    job.ownedCode = std::move(code);
                    job.image.code = job.ownedCode->data();
                    stats_.copiedCodeBytes.fetch_add(source.size, std::memory_order_relaxed);
                }

                if (!enqueue(Task{batch, i, std::move(job)})) break;
            }
        } catch (...) {
            batch->cancelRequested.store(true, std::memory_order_release);
            queueConsumed_.notify_all();
            finishRecover(*batch);
            throw;
        }

        finishRecover(*batch);
        return std::move(batch->results);
    }

    void cancel() {
        {
            std::lock_guard lock(activeMutex_);
            for (const auto& batch : activeBatches_) {
                batch->cancelRequested.store(true, std::memory_order_release);
            }
        }
        queueConsumed_.notify_all();
    }

    void clearCache() {
        std::lock_guard lock(cacheMutex_);
        cache_.clear();
        cacheLru_.clear();
        stats_.cacheCodeBytes.store(0, std::memory_order_relaxed);
    }

    size_t workerCount() const noexcept {
        return workerCount_;
    }

    size_t queueCapacity() const noexcept {
        return queueCapacity_;
    }

    size_t queueByteCapacity() const noexcept {
        return queueByteCapacity_;
    }

    size_t cacheSize() const {
        std::lock_guard lock(cacheMutex_);
        return cache_.size();
    }

    RecoveryPipelineStats stats() const noexcept {
        RecoveryPipelineStats result;
        result.recoverCalls = stats_.recoverCalls.load(std::memory_order_relaxed);
        result.images = stats_.images.load(std::memory_order_relaxed);
        result.succeeded = stats_.succeeded.load(std::memory_order_relaxed);
        result.cacheHits = stats_.cacheHits.load(std::memory_order_relaxed);
        result.errors = stats_.errors.load(std::memory_order_relaxed);
        result.cancelled = stats_.cancelled.load(std::memory_order_relaxed);
        result.cacheLookups = stats_.cacheLookups.load(std::memory_order_relaxed);
        result.cacheMisses = stats_.cacheMisses.load(std::memory_order_relaxed);
        result.cacheStores = stats_.cacheStores.load(std::memory_order_relaxed);
        result.cacheEvictions = stats_.cacheEvictions.load(std::memory_order_relaxed);
        result.inputBytes = stats_.inputBytes.load(std::memory_order_relaxed);
        result.copiedCodeBytes = stats_.copiedCodeBytes.load(std::memory_order_relaxed);
        result.borrowedCodeBytes = stats_.borrowedCodeBytes.load(std::memory_order_relaxed);
        result.currentQueueBytes = stats_.currentQueueBytes.load(std::memory_order_relaxed);
        result.peakQueueBytes = stats_.peakQueueBytes.load(std::memory_order_relaxed);
        result.cacheCodeBytes = stats_.cacheCodeBytes.load(std::memory_order_relaxed);
        result.totalRecoverTime = std::chrono::nanoseconds(stats_.totalRecoverTime.load(std::memory_order_relaxed));
        result.queueWaitTime = std::chrono::nanoseconds(stats_.queueWaitTime.load(std::memory_order_relaxed));
        result.recoveryTime = std::chrono::nanoseconds(stats_.recoveryTime.load(std::memory_order_relaxed));
        result.diskCacheLookups = stats_.diskCacheLookups.load(std::memory_order_relaxed);
        result.diskCacheHits = stats_.diskCacheHits.load(std::memory_order_relaxed);
        result.diskCacheMisses = stats_.diskCacheMisses.load(std::memory_order_relaxed);
        result.diskCacheWrites = stats_.diskCacheWrites.load(std::memory_order_relaxed);
        result.diskCacheErrors = stats_.diskCacheErrors.load(std::memory_order_relaxed);
        result.diskCacheBytesRead = stats_.diskCacheBytesRead.load(std::memory_order_relaxed);
        result.diskCacheBytesWritten = stats_.diskCacheBytesWritten.load(std::memory_order_relaxed);
        return result;
    }

    RecoveryProfileStats profileStats() const {
        RecoveryProfileStats result;
        result.sourceProfile = sourceProfile_;
        result.memoryCacheHits = profileStats_.memoryCacheHits.load(std::memory_order_relaxed);
        result.persistentCacheHits = profileStats_.persistentCacheHits.load(std::memory_order_relaxed);
        result.reusedCodeBytes = profileStats_.reusedCodeBytes.load(std::memory_order_relaxed);
        result.reusedExpressionNodes = profileStats_.reusedExpressionNodes.load(std::memory_order_relaxed);
        result.reusedStatements = profileStats_.reusedStatements.load(std::memory_order_relaxed);
        result.reusedPersistentBytes = profileStats_.reusedPersistentBytes.load(std::memory_order_relaxed);
        return result;
    }

    RecoveryPipelineDiagnostics diagnostics() const {
        RecoveryPipelineDiagnostics result;
        result.exactFunctions = stats_.exactFunctions.load(std::memory_order_relaxed);
        result.partialFunctions = stats_.partialFunctions.load(std::memory_order_relaxed);
        result.partialReasonOccurrences = stats_.partialReasonOccurrences.load(std::memory_order_relaxed);
        result.invalidImageErrors = stats_.invalidImageErrors.load(std::memory_order_relaxed);
        result.queueCapacityErrors = stats_.queueCapacityErrors.load(std::memory_order_relaxed);
        result.recoveryErrors = stats_.recoveryErrors.load(std::memory_order_relaxed);
        result.persistentCacheErrors = stats_.diskCacheErrors.load(std::memory_order_relaxed);
        std::lock_guard lock(diagnosticsMutex_);
        result.partialReasons.reserve(partialReasonCounts_.size());
        for (const auto& [reason, count] : partialReasonCounts_) {
            result.partialReasons.push_back({reason.first, reason.second, count});
        }
        return result;
    }

private:
    struct MutableStats {
        std::atomic<uint64_t> recoverCalls = 0;
        std::atomic<uint64_t> images = 0;
        std::atomic<uint64_t> succeeded = 0;
        std::atomic<uint64_t> cacheHits = 0;
        std::atomic<uint64_t> errors = 0;
        std::atomic<uint64_t> cancelled = 0;
        std::atomic<uint64_t> cacheLookups = 0;
        std::atomic<uint64_t> cacheMisses = 0;
        std::atomic<uint64_t> cacheStores = 0;
        std::atomic<uint64_t> cacheEvictions = 0;
        std::atomic<uint64_t> inputBytes = 0;
        std::atomic<uint64_t> copiedCodeBytes = 0;
        std::atomic<uint64_t> borrowedCodeBytes = 0;
        std::atomic<uint64_t> currentQueueBytes = 0;
        std::atomic<uint64_t> peakQueueBytes = 0;
        std::atomic<uint64_t> cacheCodeBytes = 0;
        std::atomic<uint64_t> totalRecoverTime = 0;
        std::atomic<uint64_t> queueWaitTime = 0;
        std::atomic<uint64_t> recoveryTime = 0;
        std::atomic<uint64_t> diskCacheLookups = 0;
        std::atomic<uint64_t> diskCacheHits = 0;
        std::atomic<uint64_t> diskCacheMisses = 0;
        std::atomic<uint64_t> diskCacheWrites = 0;
        std::atomic<uint64_t> diskCacheErrors = 0;
        std::atomic<uint64_t> diskCacheBytesRead = 0;
        std::atomic<uint64_t> diskCacheBytesWritten = 0;
        std::atomic<uint64_t> exactFunctions = 0;
        std::atomic<uint64_t> partialFunctions = 0;
        std::atomic<uint64_t> partialReasonOccurrences = 0;
        std::atomic<uint64_t> invalidImageErrors = 0;
        std::atomic<uint64_t> queueCapacityErrors = 0;
        std::atomic<uint64_t> recoveryErrors = 0;
    };

    struct MutableProfileStats {
        std::atomic<uint64_t> memoryCacheHits = 0;
        std::atomic<uint64_t> persistentCacheHits = 0;
        std::atomic<uint64_t> reusedCodeBytes = 0;
        std::atomic<uint64_t> reusedExpressionNodes = 0;
        std::atomic<uint64_t> reusedStatements = 0;
        std::atomic<uint64_t> reusedPersistentBytes = 0;
    };

    struct ActiveBatchGuard {
        ActiveBatchGuard(Impl* impl, std::shared_ptr<Batch> batch)
            : impl(impl), batch(std::move(batch)) {
            std::lock_guard lock(impl->activeMutex_);
            impl->activeBatches_.push_back(this->batch);
        }

        ~ActiveBatchGuard() {
            std::lock_guard lock(impl->activeMutex_);
            auto& batches = impl->activeBatches_;
            batches.erase(std::remove(batches.begin(), batches.end(), batch), batches.end());
        }

        ActiveBatchGuard(const ActiveBatchGuard&) = delete;
        ActiveBatchGuard& operator=(const ActiveBatchGuard&) = delete;

        Impl* impl;
        std::shared_ptr<Batch> batch;
    };

    struct BatchCompletion {
        ~BatchCompletion() {
            bool finished = false;
            {
                std::lock_guard lock(batch->mutex);
                finished = --batch->pending == 0;
            }
            if (finished) batch->finished.notify_all();
        }

        std::shared_ptr<Batch> batch;
    };

    static void updatePeak(std::atomic<uint64_t>& peak, uint64_t value) noexcept {
        auto current = peak.load(std::memory_order_relaxed);
        while (current < value
            && !peak.compare_exchange_weak(current, value, std::memory_order_relaxed, std::memory_order_relaxed)) {
        }
    }

    void recordProfileReuse(
        bool persistent,
        uint64_t codeBytes,
        uint64_t expressionCount,
        uint64_t statementCount,
        uint64_t persistentBytes) noexcept {
        if (persistent) profileStats_.persistentCacheHits.fetch_add(1, std::memory_order_relaxed);
        else profileStats_.memoryCacheHits.fetch_add(1, std::memory_order_relaxed);
        profileStats_.reusedCodeBytes.fetch_add(codeBytes, std::memory_order_relaxed);
        profileStats_.reusedExpressionNodes.fetch_add(expressionCount, std::memory_order_relaxed);
        profileStats_.reusedStatements.fetch_add(statementCount, std::memory_order_relaxed);
        profileStats_.reusedPersistentBytes.fetch_add(persistentBytes, std::memory_order_relaxed);
    }

    void populatePartialReasons(RecoveryResult& result) noexcept {
        if (!result.succeeded() || !result.function) return;
        try {
            result.partialReasons.clear();
            for (const auto& diagnostic : result.recoveryDiagnostics) {
                result.partialReasons.push_back({diagnostic.address,
                    "Recovery diagnostic " + std::to_string(static_cast<uint32_t>(diagnostic.kind))
                        + " at target " + std::to_string(diagnostic.target)});
            }
            for (const auto& diagnostic : result.exceptionAnalysis.diagnostics) {
                result.partialReasons.push_back({diagnostic.address, diagnostic.message});
            }
            if (result.exceptionAnalysis.partial && result.exceptionAnalysis.diagnostics.empty()) {
                result.partialReasons.push_back({result.function->address, "Exception region analysis is incomplete"});
            }
            auto emission = result.function->emitCSharp();
            result.partialReasons.insert(result.partialReasons.end(),
                std::make_move_iterator(emission.diagnostics.begin()), std::make_move_iterator(emission.diagnostics.end()));
            if (emission.partial && emission.diagnostics.empty()) {
                result.partialReasons.push_back({result.function->address, "C# emission is incomplete"});
            }
        } catch (...) {
            try {
                result.partialReasons.clear();
                result.partialReasons.push_back({result.function->address, "C# emission analysis failed"});
            } catch (...) {
            }
        }
    }

    bool stoppingRequested() const {
        std::lock_guard lock(queueMutex_);
        return stopping_;
    }

    void finishRecover(Batch& batch) noexcept {
        {
            std::unique_lock lock(batch.mutex);
            batch.finished.wait(lock, [&batch] { return batch.pending == 0; });
        }
        for (const auto& result : batch.results) {
            switch (result.status) {
            case RecoveryResultStatus::Success:
                stats_.succeeded.fetch_add(1, std::memory_order_relaxed);
                break;
            case RecoveryResultStatus::CacheHit:
                stats_.succeeded.fetch_add(1, std::memory_order_relaxed);
                stats_.cacheHits.fetch_add(1, std::memory_order_relaxed);
                break;
            case RecoveryResultStatus::Cancelled:
                stats_.cancelled.fetch_add(1, std::memory_order_relaxed);
                break;
            case RecoveryResultStatus::Error:
                stats_.errors.fetch_add(1, std::memory_order_relaxed);
                switch (result.errorCategory) {
                case RecoveryErrorCategory::InvalidImage:
                    stats_.invalidImageErrors.fetch_add(1, std::memory_order_relaxed);
                    break;
                case RecoveryErrorCategory::QueueCapacity:
                    stats_.queueCapacityErrors.fetch_add(1, std::memory_order_relaxed);
                    break;
                case RecoveryErrorCategory::Recovery:
                    stats_.recoveryErrors.fetch_add(1, std::memory_order_relaxed);
                    break;
                case RecoveryErrorCategory::None:
                    break;
                }
                break;
            }
            if (result.exact()) stats_.exactFunctions.fetch_add(1, std::memory_order_relaxed);
            else if (result.succeeded() && result.function) {
                stats_.partialFunctions.fetch_add(1, std::memory_order_relaxed);
            }
            stats_.partialReasonOccurrences.fetch_add(result.partialReasons.size(), std::memory_order_relaxed);
        }
        try {
            std::lock_guard lock(diagnosticsMutex_);
            for (const auto& result : batch.results) {
                for (const auto& reason : result.partialReasons) {
                    ++partialReasonCounts_[{reason.address, reason.message}];
                }
            }
        } catch (...) {
        }
    }

    bool enqueue(Task task) {
        DurationMeasurement waitTime(stats_.queueWaitTime);
        std::unique_lock lock(queueMutex_);
        queueConsumed_.wait(lock, task.batch->cancellation, [this, &task] {
            return stopping_ || task.batch->isCancelled()
                || (queue_.size() < queueCapacity_
                    && task.job.queueBytes <= queueByteCapacity_ - queueBytes_);
        });
        if (stopping_ || task.batch->isCancelled()) return false;

        queue_.push_back(std::move(task));
        queueBytes_ += queue_.back().job.queueBytes;
        stats_.currentQueueBytes.store(queueBytes_, std::memory_order_relaxed);
        updatePeak(stats_.peakQueueBytes, queueBytes_);
        {
            std::lock_guard batchLock(queue_.back().batch->mutex);
            ++queue_.back().batch->pending;
        }
        lock.unlock();
        queueAvailable_.notify_one();
        return true;
    }

    std::optional<RecoveredFunction> lookupCache(const Job& job, RecoveryResult& result) {
        if (cacheCapacity_ != 0) {
            stats_.cacheLookups.fetch_add(1, std::memory_order_relaxed);
            std::shared_ptr<const RecoveredFunction> cached;
            uint64_t expressionCount = 0;
            uint64_t statementCount = 0;
            std::vector<RecoveryDiagnostic> diagnostics;
            flow::ExceptionRegionAnalysis exceptionAnalysis;
            {
                std::lock_guard lock(cacheMutex_);
                const auto entry = cache_.find(job.key);
                if (entry != cache_.end()
                    && std::equal(entry->second.code->begin(), entry->second.code->end(), job.image.code)) {
                    cacheLru_.splice(cacheLru_.begin(), cacheLru_, entry->second.lruPosition);
                    cached = entry->second.function;
                    expressionCount = entry->second.expressionCount;
                    statementCount = entry->second.statementCount;
                    diagnostics = entry->second.recoveryDiagnostics;
                    exceptionAnalysis = entry->second.exceptionAnalysis;
                } else {
                    stats_.cacheMisses.fetch_add(1, std::memory_order_relaxed);
                }
            }
            if (cached) {
                result.recoveryDiagnostics = std::move(diagnostics);
                result.exceptionAnalysis = std::move(exceptionAnalysis);
                recordProfileReuse(false, job.image.size, expressionCount, statementCount, 0);
                return cloneRecoveredFunction(*cached);
            }
        }

        auto disk = lookupDiskCache(job);
        if (!disk) return std::nullopt;
        recordProfileReuse(
            true, job.image.size, disk->expressionCount, disk->statementCount, disk->serializedBytes);
        if (cacheCapacity_ == 0) {
            result.recoveryDiagnostics = std::move(disk->recoveryDiagnostics);
            result.exceptionAnalysis = std::move(disk->exceptionAnalysis);
            return std::move(disk->function);
        }
        auto cached = std::make_shared<RecoveredFunction>(std::move(disk->function));
        storeMemoryCache(job, cached, disk->code, disk->expressionCount, disk->statementCount,
            disk->recoveryDiagnostics, disk->exceptionAnalysis);
        result.recoveryDiagnostics = disk->recoveryDiagnostics;
        result.exceptionAnalysis = disk->exceptionAnalysis;
        return cloneRecoveredFunction(*cached);
    }

    std::optional<DiskCacheData> lookupDiskCache(const Job& job) noexcept {
        if (cacheDirectory_.empty()) return std::nullopt;
        stats_.diskCacheLookups.fetch_add(1, std::memory_order_relaxed);
        const auto miss = [this](bool error) {
            stats_.diskCacheMisses.fetch_add(1, std::memory_order_relaxed);
            if (error) stats_.diskCacheErrors.fetch_add(1, std::memory_order_relaxed);
        };

        try {
            const auto target = diskCachePath(cacheDirectory_, job);
            std::error_code error;
            const bool exists = std::filesystem::exists(target, error);
            if (error || !exists) {
                miss(error != std::error_code{});
                return std::nullopt;
            }

            std::ifstream input(target, std::ios::binary | std::ios::ate);
            if (!input) {
                miss(true);
                return std::nullopt;
            }
            const auto end = input.tellg();
            if (end < std::streampos(0)) {
                miss(true);
                return std::nullopt;
            }
            const auto fileSize = static_cast<uint64_t>(static_cast<std::streamoff>(end));
            if (fileSize > maxDiskCacheFileSize || fileSize > std::numeric_limits<size_t>::max()
                || fileSize > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
                miss(true);
                return std::nullopt;
            }

            std::vector<uint8_t> bytes(static_cast<size_t>(fileSize));
            input.seekg(0);
            if (!bytes.empty()) {
                input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
                if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
                    miss(true);
                    return std::nullopt;
                }
            }
            stats_.diskCacheBytesRead.fetch_add(bytes.size(), std::memory_order_relaxed);
            auto result = deserializeDiskCache(bytes, job, sourceProfile_);
            if (!result) {
                miss(true);
                return std::nullopt;
            }
            stats_.diskCacheHits.fetch_add(1, std::memory_order_relaxed);
            return result;
        } catch (...) {
            miss(true);
            return std::nullopt;
        }
    }

    void storeMemoryCache(
        const Job& job,
        const std::shared_ptr<const RecoveredFunction>& cached,
        const SharedCodeBuffer& code,
        uint64_t expressionCount,
        uint64_t statementCount,
        const std::vector<RecoveryDiagnostic>& diagnostics,
        const flow::ExceptionRegionAnalysis& exceptionAnalysis) {
        std::lock_guard lock(cacheMutex_);
        const auto existing = cache_.find(job.key);
        if (existing != cache_.end()) {
            stats_.cacheCodeBytes.fetch_sub(existing->second.code->size(), std::memory_order_relaxed);
            cacheLru_.erase(existing->second.lruPosition);
            cache_.erase(existing);
        }

        cacheLru_.push_front(job.key);
        try {
            cache_.emplace(job.key, CacheEntry{
                cacheLru_.begin(), cached, code, expressionCount, statementCount, diagnostics, exceptionAnalysis});
        } catch (...) {
            cacheLru_.pop_front();
            throw;
        }
        stats_.cacheCodeBytes.fetch_add(code->size(), std::memory_order_relaxed);
        stats_.cacheStores.fetch_add(1, std::memory_order_relaxed);

        while (cache_.size() > cacheCapacity_) {
            const auto oldest = std::prev(cacheLru_.end());
            const auto entry = cache_.find(*oldest);
            stats_.cacheCodeBytes.fetch_sub(entry->second.code->size(), std::memory_order_relaxed);
            cache_.erase(entry);
            cacheLru_.erase(oldest);
            stats_.cacheEvictions.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void storeDiskCache(const Job& job, const RecoveryOutcome& outcome) noexcept {
        if (cacheDirectory_.empty()) return;
        try {
            const auto bytes = serializeDiskCache(job, outcome, sourceProfile_);
            const auto target = diskCachePath(cacheDirectory_, job);
            if (writeAtomically(target, bytes)) {
                stats_.diskCacheWrites.fetch_add(1, std::memory_order_relaxed);
                stats_.diskCacheBytesWritten.fetch_add(bytes.size(), std::memory_order_relaxed);
            } else {
                stats_.diskCacheErrors.fetch_add(1, std::memory_order_relaxed);
            }
        } catch (...) {
            stats_.diskCacheErrors.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void storeCache(const Job& job, const RecoveryOutcome& outcome) {
        if (cacheCapacity_ != 0 && job.ownedCode) {
            IrShape shape;
            auto cached = std::make_shared<RecoveredFunction>(cloneRecoveredFunction(outcome.function, &shape));
            cached->name.clear();
            storeMemoryCache(job, cached, job.ownedCode, shape.expressionCount, shape.statementCount,
                outcome.diagnostics, outcome.exceptionAnalysis);
        }
        storeDiskCache(job, outcome);
    }

    void process(Task task) {
        BatchCompletion completion{task.batch};
        auto& result = task.batch->results[task.index];
        if (task.batch->isCancelled() || stoppingRequested()) return;

        try {
            if (auto cached = lookupCache(task.job, result)) {
                if (task.batch->isCancelled() || stoppingRequested()) return;
                cached->name = task.job.image.name;
                result.function = std::move(*cached);
                result.status = RecoveryResultStatus::CacheHit;
                populatePartialReasons(result);
                return;
            }

            Recovery recovery;
            RecoveryOutcome outcome;
            {
                DurationMeasurement recoveryTime(stats_.recoveryTime);
                outcome = recovery.recoverWithDiagnostics(task.job.image);
            }
            if (task.batch->isCancelled() || stoppingRequested()) return;

            storeCache(task.job, outcome);
            result.function = std::move(outcome.function);
            result.recoveryDiagnostics = std::move(outcome.diagnostics);
            result.exceptionAnalysis = std::move(outcome.exceptionAnalysis);
            result.status = RecoveryResultStatus::Success;
            populatePartialReasons(result);
        } catch (const std::exception& exception) {
            if (task.batch->isCancelled() || stoppingRequested()) return;
            result.status = RecoveryResultStatus::Error;
            result.errorCategory = RecoveryErrorCategory::Recovery;
            result.error = exception.what();
        } catch (...) {
            if (task.batch->isCancelled() || stoppingRequested()) return;
            result.status = RecoveryResultStatus::Error;
            result.errorCategory = RecoveryErrorCategory::Recovery;
            result.error = "Unknown recovery error";
        }
    }

    void workerLoop() {
        for (;;) {
            Task task;
            {
                std::unique_lock lock(queueMutex_);
                queueAvailable_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (stopping_ && queue_.empty()) return;
                task = std::move(queue_.front());
                queueBytes_ -= task.job.queueBytes;
                stats_.currentQueueBytes.store(queueBytes_, std::memory_order_relaxed);
                queue_.pop_front();
            }
            queueConsumed_.notify_one();
            process(std::move(task));
        }
    }

    static constexpr size_t defaultQueueByteCapacity = 64 * 1024 * 1024;

    const size_t workerCount_;
    const size_t queueCapacity_;
    const size_t queueByteCapacity_;
    const size_t cacheCapacity_;
    const RecoveryCodeOwnership codeOwnership_;
    const RecoverySourceProfile sourceProfile_;
    const ProfileHash sourceProfileHash_;
    const std::filesystem::path cacheDirectory_;

    std::vector<std::jthread> workers_;
    std::deque<Task> queue_;
    size_t queueBytes_ = 0;
    mutable std::mutex queueMutex_;
    std::condition_variable queueAvailable_;
    std::condition_variable_any queueConsumed_;
    bool stopping_ = false;

    std::mutex activeMutex_;
    std::vector<std::shared_ptr<Batch>> activeBatches_;

    mutable std::mutex cacheMutex_;
    std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;
    std::list<CacheKey> cacheLru_;

    mutable std::mutex diagnosticsMutex_;
    std::map<std::pair<uint64_t, std::string>, uint64_t> partialReasonCounts_;

    MutableStats stats_;
    MutableProfileStats profileStats_;
};

RecoveryPipeline::RecoveryPipeline(const RecoveryPipelineOptions& options)
    : impl_(std::make_unique<Impl>(options)) {}

RecoveryPipeline::~RecoveryPipeline() = default;

std::vector<RecoveryResult> RecoveryPipeline::recover(
    const std::vector<FunctionImage>& images,
    std::stop_token cancellation) {
    return impl_->recover(images, cancellation);
}

void RecoveryPipeline::cancel() {
    impl_->cancel();
}

void RecoveryPipeline::clearCache() {
    impl_->clearCache();
}

size_t RecoveryPipeline::workerCount() const noexcept {
    return impl_->workerCount();
}

size_t RecoveryPipeline::queueCapacity() const noexcept {
    return impl_->queueCapacity();
}

size_t RecoveryPipeline::queueByteCapacity() const noexcept {
    return impl_->queueByteCapacity();
}

size_t RecoveryPipeline::cacheSize() const {
    return impl_->cacheSize();
}

RecoveryPipelineStats RecoveryPipeline::stats() const noexcept {
    return impl_->stats();
}

RecoveryProfileStats RecoveryPipeline::profileStats() const {
    return impl_->profileStats();
}

RecoveryPipelineDiagnostics RecoveryPipeline::diagnostics() const {
    return impl_->diagnostics();
}

RecoveryExactComparison RecoveryPipeline::compareExact(
    const RecoveredFunction& before,
    const RecoveredFunction& after,
    bool ignoreName) {
    return ExactComparator(before, after, ignoreName).compare();
}

RecoveryExactComparison RecoveryPipeline::compareProfilesExact(
    const RecoverySourceProfile& before,
    const RecoverySourceProfile& after) {
    RecoveryExactComparison result;
    const auto compareString = [&result](
        RecoveryExactMismatchKind kind, const std::string& path, const std::string& expected, const std::string& actual) {
        if (expected != actual) result.mismatches.push_back({kind, path, expected, actual});
    };
    const auto compareInteger = [&result](
        RecoveryExactMismatchKind kind, const std::string& path, uint64_t expected, uint64_t actual) {
        if (expected != actual) {
            result.mismatches.push_back({kind, path, std::to_string(expected), std::to_string(actual)});
        }
    };
    const auto compareSection = [&result](
        RecoveryExactMismatchKind kind, const std::string& path,
        const MetadataSectionModel& expected, const MetadataSectionModel& actual) {
        const auto compareField = [&result, kind, &path](const std::string& field, int32_t expected, int32_t actual) {
            if (expected != actual) {
                result.mismatches.push_back({kind, path + "." + field,
                    std::to_string(expected), std::to_string(actual)});
            }
        };
        compareField("offset", expected.offset, actual.offset);
        compareField("sectionSize", expected.sectionSize, actual.sectionSize);
        compareField("count", expected.count, actual.count);
    };

    compareString(RecoveryExactMismatchKind::Name, "unityMetadataVersion",
        before.unityMetadataVersion, after.unityMetadataVersion);
    compareString(RecoveryExactMismatchKind::ProfileIdentity, "binaryIdentity",
        before.binaryIdentity, after.binaryIdentity);
    compareString(RecoveryExactMismatchKind::ProfileIdentity, "codeRegistrationIdentity",
        before.codeRegistrationIdentity, after.codeRegistrationIdentity);
    compareString(RecoveryExactMismatchKind::ProfileIdentity, "methodPointersIdentity",
        before.methodPointersIdentity, after.methodPointersIdentity);
    compareInteger(RecoveryExactMismatchKind::LifterSemanticsVersion, "lifterSemanticsVersion",
        before.lifterSemanticsVersion, after.lifterSemanticsVersion);
    compareString(RecoveryExactMismatchKind::ProfileIdentity, "profileIdentity",
        before.profileIdentity, after.profileIdentity);
    compareString(RecoveryExactMismatchKind::LayoutIdentity, "layoutIdentity",
        before.layoutIdentity, after.layoutIdentity);
    compareInteger(RecoveryExactMismatchKind::RawMetadataVersion, "rawMetadataVersion",
        static_cast<uint32_t>(before.rawMetadataVersion), static_cast<uint32_t>(after.rawMetadataVersion));
    compareInteger(RecoveryExactMismatchKind::PreciseMetadataVersion, "preciseMetadataVersion",
        std::bit_cast<uint64_t>(before.preciseMetadataVersion), std::bit_cast<uint64_t>(after.preciseMetadataVersion));
    compareInteger(RecoveryExactMismatchKind::RegistrationVersion, "registrationVersion",
        std::bit_cast<uint64_t>(before.registrationVersion), std::bit_cast<uint64_t>(after.registrationVersion));
    compareSection(RecoveryExactMismatchKind::GeneratedMethodTypeInfos, "generatedMethodTypeInfos",
        before.generatedMethodTypeInfos, after.generatedMethodTypeInfos);
    compareSection(RecoveryExactMismatchKind::GeneratedMethodTokens, "generatedMethodTokens",
        before.generatedMethodTokens, after.generatedMethodTokens);
    compareInteger(RecoveryExactMismatchKind::ExceptionSemanticsVersion, "exceptionSemanticsVersion",
        before.exceptionSemanticsVersion, after.exceptionSemanticsVersion);
    compareInteger(RecoveryExactMismatchKind::VectorSemanticsVersion, "vectorSemanticsVersion",
        before.vectorSemanticsVersion, after.vectorSemanticsVersion);
    return result;
}

} // namespace il2cpprec
