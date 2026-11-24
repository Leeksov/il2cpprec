#include <il2cpprec/ida/McpClient.hpp>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <limits>
#include <list>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <io.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace il2cpprec::ida {

bool McpError::isTransportError() const noexcept {
    return kind == McpErrorKind::Transport;
}

bool McpError::isAnalysisError() const noexcept {
    return kind == McpErrorKind::Analysis;
}

McpError::operator bool() const noexcept {
    return kind != McpErrorKind::None;
}

namespace {

template <typename T>
McpResult<T> success(T value) {
    return McpResult<T>{std::move(value), {}};
}

template <typename T>
McpResult<T> failure(McpError error) {
    return McpResult<T>{std::nullopt, std::move(error)};
}

McpError makeError(McpErrorKind kind, std::string message, std::string rawJson = {}) {
    McpError error;
    error.kind = kind;
    error.message = std::move(message);
    error.rawJson = std::move(rawJson);
    return error;
}

struct Json {
    enum class Type {
        Null,
        Boolean,
        Number,
        String,
        Array,
        Object
    };

    Type type = Type::Null;
    bool boolean = false;
    std::string text;
    std::vector<Json> array;
    std::vector<std::pair<std::string, Json>> object;

    const Json* find(std::string_view key) const {
        if (type != Type::Object) return nullptr;
        for (const auto& [name, value] : object) {
            if (name == key) return &value;
        }
        return nullptr;
    }
};

std::string escapeJson(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() + 2);
    result.push_back('"');
    for (const unsigned char c : value) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 0x20) {
                    result += "\\u00";
                    result.push_back(hex[c >> 4]);
                    result.push_back(hex[c & 0x0f]);
                } else {
                    result.push_back(static_cast<char>(c));
                }
        }
    }
    result.push_back('"');
    return result;
}

std::string stringifyJson(const Json& value) {
    switch (value.type) {
        case Json::Type::Null: return "null";
        case Json::Type::Boolean: return value.boolean ? "true" : "false";
        case Json::Type::Number: return value.text;
        case Json::Type::String: return escapeJson(value.text);
        case Json::Type::Array: {
            std::string result = "[";
            for (std::size_t i = 0; i < value.array.size(); ++i) {
                if (i != 0) result.push_back(',');
                result += stringifyJson(value.array[i]);
            }
            result.push_back(']');
            return result;
        }
        case Json::Type::Object: {
            std::string result = "{";
            for (std::size_t i = 0; i < value.object.size(); ++i) {
                if (i != 0) result.push_back(',');
                result += escapeJson(value.object[i].first);
                result.push_back(':');
                result += stringifyJson(value.object[i].second);
            }
            result.push_back('}');
            return result;
        }
    }
    return {};
}

void appendUtf8(std::string& output, uint32_t codePoint) {
    if (codePoint <= 0x7f) {
        output.push_back(static_cast<char>(codePoint));
    } else if (codePoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codePoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    } else if (codePoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codePoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (codePoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    }
}

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    bool parse(Json& output) {
        skipWhitespace();
        if (!parseValue(output, 0)) return false;
        skipWhitespace();
        if (position_ != input_.size()) return setError("unexpected trailing characters");
        return true;
    }

    const std::string& error() const noexcept {
        return error_;
    }

private:
    bool setError(std::string message) {
        if (error_.empty()) {
            error_ = std::move(message) + " at byte " + std::to_string(position_);
        }
        return false;
    }

    void skipWhitespace() {
        while (position_ < input_.size()) {
            const char c = input_[position_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            ++position_;
        }
    }

    bool consume(char c) {
        if (position_ >= input_.size() || input_[position_] != c) return false;
        ++position_;
        return true;
    }

    bool consumeLiteral(std::string_view value) {
        if (input_.substr(position_, value.size()) != value) return false;
        position_ += value.size();
        return true;
    }

    bool parseHex4(uint32_t& value) {
        if (input_.size() - position_ < 4) return setError("incomplete Unicode escape");
        value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = input_[position_++];
            value <<= 4;
            if (c >= '0' && c <= '9') value |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') value |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value |= static_cast<uint32_t>(c - 'A' + 10);
            else return setError("invalid Unicode escape");
        }
        return true;
    }

    bool parseString(std::string& output) {
        if (!consume('"')) return setError("expected a string");
        output.clear();
        while (position_ < input_.size()) {
            const unsigned char c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"') return true;
            if (c < 0x20) return setError("control character in string");
            if (c != '\\') {
                output.push_back(static_cast<char>(c));
                continue;
            }
            if (position_ >= input_.size()) return setError("incomplete escape");
            const char escaped = input_[position_++];
            switch (escaped) {
                case '"': output.push_back('"'); break;
                case '\\': output.push_back('\\'); break;
                case '/': output.push_back('/'); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                case 'u': {
                    uint32_t codePoint = 0;
                    if (!parseHex4(codePoint)) return false;
                    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
                        if (!consume('\\') || !consume('u')) {
                            return setError("missing low surrogate");
                        }
                        uint32_t low = 0;
                        if (!parseHex4(low)) return false;
                        if (low < 0xdc00 || low > 0xdfff) return setError("invalid low surrogate");
                        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00);
                    } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
                        return setError("unexpected low surrogate");
                    }
                    appendUtf8(output, codePoint);
                    break;
                }
                default: return setError("invalid escape");
            }
        }
        return setError("unterminated string");
    }

    bool parseNumber(Json& output) {
        const std::size_t start = position_;
        consume('-');
        if (consume('0')) {
            if (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                return setError("leading zero in number");
            }
        } else {
            if (position_ >= input_.size() || input_[position_] < '1' || input_[position_] > '9') {
                return setError("invalid number");
            }
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                ++position_;
            }
        }
        if (consume('.')) {
            if (position_ >= input_.size() || input_[position_] < '0' || input_[position_] > '9') {
                return setError("invalid number fraction");
            }
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                ++position_;
            }
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            if (position_ >= input_.size() || input_[position_] < '0' || input_[position_] > '9') {
                return setError("invalid number exponent");
            }
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                ++position_;
            }
        }
        output.type = Json::Type::Number;
        output.text = std::string(input_.substr(start, position_ - start));
        return true;
    }

    bool parseArray(Json& output) {
        consume('[');
        output.type = Json::Type::Array;
        skipWhitespace();
        if (consume(']')) return true;
        while (position_ < input_.size()) {
            Json element;
            if (!parseValue(element, 0)) return false;
            output.array.push_back(std::move(element));
            skipWhitespace();
            if (consume(']')) return true;
            if (!consume(',')) return setError("expected ',' or ']'");
            skipWhitespace();
        }
        return setError("unterminated array");
    }

    bool parseObject(Json& output) {
        consume('{');
        output.type = Json::Type::Object;
        skipWhitespace();
        if (consume('}')) return true;
        while (position_ < input_.size()) {
            std::string key;
            if (!parseString(key)) return false;
            skipWhitespace();
            if (!consume(':')) return setError("expected ':'");
            skipWhitespace();
            Json value;
            if (!parseValue(value, 0)) return false;
            output.object.emplace_back(std::move(key), std::move(value));
            skipWhitespace();
            if (consume('}')) return true;
            if (!consume(',')) return setError("expected ',' or '}'");
            skipWhitespace();
        }
        return setError("unterminated object");
    }

    bool parseValue(Json& output, std::size_t depth) {
        if (depth > 128) return setError("JSON nesting limit exceeded");
        if (position_ >= input_.size()) return setError("expected a value");
        switch (input_[position_]) {
            case 'n':
                if (!consumeLiteral("null")) return setError("invalid literal");
                output = Json{};
                return true;
            case 't':
                if (!consumeLiteral("true")) return setError("invalid literal");
                output = Json{};
                output.type = Json::Type::Boolean;
                output.boolean = true;
                return true;
            case 'f':
                if (!consumeLiteral("false")) return setError("invalid literal");
                output = Json{};
                output.type = Json::Type::Boolean;
                return true;
            case '"':
                output = Json{};
                output.type = Json::Type::String;
                return parseString(output.text);
            case '[': {
                if (depth >= 128) return setError("JSON nesting limit exceeded");
                output = Json{};
                output.type = Json::Type::Array;
                consume('[');
                skipWhitespace();
                if (consume(']')) return true;
                while (position_ < input_.size()) {
                    Json element;
                    if (!parseValue(element, depth + 1)) return false;
                    output.array.push_back(std::move(element));
                    skipWhitespace();
                    if (consume(']')) return true;
                    if (!consume(',')) return setError("expected ',' or ']'");
                    skipWhitespace();
                }
                return setError("unterminated array");
            }
            case '{': {
                if (depth >= 128) return setError("JSON nesting limit exceeded");
                output = Json{};
                output.type = Json::Type::Object;
                consume('{');
                skipWhitespace();
                if (consume('}')) return true;
                while (position_ < input_.size()) {
                    std::string key;
                    if (!parseString(key)) return false;
                    skipWhitespace();
                    if (!consume(':')) return setError("expected ':'");
                    skipWhitespace();
                    Json value;
                    if (!parseValue(value, depth + 1)) return false;
                    output.object.emplace_back(std::move(key), std::move(value));
                    skipWhitespace();
                    if (consume('}')) return true;
                    if (!consume(',')) return setError("expected ',' or '}'");
                    skipWhitespace();
                }
                return setError("unterminated object");
            }
            default: return parseNumber(output);
        }
    }

    std::string_view input_;
    std::size_t position_ = 0;
    std::string error_;
};

bool parseJson(std::string_view input, Json& output, std::string& error) {
    JsonParser parser(input);
    if (!parser.parse(output)) {
        error = parser.error();
        return false;
    }
    return true;
}

const Json* findField(const Json& object, std::initializer_list<std::string_view> names) {
    for (const auto name : names) {
        if (const Json* value = object.find(name)) return value;
    }
    return nullptr;
}

std::string scalarText(const Json* value) {
    if (!value) return {};
    if (value->type == Json::Type::String || value->type == Json::Type::Number) return value->text;
    if (value->type == Json::Type::Boolean) return value->boolean ? "true" : "false";
    return {};
}

std::string fieldText(const Json& object, std::initializer_list<std::string_view> names) {
    return scalarText(findField(object, names));
}

std::optional<uint64_t> parseUnsigned(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    if (text.empty() || text.front() == '-') return std::nullopt;
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return std::nullopt;
    uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

std::optional<uint64_t> jsonAddress(const Json* value) {
    if (!value) return std::nullopt;
    if (value->type == Json::Type::Number || value->type == Json::Type::String) {
        return parseUnsigned(value->text);
    }
    return std::nullopt;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
        return static_cast<char>(c);
    });
    return value;
}

std::string trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle invalidSocket = INVALID_SOCKET;

std::string socketError() {
    const int code = WSAGetLastError();
    char* message = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        0,
        reinterpret_cast<char*>(&message),
        0,
        nullptr);
    std::string result = length && message ? std::string(message, length) : "Winsock error " + std::to_string(code);
    if (message) LocalFree(message);
    while (!result.empty() && (result.back() == '\r' || result.back() == '\n')) result.pop_back();
    return result;
}

class SocketRuntime {
public:
    SocketRuntime() {
        WSADATA data{};
        error_ = WSAStartup(MAKEWORD(2, 2), &data);
    }

    ~SocketRuntime() {
        if (error_ == 0) WSACleanup();
    }

    bool ok() const noexcept { return error_ == 0; }
    int error() const noexcept { return error_; }

private:
    int error_ = 0;
};

void closeSocket(SocketHandle socket) {
    if (socket != invalidSocket) closesocket(socket);
}

bool setBlocking(SocketHandle socket, bool blocking) {
    u_long mode = blocking ? 0 : 1;
    return ioctlsocket(socket, FIONBIO, &mode) == 0;
}
#else
using SocketHandle = int;
constexpr SocketHandle invalidSocket = -1;

std::string socketError() {
    return std::strerror(errno);
}

class SocketRuntime {
public:
    bool ok() const noexcept { return true; }
    int error() const noexcept { return 0; }
};

void closeSocket(SocketHandle socket) {
    if (socket != invalidSocket) ::close(socket);
}

bool setBlocking(SocketHandle socket, bool blocking) {
    const int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(socket, F_SETFL, blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK) == 0;
}
#endif

class SocketGuard {
public:
    explicit SocketGuard(SocketHandle socket = invalidSocket) : socket_(socket) {}
    ~SocketGuard() { closeSocket(socket_); }

    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

    SocketGuard(SocketGuard&& other) noexcept : socket_(other.release()) {}

    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            closeSocket(socket_);
            socket_ = other.release();
        }
        return *this;
    }

    SocketHandle get() const noexcept { return socket_; }
    SocketHandle release() noexcept {
        const SocketHandle result = socket_;
        socket_ = invalidSocket;
        return result;
    }

private:
    SocketHandle socket_;
};

timeval toTimeval(std::chrono::milliseconds timeout) {
    const auto milliseconds = std::max<int64_t>(0, timeout.count());
    timeval result{};
    result.tv_sec = static_cast<decltype(result.tv_sec)>(milliseconds / 1000);
    result.tv_usec = static_cast<decltype(result.tv_usec)>((milliseconds % 1000) * 1000);
    return result;
}

struct HttpResponse {
    int status = 0;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

bool decodeChunked(std::string_view input, std::string& output, std::string& error) {
    std::size_t position = 0;
    output.clear();
    while (true) {
        const std::size_t lineEnd = input.find("\r\n", position);
        if (lineEnd == std::string_view::npos) {
            error = "Incomplete chunk size";
            return false;
        }
        std::string_view sizeText = input.substr(position, lineEnd - position);
        const std::size_t extension = sizeText.find(';');
        if (extension != std::string_view::npos) sizeText = sizeText.substr(0, extension);
        uint64_t size = 0;
        const auto [sizeEnd, sizeError] = std::from_chars(
            sizeText.data(), sizeText.data() + sizeText.size(), size, 16);
        if (sizeText.empty() || sizeError != std::errc{} || sizeEnd != sizeText.data() + sizeText.size() ||
            size > std::numeric_limits<std::size_t>::max()) {
            error = "Invalid chunk size";
            return false;
        }
        position = lineEnd + 2;
        if (size == 0) return true;
        if (size > input.size() - position || input.size() - position - size < 2) {
            error = "Incomplete HTTP chunk";
            return false;
        }
        output.append(input.substr(position, static_cast<std::size_t>(size)));
        position += static_cast<std::size_t>(size);
        if (input.substr(position, 2) != "\r\n") {
            error = "Invalid HTTP chunk terminator";
            return false;
        }
        position += 2;
    }
}

McpResult<HttpResponse> parseHttpResponse(std::string bytes, std::size_t maxResponseBytes) {
    const std::size_t headerEnd = bytes.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Incomplete HTTP response headers"));
    }
    std::istringstream headerStream(bytes.substr(0, headerEnd));
    std::string statusLine;
    std::getline(headerStream, statusLine);
    if (!statusLine.empty() && statusLine.back() == '\r') statusLine.pop_back();
    std::istringstream statusStream(statusLine);
    std::string version;
    int status = 0;
    if (!(statusStream >> version >> status) || version.rfind("HTTP/", 0) != 0) {
        return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Invalid HTTP status line: " + statusLine));
    }

    HttpResponse response;
    response.status = status;
    std::string line;
    while (std::getline(headerStream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        response.headers[lower(trim(std::string_view(line).substr(0, colon)))] =
            trim(std::string_view(line).substr(colon + 1));
    }

    const std::string payload = bytes.substr(headerEnd + 4);
    const auto transfer = response.headers.find("transfer-encoding");
    if (transfer != response.headers.end() && lower(transfer->second).find("chunked") != std::string::npos) {
        std::string error;
        if (!decodeChunked(payload, response.body, error)) {
            return failure<HttpResponse>(makeError(McpErrorKind::Transport, error));
        }
    } else {
        const auto length = response.headers.find("content-length");
        if (length != response.headers.end()) {
            const auto expected = parseUnsigned(length->second);
            if (!expected) {
                return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Invalid HTTP Content-Length"));
            }
            if (*expected > maxResponseBytes) {
                return failure<HttpResponse>(makeError(McpErrorKind::Transport, "HTTP response body exceeds configured limit"));
            }
            if (payload.size() < *expected) {
                return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Incomplete HTTP response body"));
            }
            response.body = payload.substr(0, static_cast<std::size_t>(*expected));
        } else {
            response.body = payload;
        }
    }

    if (response.status < 200 || response.status >= 300) {
        return failure<HttpResponse>(makeError(
            McpErrorKind::Transport,
            "MCP HTTP request failed with status " + std::to_string(response.status) +
                (response.body.empty() ? "" : ": " + response.body.substr(0, 512)),
            response.body));
    }
    return success(std::move(response));
}

McpResult<HttpResponse> postHttp(
    const McpClientConfig& config,
    const std::string& body,
    const std::string& sessionId,
    bool includeProtocolVersion) {
    SocketRuntime runtime;
    if (!runtime.ok()) {
        return failure<HttpResponse>(makeError(
            McpErrorKind::Transport,
            "Cannot initialize sockets: " + std::to_string(runtime.error())));
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    const std::string port = std::to_string(config.port);
    const int addressResult = getaddrinfo(config.host.c_str(), port.c_str(), &hints, &addresses);
    if (addressResult != 0) {
#ifdef _WIN32
        const std::string message = gai_strerrorA(addressResult);
#else
        const std::string message = gai_strerror(addressResult);
#endif
        return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Cannot resolve MCP host: " + message));
    }
    struct AddressGuard {
        addrinfo* value;
        ~AddressGuard() { freeaddrinfo(value); }
    } addressGuard{addresses};

    SocketGuard socket;
    std::string lastError = "No usable address";
    for (addrinfo* address = addresses; address; address = address->ai_next) {
        SocketHandle candidate = ::socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate == invalidSocket) {
            lastError = socketError();
            continue;
        }
        SocketGuard candidateGuard(candidate);
        if (!setBlocking(candidate, false)) {
            lastError = socketError();
            continue;
        }

        const int connectResult = ::connect(candidate, address->ai_addr, static_cast<int>(address->ai_addrlen));
        if (connectResult != 0) {
#ifdef _WIN32
            const int error = WSAGetLastError();
            const bool pending = error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
            const int error = errno;
            const bool pending = error == EINPROGRESS;
#endif
            if (!pending) {
                lastError = socketError();
                continue;
            }
            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(candidate, &writeSet);
            timeval timeout = toTimeval(config.timeout);
            const int selected = ::select(static_cast<int>(candidate + 1), nullptr, &writeSet, nullptr, &timeout);
            if (selected <= 0) {
                lastError = selected == 0 ? "Connection timed out" : socketError();
                continue;
            }
            int connectionError = 0;
            socklen_t errorSize = sizeof(connectionError);
            if (getsockopt(candidate, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&connectionError), &errorSize) != 0 ||
                connectionError != 0) {
#ifdef _WIN32
                lastError = "Connect failed with Winsock error " + std::to_string(connectionError);
#else
                lastError = std::strerror(connectionError);
#endif
                continue;
            }
        }
        if (!setBlocking(candidate, true)) {
            lastError = socketError();
            continue;
        }

#ifdef _WIN32
        const DWORD timeout = static_cast<DWORD>(std::clamp<int64_t>(config.timeout.count(), 0, ULONG_MAX));
        setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
        const timeval timeout = toTimeval(config.timeout);
        setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#ifdef SO_NOSIGPIPE
        int enabled = 1;
        setsockopt(candidate, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
#endif
        socket = SocketGuard(candidateGuard.release());
        break;
    }
    if (socket.get() == invalidSocket) {
        return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Cannot connect to MCP server: " + lastError));
    }

    const std::string path = config.endpointPath.empty() ? "/mcp" :
        (config.endpointPath.front() == '/' ? config.endpointPath : "/" + config.endpointPath);
    const std::string host = config.host.find(':') != std::string::npos && config.host.front() != '[' ?
        "[" + config.host + "]" : config.host;
    std::string request = "POST " + path + " HTTP/1.1\r\n";
    request += "Host: " + host + ":" + std::to_string(config.port) + "\r\n";
    request += "Accept: application/json, text/event-stream\r\n";
    request += "Content-Type: application/json\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    request += "Connection: close\r\n";
    if (!sessionId.empty()) request += "Mcp-Session-Id: " + sessionId + "\r\n";
    if (includeProtocolVersion) request += "MCP-Protocol-Version: 2024-11-05\r\n";
    request += "\r\n";
    request += body;

    std::size_t sent = 0;
    while (sent < request.size()) {
#ifdef MSG_NOSIGNAL
        constexpr int flags = MSG_NOSIGNAL;
#else
        constexpr int flags = 0;
#endif
        const int count = ::send(socket.get(), request.data() + sent,
            static_cast<int>(std::min<std::size_t>(request.size() - sent, INT_MAX)), flags);
        if (count <= 0) {
            return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Cannot send MCP request: " + socketError()));
        }
        sent += static_cast<std::size_t>(count);
    }

    std::string responseBytes;
    char buffer[16384];
    while (true) {
        const int count = ::recv(socket.get(), buffer, sizeof(buffer), 0);
        if (count == 0) break;
        if (count < 0) {
            return failure<HttpResponse>(makeError(McpErrorKind::Transport, "Cannot read MCP response: " + socketError()));
        }
        if (responseBytes.size() + static_cast<std::size_t>(count) > config.maxResponseBytes + 64 * 1024) {
            return failure<HttpResponse>(makeError(McpErrorKind::Transport, "MCP response exceeds configured limit"));
        }
        responseBytes.append(buffer, static_cast<std::size_t>(count));
    }
    return parseHttpResponse(std::move(responseBytes), config.maxResponseBytes);
}

std::vector<std::string> eventData(const std::string& body) {
    std::vector<std::string> events;
    std::string data;
    std::size_t position = 0;
    auto finishEvent = [&]() {
        if (!data.empty()) {
            events.push_back(data);
            data.clear();
        }
    };
    while (position <= body.size()) {
        const std::size_t end = body.find('\n', position);
        const bool last = end == std::string::npos;
        std::string_view line = body;
        line = line.substr(position, last ? body.size() - position : end - position);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) {
            finishEvent();
        } else if (line.front() != ':' && line.substr(0, 5) == "data:") {
            std::string_view value = line.substr(5);
            if (!value.empty() && value.front() == ' ') value.remove_prefix(1);
            if (!data.empty()) data.push_back('\n');
            data.append(value);
        }
        if (last) break;
        position = end + 1;
    }
    finishEvent();
    return events;
}

bool responseIdMatches(const Json& object, uint64_t id) {
    const Json* responseId = object.find("id");
    if (!responseId) return false;
    if (responseId->type == Json::Type::Number || responseId->type == Json::Type::String) {
        return responseId->text == std::to_string(id);
    }
    return false;
}

McpResult<Json> decodeRpcObject(const Json& object, uint64_t id) {
    if (!responseIdMatches(object, id)) {
        return failure<Json>(makeError(McpErrorKind::Protocol, "JSON-RPC response id does not match request"));
    }
    if (const Json* version = object.find("jsonrpc")) {
        if (version->type != Json::Type::String || version->text != "2.0") {
            return failure<Json>(makeError(McpErrorKind::Protocol, "Unsupported JSON-RPC version"));
        }
    }
    if (const Json* rpcError = object.find("error")) {
        McpError error = makeError(McpErrorKind::Analysis, "MCP server returned a JSON-RPC error", stringifyJson(*rpcError));
        if (const Json* code = rpcError->find("code")) {
            const auto parsed = parseUnsigned(code->text);
            if (parsed && *parsed <= static_cast<uint64_t>(std::numeric_limits<int>::max())) {
                error.code = static_cast<int>(*parsed);
            } else if (code->type == Json::Type::Number && !code->text.empty() && code->text.front() == '-') {
                int value = 0;
                const auto [end, result] = std::from_chars(code->text.data(), code->text.data() + code->text.size(), value);
                if (result == std::errc{} && end == code->text.data() + code->text.size()) error.code = value;
            }
        }
        const std::string message = fieldText(*rpcError, {"message"});
        if (!message.empty()) error.message = message;
        return failure<Json>(std::move(error));
    }
    const Json* result = object.find("result");
    if (!result) return failure<Json>(makeError(McpErrorKind::Protocol, "JSON-RPC response has no result"));
    return success(*result);
}

McpResult<Json> decodeRpcResponse(const HttpResponse& response, uint64_t id) {
    const auto contentType = response.headers.find("content-type");
    const bool eventStream = contentType != response.headers.end() &&
        lower(contentType->second).find("text/event-stream") != std::string::npos;
    std::vector<std::string> payloads = eventStream ? eventData(response.body) : std::vector<std::string>{response.body};
    if (payloads.empty()) {
        return failure<Json>(makeError(McpErrorKind::Protocol, "MCP response contains no JSON-RPC message"));
    }

    for (const std::string& payload : payloads) {
        if (payload == "[DONE]") continue;
        Json root;
        std::string parseError;
        if (!parseJson(payload, root, parseError)) {
            return failure<Json>(makeError(McpErrorKind::Protocol, "Invalid JSON-RPC response: " + parseError, payload));
        }
        if (root.type == Json::Type::Array) {
            for (const Json& item : root.array) {
                if (item.type == Json::Type::Object && responseIdMatches(item, id)) return decodeRpcObject(item, id);
            }
            continue;
        }
        if (root.type != Json::Type::Object) {
            return failure<Json>(makeError(McpErrorKind::Protocol, "JSON-RPC response is not an object"));
        }
        if (responseIdMatches(root, id)) return decodeRpcObject(root, id);
    }
    return failure<Json>(makeError(McpErrorKind::Protocol, "MCP response contains no matching JSON-RPC response"));
}

struct ToolOutput {
    Json data;
    bool hasData = false;
    std::string text;
    std::string rawJson;
};

McpResult<ToolOutput> decodeToolOutput(const Json& result) {
    ToolOutput output;
    bool isError = false;
    if (const Json* value = result.find("isError"); value && value->type == Json::Type::Boolean) {
        isError = value->boolean;
    }

    if (const Json* content = result.find("content"); content && content->type == Json::Type::Array) {
        for (const Json& item : content->array) {
            if (item.type != Json::Type::Object) continue;
            const Json* text = item.find("text");
            if (!text || text->type != Json::Type::String) continue;
            if (!output.text.empty()) output.text.push_back('\n');
            output.text += text->text;
        }
        if (isError) {
            return failure<ToolOutput>(makeError(
                McpErrorKind::Analysis,
                output.text.empty() ? "MCP analysis tool failed" : output.text,
                stringifyJson(result)));
        }
        if (!output.text.empty()) {
            std::string parseError;
            output.hasData = parseJson(output.text, output.data, parseError);
        }
        if (!output.hasData) {
            if (const Json* structured = result.find("structuredContent")) {
                output.data = *structured;
                output.hasData = true;
            }
        }
        output.rawJson = output.hasData ? stringifyJson(output.data) : output.text;
        return success(std::move(output));
    }

    output.data = result;
    output.hasData = true;
    output.rawJson = stringifyJson(result);
    if (isError) {
        return failure<ToolOutput>(makeError(McpErrorKind::Analysis, "MCP analysis tool failed", output.rawJson));
    }
    return success(std::move(output));
}

std::optional<McpError> embeddedAnalysisError(const Json& node) {
    if (node.type == Json::Type::Array) {
        for (const Json& item : node.array) {
            if (auto error = embeddedAnalysisError(item)) return error;
        }
        return std::nullopt;
    }
    if (node.type != Json::Type::Object) return std::nullopt;
    if (const Json* error = node.find("error"); error && error->type != Json::Type::Null) {
        std::string message;
        if (error->type == Json::Type::String) {
            message = error->text;
        } else if (error->type == Json::Type::Object) {
            message = fieldText(*error, {"message", "error", "detail"});
        }
        if (message.empty()) message = "MCP analysis tool returned an error";
        return makeError(McpErrorKind::Analysis, message, stringifyJson(*error));
    }
    for (const auto& [key, value] : node.object) {
        if (key == "error") continue;
        if (value.type == Json::Type::Object || value.type == Json::Type::Array) {
            if (auto error = embeddedAnalysisError(value)) return error;
        }
    }
    return std::nullopt;
}

std::optional<McpError> embeddedAnalysisError(const ToolOutput& output) {
    if (!output.hasData) return std::nullopt;
    return embeddedAnalysisError(output.data);
}

std::vector<uint64_t> parseSuccessors(const Json* value) {
    std::vector<uint64_t> result;
    if (!value || value->type != Json::Type::Array) return result;
    for (const Json& item : value->array) {
        if (const auto address = jsonAddress(&item)) {
            result.push_back(*address);
        } else if (item.type == Json::Type::Object) {
            if (const auto address = jsonAddress(findField(item, {"start", "start_ea", "address", "addr", "ea"}))) {
                result.push_back(*address);
            }
        }
    }
    return result;
}

bool isWrapperKey(std::string_view key) {
    return key == "blocks" || key == "basic_blocks" || key == "callees" || key == "calls" ||
        key == "result" || key == "results" || key == "data" || key == "functions";
}

void collectBlocks(const Json& node, const std::string& functionAddress, std::vector<McpBasicBlock>& blocks) {
    if (node.type == Json::Type::Array) {
        for (const Json& item : node.array) collectBlocks(item, functionAddress, blocks);
        return;
    }
    if (node.type != Json::Type::Object) return;

    const Json* start = findField(node, {"start", "start_ea", "startAddress", "ea"});
    const Json* end = findField(node, {"end", "end_ea", "endAddress"});
    if (start || end) {
        McpBasicBlock block;
        block.functionAddress = functionAddress;
        block.start = jsonAddress(start);
        block.end = jsonAddress(end);
        block.successors = parseSuccessors(findField(node, {"successors", "succs", "next"}));
        block.rawJson = stringifyJson(node);
        blocks.push_back(std::move(block));
        return;
    }

    const std::string context = functionAddress.empty()
        ? fieldText(node, {"addr", "function_address", "functionAddress", "query"})
        : functionAddress;
    for (const auto& [key, value] : node.object) {
        if (value.type != Json::Type::Object && value.type != Json::Type::Array) continue;
        const std::string childContext = context.empty() && !isWrapperKey(key) ? key : context;
        collectBlocks(value, childContext, blocks);
    }
}

void collectCallees(const Json& node, const std::string& functionAddress, std::vector<McpCallee>& callees) {
    if (node.type == Json::Type::Array) {
        for (const Json& item : node.array) collectCallees(item, functionAddress, callees);
        return;
    }
    if (node.type == Json::Type::String || node.type == Json::Type::Number) {
        McpCallee callee;
        callee.functionAddress = functionAddress;
        callee.address = jsonAddress(&node);
        if (node.type == Json::Type::String && !callee.address) callee.name = node.text;
        callee.rawJson = stringifyJson(node);
        callees.push_back(std::move(callee));
        return;
    }
    if (node.type != Json::Type::Object) return;

    const Json* address = findField(node, {"addr", "address", "callee", "ea", "function_address", "functionAddress"});
    const std::string name = fieldText(node, {"name", "function_name", "functionName", "symbol"});
    const bool container = findField(node, {"callees", "calls", "result", "results"}) != nullptr;
    if ((address || !name.empty()) && !container) {
        McpCallee callee;
        callee.functionAddress = functionAddress;
        callee.address = jsonAddress(address);
        callee.name = name;
        callee.rawJson = stringifyJson(node);
        callees.push_back(std::move(callee));
        return;
    }

    const std::string context = functionAddress.empty()
        ? fieldText(node, {"addr", "function_address", "functionAddress", "query"})
        : functionAddress;
    for (const auto& [key, value] : node.object) {
        if (value.type != Json::Type::Object && value.type != Json::Type::Array) continue;
        const std::string childContext = context.empty() && !isWrapperKey(key) ? key : context;
        collectCallees(value, childContext, callees);
    }
}

} // namespace

class McpClient::Impl {
public:
    explicit Impl(McpClientConfig config) : config_(std::move(config)) {}

    McpResult<std::vector<McpInstance>> listInstances() {
        auto output = callTool("list_instances", "{}", {});
        if (!output) return failure<std::vector<McpInstance>>(std::move(output.error));
        if (!output.value->hasData) {
            return failure<std::vector<McpInstance>>(makeError(
                McpErrorKind::Protocol, "list_instances returned non-JSON data", output.value->rawJson));
        }

        const Json* instances = &output.value->data;
        if (instances->type == Json::Type::Object) instances = instances->find("instances");
        if (!instances || instances->type != Json::Type::Array) {
            return failure<std::vector<McpInstance>>(makeError(
                McpErrorKind::Protocol, "list_instances response has no instances array", output.value->rawJson));
        }

        std::vector<McpInstance> result;
        for (const Json& item : instances->array) {
            McpInstance instance;
            instance.rawJson = stringifyJson(item);
            if (item.type == Json::Type::String) {
                instance.id = item.text;
            } else if (item.type == Json::Type::Object) {
                instance.id = fieldText(item, {"id", "instance_id", "instanceId"});
                instance.type = fieldText(item, {"type"});
                instance.binaryName = fieldText(item, {"binary_name", "binaryName", "name"});
                instance.binaryPath = fieldText(item, {"binary_path", "binaryPath", "idb_path", "idbPath"});
                instance.architecture = fieldText(item, {"arch", "architecture"});
                instance.host = fieldText(item, {"host"});
                if (const auto port = jsonAddress(findField(item, {"port"})); port && *port <= 65535) {
                    instance.port = static_cast<uint16_t>(*port);
                }
                if (const Json* pid = item.find("pid"); pid && pid->type == Json::Type::Number) {
                    int64_t value = 0;
                    const auto [end, error] = std::from_chars(pid->text.data(), pid->text.data() + pid->text.size(), value);
                    if (error == std::errc{} && end == pid->text.data() + pid->text.size()) instance.pid = value;
                }
            }
            result.push_back(std::move(instance));
        }
        {
            std::lock_guard lock(mutex_);
            for (const McpInstance& instance : result) {
                if (!instance.id.empty()) endpoints_[instance.id] = Endpoint{instance.host, instance.port};
            }
        }
        return success(std::move(result));
    }

    McpResult<McpBinaryFingerprint> binaryFingerprint(const std::string& instanceId) {
        auto output = callTool("binary_fingerprint", "{\"instance_id\":" + escapeJson(instanceId) + "}", instanceId);
        if (!output) return failure<McpBinaryFingerprint>(std::move(output.error));
        if (!output.value->hasData) {
            return failure<McpBinaryFingerprint>(makeError(
                McpErrorKind::Protocol, "binary_fingerprint returned non-JSON data", output.value->rawJson));
        }

        McpBinaryFingerprint result;
        result.rawJson = output.value->rawJson;
        std::function<bool(const Json&)> visit = [&](const Json& node) {
            if (node.type == Json::Type::Array) {
                for (const Json& item : node.array) if (visit(item)) return true;
                return false;
            }
            if (node.type != Json::Type::Object) return false;
            if (node.find("sha256") || node.find("md5")) {
                result.sha256 = fieldText(node, {"sha256", "SHA256"});
                result.md5 = fieldText(node, {"md5", "MD5"});
                result.architecture = fieldText(node, {"arch", "architecture"});
                if (const auto count = jsonAddress(node.find("function_count"));
                    count && *count <= std::numeric_limits<std::size_t>::max()) {
                    result.functionCount = static_cast<std::size_t>(*count);
                }
                return true;
            }
            for (const auto& [key, value] : node.object) {
                (void)key;
                if ((value.type == Json::Type::Object || value.type == Json::Type::Array) && visit(value)) return true;
            }
            return false;
        };
        if (!visit(output.value->data)) {
            return failure<McpBinaryFingerprint>(makeError(
                McpErrorKind::Protocol, "binary_fingerprint response has no hashes", output.value->rawJson));
        }
        return success(std::move(result));
    }

    McpResult<McpFunctionBounds> functionBounds(const std::string& instanceId, const std::string& addressOrName) {
        const std::string arguments = "{\"instance_id\":" + escapeJson(instanceId) +
            ",\"queries\":[" + escapeJson(addressOrName) + "]}";
        auto output = callTool("lookup_funcs", arguments, instanceId);
        if (!output) return failure<McpFunctionBounds>(std::move(output.error));
        if (!output.value->hasData) {
            return failure<McpFunctionBounds>(makeError(
                McpErrorKind::Protocol, "lookup_funcs returned non-JSON data", output.value->rawJson));
        }

        McpFunctionBounds result;
        result.query = addressOrName;
        std::function<bool(const Json&)> visit = [&](const Json& node) {
            if (node.type == Json::Type::Array) {
                for (const Json& item : node.array) if (visit(item)) return true;
                return false;
            }
            if (node.type != Json::Type::Object) return false;
            if (const Json* function = node.find("fn")) {
                if (function->type == Json::Type::Object && parseBounds(*function, result)) {
                    result.rawJson = stringifyJson(*function);
                    return true;
                }
            }
            if (parseBounds(node, result)) {
                result.rawJson = stringifyJson(node);
                return true;
            }
            for (const auto& [key, value] : node.object) {
                if (key == "fn") continue;
                if ((value.type == Json::Type::Object || value.type == Json::Type::Array) && visit(value)) return true;
            }
            return false;
        };
        if (!visit(output.value->data) || !result.valid()) {
            return failure<McpFunctionBounds>(makeError(
                McpErrorKind::Analysis, "IDA returned no valid bounds for " + addressOrName, output.value->rawJson));
        }
        return success(std::move(result));
    }

    McpResult<McpDecompilation> decompile(const std::string& instanceId, const std::string& address) {
        const std::string arguments = "{\"instance_id\":" + escapeJson(instanceId) +
            ",\"addr\":" + escapeJson(address) + "}";
        auto output = callTool("decompile", arguments, instanceId);
        if (!output) return failure<McpDecompilation>(std::move(output.error));

        McpDecompilation result;
        result.rawJson = output.value->rawJson;
        if (!output.value->hasData) {
            result.code = output.value->text;
        } else if (output.value->data.type == Json::Type::String) {
            result.code = output.value->data.text;
        } else if (output.value->data.type == Json::Type::Object) {
            result.code = fieldText(output.value->data,
                {"decompilation", "pseudocode", "code", "decompiled", "result", "text", "output"});
            if (result.code.empty()) result.code = output.value->text;
            if (result.code.empty()) result.code = result.rawJson;
        } else {
            result.code = result.rawJson;
        }
        return success(std::move(result));
    }

    McpResult<McpBasicBlocksResult> basicBlocks(
        const std::string& instanceId,
        const std::vector<std::string>& addresses,
        std::size_t maxBlocks,
        std::size_t offset) {
        std::string arguments = "{\"instance_id\":" + escapeJson(instanceId) + ",\"addrs\":[";
        for (std::size_t i = 0; i < addresses.size(); ++i) {
            if (i != 0) arguments.push_back(',');
            arguments += escapeJson(addresses[i]);
        }
        arguments += "],\"max_blocks\":" + std::to_string(maxBlocks) +
            ",\"offset\":" + std::to_string(offset) + "}";
        auto output = callTool("basic_blocks", arguments, instanceId);
        if (!output) return failure<McpBasicBlocksResult>(std::move(output.error));
        if (!output.value->hasData) {
            return failure<McpBasicBlocksResult>(makeError(
                McpErrorKind::Protocol, "basic_blocks returned non-JSON data", output.value->rawJson));
        }

        McpBasicBlocksResult result;
        result.rawJson = output.value->rawJson;
        collectBlocks(output.value->data, {}, result.blocks);
        std::function<void(const Json&)> pageInfo = [&](const Json& node) {
            if (node.type == Json::Type::Array) {
                for (const Json& item : node.array) pageInfo(item);
                return;
            }
            if (node.type != Json::Type::Object) return;
            if (const auto total = jsonAddress(findField(node, {"total_blocks", "totalBlocks"}));
                total && *total <= std::numeric_limits<std::size_t>::max()) {
                const auto count = static_cast<std::size_t>(*total);
                if (!result.totalBlocks || count > *result.totalBlocks) result.totalBlocks = count;
            }
            if (const Json* more = node.find("more"); more && more->type == Json::Type::Boolean && more->boolean) {
                result.complete = false;
            }
            if (const Json* cursor = node.find("cursor"); cursor && cursor->type == Json::Type::Object) {
                if (const Json* done = cursor->find("done");
                    done && done->type == Json::Type::Boolean && !done->boolean) {
                    result.complete = false;
                }
            }
            for (const auto& [key, value] : node.object) {
                (void)key;
                if (value.type == Json::Type::Object || value.type == Json::Type::Array) pageInfo(value);
            }
        };
        pageInfo(output.value->data);
        if (result.totalBlocks && result.blocks.size() < *result.totalBlocks) result.complete = false;
        return success(std::move(result));
    }

    McpResult<McpCalleesResult> callees(
        const std::string& instanceId,
        const std::vector<std::string>& addresses,
        std::size_t limit) {
        std::string arguments = "{\"instance_id\":" + escapeJson(instanceId) + ",\"addrs\":[";
        for (std::size_t i = 0; i < addresses.size(); ++i) {
            if (i != 0) arguments.push_back(',');
            arguments += escapeJson(addresses[i]);
        }
        arguments += "],\"limit\":" + std::to_string(limit) + "}";
        auto output = callTool("callees", arguments, instanceId);
        if (!output) return failure<McpCalleesResult>(std::move(output.error));
        if (!output.value->hasData) {
            return failure<McpCalleesResult>(makeError(
                McpErrorKind::Protocol, "callees returned non-JSON data", output.value->rawJson));
        }

        McpCalleesResult result;
        result.rawJson = output.value->rawJson;
        collectCallees(output.value->data, {}, result.callees);
        return success(std::move(result));
    }

    void clearCache() {
        std::lock_guard lock(mutex_);
        cache_.clear();
        cacheOrder_.clear();
    }

private:
    struct Endpoint {
        std::string host;
        std::optional<uint16_t> port;
    };

    struct Session {
        bool initialized = false;
        std::string id;
    };

    struct CacheEntry {
        ToolOutput output;
        std::chrono::steady_clock::time_point expires;
        std::list<std::string>::iterator lru;
    };

    static std::string endpointKey(const McpClientConfig& config) {
        return config.host + ":" + std::to_string(config.port) + config.endpointPath;
    }

    static bool parseBounds(const Json& node, McpFunctionBounds& result) {
        const auto start = jsonAddress(findField(node, {"addr", "start", "start_ea", "ea"}));
        if (!start) return false;
        auto end = jsonAddress(findField(node, {"end", "end_ea"}));
        if (!end) {
            const auto size = jsonAddress(findField(node, {"size", "length"}));
            if (!size || *size == 0 || *start > std::numeric_limits<uint64_t>::max() - *size) return false;
            end = *start + *size;
        }
        if (*end <= *start) return false;
        result.start = *start;
        result.end = *end;
        result.name = fieldText(node, {"name", "function_name", "functionName"});
        return true;
    }

    McpClientConfig configFor(const std::string& instanceId) const {
        McpClientConfig config = config_;
        const auto found = endpoints_.find(instanceId);
        if (found == endpoints_.end()) return config;
        if (!found->second.host.empty()) config.host = found->second.host;
        if (found->second.port) config.port = *found->second.port;
        return config;
    }

    McpResult<Json> request(
        const McpClientConfig& config,
        const std::string& endpoint,
        const std::string& method,
        const std::string& parameters) {
        Session& session = sessions_[endpoint];
        const uint64_t id = nextId_++;
        const std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
            ",\"method\":" + escapeJson(method) + ",\"params\":" + parameters + "}";
        for (std::size_t attempt = 0;; ++attempt) {
            auto response = postHttp(config, body, session.id, session.initialized || !session.id.empty());
            if (response) {
                const auto sessionHeader = response.value->headers.find("mcp-session-id");
                if (sessionHeader != response.value->headers.end() && !sessionHeader->second.empty()) {
                    session.id = sessionHeader->second;
                }
                return decodeRpcResponse(*response.value, id);
            }
            if (!response.error.isTransportError() || attempt >= config.maxTransportRetries) {
                return failure<Json>(std::move(response.error));
            }
            if (config.transportRetryDelay.count() > 0) {
                std::this_thread::sleep_for(config.transportRetryDelay);
            }
        }
    }

    McpError notify(
        const McpClientConfig& config,
        const std::string& endpoint,
        const std::string& method,
        const std::string& parameters) {
        Session& session = sessions_[endpoint];
        const std::string body = "{\"jsonrpc\":\"2.0\",\"method\":" + escapeJson(method) +
            ",\"params\":" + parameters + "}";
        for (std::size_t attempt = 0;; ++attempt) {
            auto response = postHttp(config, body, session.id, session.initialized || !session.id.empty());
            if (response) {
                const auto sessionHeader = response.value->headers.find("mcp-session-id");
                if (sessionHeader != response.value->headers.end() && !sessionHeader->second.empty()) {
                    session.id = sessionHeader->second;
                }
                return {};
            }
            if (!response.error.isTransportError() || attempt >= config.maxTransportRetries) {
                return std::move(response.error);
            }
            if (config.transportRetryDelay.count() > 0) {
                std::this_thread::sleep_for(config.transportRetryDelay);
            }
        }
    }

    McpError ensureInitialized(const McpClientConfig& config, const std::string& endpoint) {
        Session& session = sessions_[endpoint];
        if (!config.autoInitialize || session.initialized) return {};
        auto response = request(
            config,
            endpoint,
            "initialize",
            "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
            "\"clientInfo\":{\"name\":\"il2cpprec\",\"version\":\"1.0\"}}");
        if (!response) return std::move(response.error);
        McpError notificationError = notify(config, endpoint, "notifications/initialized", "{}");
        if (notificationError) return notificationError;
        session.initialized = true;
        return {};
    }

    McpResult<ToolOutput> callTool(
        const std::string& name,
        const std::string& arguments,
        const std::string& instanceId) {
        std::lock_guard lock(mutex_);
        const McpClientConfig config = configFor(instanceId);
        const std::string endpoint = endpointKey(config);
        std::string toolArguments = arguments;
        if (!instanceId.empty() && (config_.directInstance || endpoint != endpointKey(config_))) {
            Json parsed;
            std::string parseError;
            if (!parseJson(arguments, parsed, parseError) || parsed.type != Json::Type::Object) {
                return failure<ToolOutput>(makeError(McpErrorKind::Protocol, "Invalid internal MCP tool arguments"));
            }
            parsed.object.erase(std::remove_if(parsed.object.begin(), parsed.object.end(), [](const auto& field) {
                return field.first == "instance_id";
            }), parsed.object.end());
            toolArguments = stringifyJson(parsed);
        }
        const std::string cacheKey = endpoint + "\n" + name + "\n" + toolArguments;
        const auto now = std::chrono::steady_clock::now();
        if (config.cacheCapacity > 0 && config.cacheTtl.count() > 0) {
            const auto cached = cache_.find(cacheKey);
            if (cached != cache_.end()) {
                if (cached->second.expires > now) {
                    cacheOrder_.splice(cacheOrder_.begin(), cacheOrder_, cached->second.lru);
                    return success(cached->second.output);
                }
                cacheOrder_.erase(cached->second.lru);
                cache_.erase(cached);
            }
        }

        McpError initializationError = ensureInitialized(config, endpoint);
        if (initializationError) return failure<ToolOutput>(std::move(initializationError));
        const std::string parameters = "{\"name\":" + escapeJson(name) +
            ",\"arguments\":" + toolArguments + "}";
        auto response = request(config, endpoint, "tools/call", parameters);
        if (!response) return failure<ToolOutput>(std::move(response.error));
        auto output = decodeToolOutput(*response.value);
        if (!output) return output;
        if (auto error = embeddedAnalysisError(*output.value)) {
            return failure<ToolOutput>(std::move(*error));
        }
        if (config.cacheCapacity > 0 && config.cacheTtl.count() > 0) {
            while (cache_.size() >= config.cacheCapacity) {
                cache_.erase(cacheOrder_.back());
                cacheOrder_.pop_back();
            }
            cacheOrder_.push_front(cacheKey);
            cache_.emplace(cacheKey, CacheEntry{
                *output.value,
                std::chrono::steady_clock::now() + config.cacheTtl,
                cacheOrder_.begin()});
        }
        return output;
    }

    McpClientConfig config_;
    std::mutex mutex_;
    uint64_t nextId_ = 1;
    std::unordered_map<std::string, Endpoint> endpoints_;
    std::unordered_map<std::string, Session> sessions_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::list<std::string> cacheOrder_;
};

McpClient::McpClient(McpClientConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
McpClient::~McpClient() = default;
McpClient::McpClient(McpClient&&) noexcept = default;
McpClient& McpClient::operator=(McpClient&&) noexcept = default;

McpResult<std::vector<McpInstance>> McpClient::listInstances() {
    return impl_->listInstances();
}

McpResult<McpBinaryFingerprint> McpClient::binaryFingerprint(const std::string& instanceId) {
    return impl_->binaryFingerprint(instanceId);
}

McpResult<McpFunctionBounds> McpClient::functionBounds(
    const std::string& instanceId,
    const std::string& addressOrName) {
    return impl_->functionBounds(instanceId, addressOrName);
}

McpResult<McpDecompilation> McpClient::decompile(const std::string& instanceId, const std::string& address) {
    return impl_->decompile(instanceId, address);
}

McpResult<McpBasicBlocksResult> McpClient::basicBlocks(
    const std::string& instanceId,
    const std::vector<std::string>& addresses,
    std::size_t maxBlocks,
    std::size_t offset) {
    return impl_->basicBlocks(instanceId, addresses, maxBlocks, offset);
}

McpResult<McpCalleesResult> McpClient::callees(
    const std::string& instanceId,
    const std::vector<std::string>& addresses,
    std::size_t limit) {
    return impl_->callees(instanceId, addresses, limit);
}

void McpClient::clearCache() {
    impl_->clearCache();
}

} // namespace il2cpprec::ida
