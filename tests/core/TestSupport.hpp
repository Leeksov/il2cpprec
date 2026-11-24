#pragma once

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <il2cpprec/IR.hpp>

namespace il2cpprec::tests {

class TestFailure : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

using TestFunction = void (*)();

struct TestCase {
    std::string_view name;
    TestFunction function;
};

std::vector<TestCase>& registry();
bool& updateGoldens();

struct TestRegistrar {
    TestRegistrar(std::string_view name, TestFunction function);
};

void fail(std::string message, const char* file, int line);
void check(bool condition, std::string_view expression, const char* file, int line);
void checkEqual(const std::string& actual, const std::string& expected, const char* file, int line);
void checkEqual(uint64_t actual, uint64_t expected, const char* file, int line);
void checkGolden(const std::string& relativePath, const std::string& actual);
std::string serializeFunction(const RecoveredFunction& function);

template<typename Exception = std::exception, typename Function>
void checkThrows(Function&& function, std::string_view messagePart, const char* file, int line) {
    try {
        std::forward<Function>(function)();
    } catch (const Exception& exception) {
        if (messagePart.empty() || std::string_view(exception.what()).find(messagePart) != std::string_view::npos) return;
        fail("Exception message does not contain '" + std::string(messagePart) + "': " + exception.what(), file, line);
    } catch (...) {
        fail("Unexpected exception type", file, line);
    }
    fail("Expected exception was not thrown", file, line);
}

} // namespace il2cpprec::tests

#define IL2CPPREC_TEST_CONCAT_INNER(left, right) left##right
#define IL2CPPREC_TEST_CONCAT(left, right) IL2CPPREC_TEST_CONCAT_INNER(left, right)
#define TEST_CASE(name) \
    static void IL2CPPREC_TEST_CONCAT(testFunction_, __LINE__)(); \
    static const il2cpprec::tests::TestRegistrar IL2CPPREC_TEST_CONCAT(testRegistrar_, __LINE__)( \
        name, &IL2CPPREC_TEST_CONCAT(testFunction_, __LINE__)); \
    static void IL2CPPREC_TEST_CONCAT(testFunction_, __LINE__)()
#define CHECK(expression) \
    ::il2cpprec::tests::check(static_cast<bool>(expression), #expression, __FILE__, __LINE__)
#define CHECK_EQ(actual, expected) \
    ::il2cpprec::tests::checkEqual((actual), (expected), __FILE__, __LINE__)
#define CHECK_THROWS(expression, messagePart) \
    ::il2cpprec::tests::checkThrows<std::runtime_error>([&] { static_cast<void>(expression); }, (messagePart), __FILE__, __LINE__)
