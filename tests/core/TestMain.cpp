#include "TestSupport.hpp"

#include <exception>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    using namespace il2cpprec::tests;
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument = argv[i];
        if (argument == "--update-goldens") {
            updateGoldens() = true;
        } else {
            std::cerr << "Unknown argument: " << argument << '\n';
            return 2;
        }
    }

    size_t failures = 0;
    for (const auto& test : registry()) {
        try {
            test.function();
            std::cout << "[PASS] " << test.name << '\n';
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << "\n" << exception.what() << '\n';
        } catch (...) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << "\nUnknown exception\n";
        }
    }
    std::cout << registry().size() - failures << "/" << registry().size() << " tests passed\n";
    return failures == 0 ? 0 : 1;
}
