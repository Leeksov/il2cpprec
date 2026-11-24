#include <il2cpprec/Recovery.hpp>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) {
        std::cerr << "usage: RecoverThumb INPUT NAME [ADDRESS]\n";
        return 2;
    }

    std::ifstream stream(argv[1], std::ios::binary);
    if (!stream) {
        std::cerr << "cannot open fixture\n";
        return 2;
    }
    const std::vector<uint8_t> bytes(
        (std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    if (bytes.empty()) {
        std::cerr << "empty fixture\n";
        return 2;
    }

    il2cpprec::FunctionImage image;
    image.architecture = il2cpprec::Architecture::Arm32;
    image.arm32Mode = il2cpprec::Arm32Mode::Thumb;
    image.address = argc == 4 ? std::stoull(argv[3], nullptr, 0) : 0x1000;
    image.code = bytes.data();
    image.size = bytes.size();
    image.name = argv[2];
    std::cout << il2cpprec::Recovery{}.recover(image).toCSharp();
    return 0;
}
