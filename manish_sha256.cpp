#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint> 

class SHA256 {
public:
    SHA256() { reset(); }
    void update(const unsigned char* data, size_t length);
    void update(const char* data, size_t length);
    std::string final();
    static std::string hash(const std::string& data);

private:
    void reset();
    void transform(const unsigned char* chunk);
    static constexpr size_t BlockSize = 64;
    static constexpr size_t HashValues = 8;

    uint32_t h[HashValues];
    unsigned char buffer[BlockSize];
    uint64_t bitLength;
    size_t bufferLength;
};

constexpr uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rightRotate(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

void SHA256::update(const unsigned char* data, size_t length) {
    bitLength += length * 8;
    size_t remaining = length;
    const unsigned char* current = data;

    while (remaining > 0) {
        size_t chunkSize = std::min(remaining, BlockSize - bufferLength);
        std::memcpy(buffer + bufferLength, current, chunkSize);
        bufferLength += chunkSize;
        current += chunkSize;
        remaining -= chunkSize;

        if (bufferLength == BlockSize) {
            transform(buffer);
            bufferLength = 0;
        }
    }
}

void SHA256::update(const char* data, size_t length) {
    update(reinterpret_cast<const unsigned char*>(data), length);
}

std::string SHA256::final() {
    unsigned char padding[BlockSize] = { 0x80 };
    size_t padLength = (bufferLength < 56) ? (56 - bufferLength) : (BlockSize + 56 - bufferLength);
    uint64_t bitLengthBE = __builtin_bswap64(bitLength);

    update(padding, padLength);
    update(reinterpret_cast<unsigned char*>(&bitLengthBE), sizeof(bitLengthBE));

    std::ostringstream result;
    for (size_t i = 0; i < HashValues; ++i) {
        result << std::hex << std::setw(8) << std::setfill('0') << h[i];
    }

    reset();
    return result.str();
}

std::string SHA256::hash(const std::string& data) {
    SHA256 sha;
    sha.update(data.c_str(), data.size());
    return sha.final();
}

void SHA256::reset() {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    bufferLength = 0;
    bitLength = 0;
}

void SHA256::transform(const unsigned char* chunk) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = __builtin_bswap32(*reinterpret_cast<const uint32_t*>(chunk + i * 4));
    }

    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t h0 = h[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h0 + S1 + ch + k[i] + w[i];
        uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h0 = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += h0;
}

int main() {
    try {
        // Using a predefined filename
        std::string filename = "manish.txt";

        // Open the file and read its contents
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }

        // Read file contents into a string
        std::ostringstream ss;
        ss << file.rdbuf();
        std::string fileContents = ss.str();

        // Calculate the hash of the file
        std::string fileHash = SHA256::hash(fileContents);

        // Print the hash
        std::cout << "The SHA-256 hash of the file is: " << fileHash << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
