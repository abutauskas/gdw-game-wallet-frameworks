// EudiGameWallet - a tiny, dependency-free framework for game developers who want
// verifiable credentials (age gates, portable entitlements, guild membership,
// tournament passes) in their games.
//
// It implements the Game Digital Wallet (GDW) token, a simplified, game-friendly
// profile of the selective-disclosure model from the EUDI Wallet Architecture
// and Reference Framework (see ../../../SPEC.md). Same wire format as the C# and
// GDScript frameworks - pick whichever your engine prefers.
//
// Drop this single header into your project and go. No dependencies for the
// default HS256 profile; OpenSSL is optional and only needed for ES256.
//
//   #include <eudi/gamewallet.hpp>
//   using namespace eudi::gw;
//
//   auto issuerKey = Key::hs256("a-shared-secret-at-least-32-bytes-long!");
//   Issuer issuer("https://issuer.example/age-service", issuerKey);
//   auto credential = issuer.issue({
//       .vct = "urn:eudi:game:attestation:age-over-18",
//       .claims = [] { Json j = Json::object(); j["age_over_18"] = Json::boolean(true); return j; }(),
//       .disclosable = {"age_over_18"},
//       .iat = now(),
//       .exp = now() + 86400,
//   });
//
// SPDX-License-Identifier: CC-BY-4.0
#pragma once

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(EUDI_GW_HAS_OPENSSL)
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#endif

namespace eudi::gw {

// ===========================================================================
// Json - a small JSON value with deterministic (canonical) encoding.
// ===========================================================================

class Json {
public:
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json>; // std::map keeps keys sorted

    enum class Type { Null, Bool, Int, String, Array, Object };

    Type type = Type::Null;
    bool boolValue = false;
    int64_t intValue = 0;
    std::string stringValue;
    Array arrayValue;
    Object objectValue;

    Json() = default;

    static Json null() { return Json(); }
    static Json boolean(bool v) { Json j; j.type = Type::Bool; j.boolValue = v; return j; }
    static Json integer(int64_t v) { Json j; j.type = Type::Int; j.intValue = v; return j; }
    static Json string(std::string v) { Json j; j.type = Type::String; j.stringValue = std::move(v); return j; }
    static Json array() { Json j; j.type = Type::Array; return j; }
    static Json object() { Json j; j.type = Type::Object; return j; }

    static Json fromStrings(const std::vector<std::string>& values) {
        Json arr = Json::array();
        for (const std::string& v : values) arr.arrayValue.push_back(Json::string(v));
        return arr;
    }

    bool isNull() const { return type == Type::Null; }
    bool isBool() const { return type == Type::Bool; }
    bool isInt() const { return type == Type::Int; }
    bool isString() const { return type == Type::String; }
    bool isArray() const { return type == Type::Array; }
    bool isObject() const { return type == Type::Object; }

    Json& operator[](const std::string& key) {
        if (type != Type::Object) { type = Type::Object; }
        return objectValue[key];
    }

    const Json* find(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        auto it = objectValue.find(key);
        return it == objectValue.end() ? nullptr : &it->second;
    }

    bool has(const std::string& key) const { return find(key) != nullptr; }

    std::string getString(const std::string& key, const std::string& fallback = "") const {
        const Json* v = find(key);
        return (v && v->isString()) ? v->stringValue : fallback;
    }

    int64_t getInt(const std::string& key, int64_t fallback = 0) const {
        const Json* v = find(key);
        return (v && v->isInt()) ? v->intValue : fallback;
    }

    // -- canonical encoding -------------------------------------------------

    std::string canonical() const {
        std::string out;
        encodeTo(out);
        return out;
    }

    void encodeTo(std::string& out) const {
        switch (type) {
            case Type::Null: out += "null"; break;
            case Type::Bool: out += boolValue ? "true" : "false"; break;
            case Type::Int: out += std::to_string(intValue); break;
            case Type::String: encodeString(stringValue, out); break;
            case Type::Array: {
                out += '[';
                for (size_t i = 0; i < arrayValue.size(); ++i) {
                    if (i) out += ',';
                    arrayValue[i].encodeTo(out);
                }
                out += ']';
                break;
            }
            case Type::Object: {
                out += '{';
                bool first = true;
                for (const auto& kv : objectValue) { // std::map == sorted keys
                    if (!first) out += ',';
                    first = false;
                    encodeString(kv.first, out);
                    out += ':';
                    kv.second.encodeTo(out);
                }
                out += '}';
                break;
            }
        }
    }

    static void encodeString(const std::string& s, std::string& out) {
        static const char* hex = "0123456789abcdef";
        out += '"';
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        out += "\\u00";
                        out += hex[(c >> 4) & 0xF];
                        out += hex[c & 0xF];
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        out += '"';
    }

    // -- parsing ------------------------------------------------------------

    static Json parse(const std::string& text) {
        size_t pos = 0;
        Json value = parseValue(text, pos);
        skipWs(text, pos);
        if (pos != text.size()) throw std::runtime_error("ERR_MALFORMED: trailing data");
        return value;
    }

private:
    static void skipWs(const std::string& t, size_t& p) {
        while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) ++p;
    }

    static Json parseValue(const std::string& t, size_t& p) {
        skipWs(t, p);
        if (p >= t.size()) throw std::runtime_error("ERR_MALFORMED: unexpected end");
        char c = t[p];
        if (c == '{') return parseObject(t, p);
        if (c == '[') return parseArray(t, p);
        if (c == '"') return Json::string(parseString(t, p));
        if (c == 't') { expect(t, p, "true"); return Json::boolean(true); }
        if (c == 'f') { expect(t, p, "false"); return Json::boolean(false); }
        if (c == 'n') { expect(t, p, "null"); return Json::null(); }
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber(t, p);
        throw std::runtime_error("ERR_MALFORMED: unexpected token");
    }

    static void expect(const std::string& t, size_t& p, const char* word) {
        size_t n = std::strlen(word);
        if (t.compare(p, n, word) != 0) throw std::runtime_error("ERR_MALFORMED: bad literal");
        p += n;
    }

    static Json parseObject(const std::string& t, size_t& p) {
        Json obj = Json::object();
        ++p; // {
        skipWs(t, p);
        if (p < t.size() && t[p] == '}') { ++p; return obj; }
        while (true) {
            skipWs(t, p);
            std::string key = parseString(t, p);
            skipWs(t, p);
            if (p >= t.size() || t[p] != ':') throw std::runtime_error("ERR_MALFORMED: expected ':'");
            ++p;
            obj.objectValue[key] = parseValue(t, p);
            skipWs(t, p);
            if (p >= t.size()) throw std::runtime_error("ERR_MALFORMED: unterminated object");
            if (t[p] == ',') { ++p; continue; }
            if (t[p] == '}') { ++p; break; }
            throw std::runtime_error("ERR_MALFORMED: expected ',' or '}'");
        }
        return obj;
    }

    static Json parseArray(const std::string& t, size_t& p) {
        Json arr = Json::array();
        ++p; // [
        skipWs(t, p);
        if (p < t.size() && t[p] == ']') { ++p; return arr; }
        while (true) {
            arr.arrayValue.push_back(parseValue(t, p));
            skipWs(t, p);
            if (p >= t.size()) throw std::runtime_error("ERR_MALFORMED: unterminated array");
            if (t[p] == ',') { ++p; continue; }
            if (t[p] == ']') { ++p; break; }
            throw std::runtime_error("ERR_MALFORMED: expected ',' or ']'");
        }
        return arr;
    }

    static uint32_t parseHex4(const std::string& t, size_t& p) {
        if (p + 4 > t.size()) throw std::runtime_error("ERR_MALFORMED: bad unicode escape");
        uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            char c = t[p++];
            value <<= 4;
            if (c >= '0' && c <= '9') value |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') value |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value |= static_cast<uint32_t>(c - 'A' + 10);
            else throw std::runtime_error("ERR_MALFORMED: bad unicode escape");
        }
        return value;
    }

    static void appendUtf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    static std::string parseString(const std::string& t, size_t& p) {
        if (p >= t.size() || t[p] != '"') throw std::runtime_error("ERR_MALFORMED: expected string");
        ++p;
        std::string out;
        while (true) {
            if (p >= t.size()) throw std::runtime_error("ERR_MALFORMED: unterminated string");
            char c = t[p++];
            if (c == '"') break;
            if (c == '\\') {
                if (p >= t.size()) throw std::runtime_error("ERR_MALFORMED: bad escape");
                char e = t[p++];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        uint32_t cp = parseHex4(t, p);
                        if (cp >= 0xD800 && cp <= 0xDBFF && p + 1 < t.size() && t[p] == '\\' && t[p + 1] == 'u') {
                            p += 2;
                            uint32_t low = parseHex4(t, p);
                            if (low >= 0xDC00 && low <= 0xDFFF) {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            }
                        }
                        appendUtf8(out, cp);
                        break;
                    }
                    default: throw std::runtime_error("ERR_MALFORMED: bad escape");
                }
            } else {
                out += c;
            }
        }
        return out;
    }

    static Json parseNumber(const std::string& t, size_t& p) {
        size_t start = p;
        if (t[p] == '-') ++p;
        while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
        if (p < t.size() && (t[p] == '.' || t[p] == 'e' || t[p] == 'E')) {
            throw std::runtime_error("ERR_MALFORMED: floating point numbers are not allowed");
        }
        std::string digits = t.substr(start, p - start);
        errno = 0;
        long long value = std::strtoll(digits.c_str(), nullptr, 10);
        if (errno != 0) throw std::runtime_error("ERR_MALFORMED: integer out of range");
        return Json::integer(static_cast<int64_t>(value));
    }
};

// ===========================================================================
// Errors
// ===========================================================================

namespace errors {
inline const char* Malformed = "ERR_MALFORMED";
inline const char* SignatureInvalid = "ERR_SIGNATURE_INVALID";
inline const char* IssuerUnknown = "ERR_ISSUER_UNKNOWN";
inline const char* VctNotAllowed = "ERR_VCT_NOT_ALLOWED";
inline const char* Expired = "ERR_EXPIRED";
inline const char* NotYetValid = "ERR_NOT_YET_VALID";
inline const char* DisclosureUnknown = "ERR_DISCLOSURE_UNKNOWN";
inline const char* ClaimMissing = "ERR_CLAIM_MISSING";
inline const char* DuplicateClaim = "ERR_DUPLICATE_CLAIM";
inline const char* KbMissing = "ERR_KB_MISSING";
inline const char* KbInvalid = "ERR_KB_INVALID";
inline const char* AudMismatch = "ERR_AUD_MISMATCH";
inline const char* NonceMismatch = "ERR_NONCE_MISMATCH";
inline const char* SdHashMismatch = "ERR_SD_HASH_MISMATCH";
inline const char* Replay = "ERR_REPLAY";
} // namespace errors

class GwError : public std::runtime_error {
public:
    explicit GwError(const std::string& code) : std::runtime_error(code), code(code) {}
    std::string code;
};

// ===========================================================================
// base64url (RFC 4648 section 5, no padding), SHA-256, HMAC-SHA256
// ===========================================================================

namespace detail {

inline const char* b64Alphabet() {
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
}

inline std::string base64UrlEncode(const std::vector<uint8_t>& data) {
    const char* table = b64Alphabet();
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out += table[(n >> 18) & 63];
        out += table[(n >> 12) & 63];
        out += table[(n >> 6) & 63];
        out += table[n & 63];
        i += 3;
    }
    if (i + 1 == data.size()) {
        uint32_t n = uint32_t(data[i]) << 16;
        out += table[(n >> 18) & 63];
        out += table[(n >> 12) & 63];
    } else if (i + 2 == data.size()) {
        uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out += table[(n >> 18) & 63];
        out += table[(n >> 12) & 63];
        out += table[(n >> 6) & 63];
    }
    return out;
}

inline std::string base64UrlEncode(const std::string& text) {
    return base64UrlEncode(std::vector<uint8_t>(text.begin(), text.end()));
}

inline std::vector<uint8_t> base64UrlDecode(const std::string& text) {
    static int lookup[256];
    static bool init = false;
    if (!init) {
        for (int& v : lookup) v = -1;
        const char* table = b64Alphabet();
        for (int i = 0; i < 64; ++i) lookup[static_cast<unsigned char>(table[i])] = i;
        init = true;
    }
    std::vector<uint8_t> out;
    uint32_t buffer = 0;
    int bits = 0;
    for (char ch : text) {
        if (ch == '=' || ch == '\n' || ch == '\r') continue;
        int v = lookup[static_cast<unsigned char>(ch)];
        if (v < 0) throw GwError("ERR_MALFORMED: invalid base64url");
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        length_ = 0;
        state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85; state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
        state_[4] = 0x510e527f; state_[5] = 0x9b05688c; state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
        bufferSize_ = 0;
    }

    void update(const uint8_t* data, size_t size) {
        length_ += size;
        while (size > 0) {
            size_t take = std::min<size_t>(size, 64 - bufferSize_);
            std::memcpy(buffer_ + bufferSize_, data, take);
            bufferSize_ += take;
            data += take;
            size -= take;
            if (bufferSize_ == 64) { transform(buffer_); bufferSize_ = 0; }
        }
    }

    void update(const std::string& text) {
        update(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }

    std::vector<uint8_t> finish() {
        uint64_t bitLength = length_ * 8;
        uint8_t padding = 0x80;
        update(&padding, 1);
        uint8_t zero = 0x00;
        while (bufferSize_ != 56) update(&zero, 1);
        uint8_t lengthBytes[8];
        for (int i = 0; i < 8; ++i) lengthBytes[i] = static_cast<uint8_t>(bitLength >> (56 - i * 8));
        update(lengthBytes, 8);
        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>(state_[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
            digest[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
        reset();
        return digest;
    }

    static std::vector<uint8_t> hash(const std::string& text) {
        Sha256 h;
        h.update(text);
        return h.finish();
    }

private:
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void transform(const uint8_t* block) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    uint32_t state_[8];
    uint64_t length_;
    uint8_t buffer_[64];
    size_t bufferSize_;
};

inline std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::string& message) {
    std::vector<uint8_t> k = key;
    if (k.size() > 64) k = Sha256::hash(std::string(k.begin(), k.end()));
    k.resize(64, 0x00);
    std::vector<uint8_t> inner(64), outer(64);
    for (int i = 0; i < 64; ++i) {
        inner[i] = k[i] ^ 0x36;
        outer[i] = k[i] ^ 0x5c;
    }
    Sha256 h1;
    h1.update(inner.data(), inner.size());
    h1.update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    std::vector<uint8_t> innerHash = h1.finish();
    Sha256 h2;
    h2.update(outer.data(), outer.size());
    h2.update(innerHash.data(), innerHash.size());
    return h2.finish();
}

inline std::string randomBytes(size_t count) {
    static std::random_device device;
    std::string out(count, '\0');
    for (size_t i = 0; i < count; ++i) out[i] = static_cast<char>(device() & 0xFF);
    return out;
}

inline std::string randomBase64Url(size_t bytes) {
    std::string raw = randomBytes(bytes);
    return base64UrlEncode(std::vector<uint8_t>(raw.begin(), raw.end()));
}

inline bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

inline bool isValidClaimName(const std::string& name) {
    if (name.empty() || name.size() > 64 || name[0] == '_') return false;
    for (char c : name) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')) return false;
    }
    return true;
}

inline bool isReserved(const std::string& name) {
    return name == "_sd" || name == "_sd_alg" || name == "cnf" || name == "iss" ||
           name == "sub" || name == "iat" || name == "exp" || name == "vct";
}

inline std::vector<std::string> splitTilde(const std::string& text) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : text) {
        if (c == '~') { parts.push_back(current); current.clear(); }
        else current += c;
    }
    parts.push_back(current);
    return parts;
}

inline std::vector<std::string> splitDot(const std::string& text) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : text) {
        if (c == '.') { parts.push_back(current); current.clear(); }
        else current += c;
    }
    parts.push_back(current);
    return parts;
}

inline std::string jsonSegment(const Json& value) {
    return base64UrlEncode(value.canonical());
}

inline Json parseSegment(const std::string& segment) {
    std::vector<uint8_t> bytes = base64UrlDecode(segment);
    return Json::parse(std::string(bytes.begin(), bytes.end()));
}

inline std::string sha256Base64(const std::string& text) {
    return base64UrlEncode(Sha256::hash(text));
}

inline std::string disclosureDigest(const std::string& segment) {
    return sha256Base64(segment);
}

inline std::string sdHash(const std::string& base) {
    return sha256Base64(base);
}

inline std::string makeDisclosure(const std::string& saltB64, const std::string& name, const Json& value) {
    if (!isValidClaimName(name)) throw GwError("ERR_MALFORMED: bad claim name");
    if (base64UrlDecode(saltB64).size() < 16) throw GwError("ERR_MALFORMED: salt too short");
    Json arr = Json::array();
    arr.arrayValue.push_back(Json::string(saltB64));
    arr.arrayValue.push_back(Json::string(name));
    arr.arrayValue.push_back(value);
    return base64UrlEncode(arr.canonical());
}

struct ParsedDisclosure {
    std::string salt;
    std::string name;
    Json value;
};

inline ParsedDisclosure parseDisclosure(const std::string& segment) {
    std::vector<uint8_t> bytes = base64UrlDecode(segment);
    Json arr = Json::parse(std::string(bytes.begin(), bytes.end()));
    if (!arr.isArray() || arr.arrayValue.size() != 3 ||
        !arr.arrayValue[0].isString() || !arr.arrayValue[1].isString()) {
        throw GwError("ERR_MALFORMED: bad disclosure");
    }
    ParsedDisclosure parsed;
    parsed.salt = arr.arrayValue[0].stringValue;
    parsed.name = arr.arrayValue[1].stringValue;
    parsed.value = arr.arrayValue[2];
    if (!isValidClaimName(parsed.name)) throw GwError("ERR_MALFORMED: bad claim name");
    if (base64UrlDecode(parsed.salt).size() < 16) throw GwError("ERR_MALFORMED: salt too short");
    return parsed;
}

struct Token {
    Json header;
    Json payload;
    std::string signingInput;
    std::string signature;
};

inline Token decodeToken(const std::string& token) {
    std::vector<std::string> parts = splitDot(token);
    if (parts.size() != 3) throw GwError("ERR_MALFORMED: token must have 3 parts");
    Token t;
    t.header = parseSegment(parts[0]);
    t.payload = parseSegment(parts[1]);
    t.signingInput = parts[0] + "." + parts[1];
    t.signature = parts[2];
    return t;
}

struct ParsedCredential {
    std::string jwt;
    Json payload;
    std::vector<std::string> disclosures;
};

inline ParsedCredential parseCredential(const std::string& credential) {
    if (credential.empty() || credential.back() != '~') throw GwError("ERR_MALFORMED: bad credential");
    std::vector<std::string> parts = splitTilde(credential);
    ParsedCredential parsed;
    parsed.jwt = parts.empty() ? std::string() : parts[0];
    for (size_t i = 1; i + 1 < parts.size(); ++i) {
        if (!parts[i].empty()) parsed.disclosures.push_back(parts[i]);
    }
    Token token = decodeToken(parsed.jwt);
    if (token.header.getString("typ") != "gw+jwt") throw GwError("ERR_MALFORMED: bad credential header");
    parsed.payload = token.payload;
    return parsed;
}

} // namespace detail

// ===========================================================================
// Keys and signers
// ===========================================================================

struct Key {
    std::string alg = "HS256";
    std::string k;       // base64url raw HS256 key material
    std::string crv;     // ES256: "P-256"
    std::string x, y, d; // ES256: base64url coordinates / private scalar

    static Key hs256(const std::string& rawSecret) {
        Key key;
        key.alg = "HS256";
        key.k = detail::base64UrlEncode(rawSecret);
        return key;
    }

    Json toJson() const {
        Json j = Json::object();
        j["alg"] = Json::string(alg);
        if (!k.empty()) j["k"] = Json::string(k);
        if (!crv.empty()) j["crv"] = Json::string(crv);
        if (!x.empty()) j["x"] = Json::string(x);
        if (!y.empty()) j["y"] = Json::string(y);
        if (!d.empty()) j["d"] = Json::string(d);
        return j;
    }

    static Key fromJson(const Json& j) {
        Key key;
        key.alg = j.getString("alg", "HS256");
        key.k = j.getString("k");
        key.crv = j.getString("crv");
        key.x = j.getString("x");
        key.y = j.getString("y");
        key.d = j.getString("d");
        return key;
    }
};

// A Signer turns bytes into a signature. Swap Hs256Signer for a real
// asymmetric signer (EcdsaP256Signer below) before shipping.
class Signer {
public:
    virtual ~Signer() = default;
    virtual std::string alg() const = 0;
    virtual std::string sign(const std::string& signingInput) const = 0;
};

class Hs256Signer : public Signer {
public:
    explicit Hs256Signer(const Key& key, const std::string& alg = "HS256") : key_(key), alg_(alg) {}

    std::string alg() const override { return alg_; }

    std::string sign(const std::string& signingInput) const override {
        std::vector<uint8_t> raw = detail::base64UrlDecode(key_.k);
        if (raw.size() < 32) throw std::runtime_error("HS256 key must be at least 32 bytes");
        return detail::base64UrlEncode(detail::hmacSha256(raw, signingInput));
    }

    bool verify(const std::string& signingInput, const std::string& signature) const {
        return detail::constantTimeEquals(sign(signingInput), signature);
    }

private:
    Key key_;
    std::string alg_;
};

#if defined(EUDI_GW_HAS_OPENSSL)
// Real asymmetric signatures (ECDSA P-256 + SHA-256), raw R||S format per
// RFC 7518. Requires OpenSSL; link with -lcrypto and define EUDI_GW_HAS_OPENSSL
// (CMake does this automatically when OpenSSL is found).
class EcdsaP256Signer : public Signer {
public:
    explicit EcdsaP256Signer(const Key& key) : key_(key) {
        if (key_.alg != "ES256") throw std::runtime_error("EcdsaP256Signer requires an ES256 key");
    }

    std::string alg() const override { return "ES256"; }

    std::string sign(const std::string& signingInput) const override {
        std::vector<uint8_t> der = signDer(signingInput);
        return detail::base64UrlEncode(derToRaw(der));
    }

    bool verify(const std::string& signingInput, const std::string& signature) const {
        std::vector<uint8_t> raw = detail::base64UrlDecode(signature);
        if (raw.size() != 64) return false;
        std::vector<uint8_t> der = rawToDer(raw);
        EVP_PKEY* pkey = publicKey();
        if (!pkey) return false;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        bool ok = false;
        if (ctx && EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
            ok = EVP_DigestVerify(ctx, der.data(), der.size(),
                                  reinterpret_cast<const unsigned char*>(signingInput.data()),
                                  signingInput.size()) == 1;
        }
        if (ctx) EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ok;
    }

private:
    std::vector<uint8_t> signDer(const std::string& message) const {
        EVP_PKEY* pkey = privateKey();
        if (!pkey) throw std::runtime_error("ES256 private key unavailable");
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> signature;
        if (ctx && EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
            size_t len = 0;
            if (EVP_DigestSign(ctx, nullptr, &len,
                               reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1) {
                signature.resize(len);
                if (EVP_DigestSign(ctx, signature.data(), &len,
                                   reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 1) {
                    signature.clear();
                } else {
                    signature.resize(len);
                }
            }
        }
        if (ctx) EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        if (signature.empty()) throw std::runtime_error("ES256 signing failed");
        return signature;
    }

    static std::vector<uint8_t> derToRaw(const std::vector<uint8_t>& der) {
        const unsigned char* p = der.data();
        ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
        if (!sig) throw std::runtime_error("ES256: cannot parse DER signature");
        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(sig, &r, &s);
        std::vector<uint8_t> raw(64, 0);
        BN_bn2binpad(r, raw.data(), 32);
        BN_bn2binpad(s, raw.data() + 32, 32);
        ECDSA_SIG_free(sig);
        return raw;
    }

    static std::vector<uint8_t> rawToDer(const std::vector<uint8_t>& raw) {
        BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
        BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
        ECDSA_SIG* sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(sig, r, s);
        unsigned char* out = nullptr;
        int len = i2d_ECDSA_SIG(sig, &out);
        std::vector<uint8_t> der(out, out + len);
        OPENSSL_free(out);
        ECDSA_SIG_free(sig);
        return der;
    }

    EVP_PKEY* privateKey() const {
        if (key_.d.empty()) return nullptr;
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec) return nullptr;
        std::vector<uint8_t> d = detail::base64UrlDecode(key_.d);
        BIGNUM* priv = BN_bin2bn(d.data(), static_cast<int>(d.size()), nullptr);
        EC_KEY_set_private_key(ec, priv);
        BN_free(priv);
        EC_POINT* pub = EC_POINT_new(EC_KEY_get0_group(ec));
        EC_POINT_mul(EC_KEY_get0_group(ec), pub, EC_KEY_get0_private_key(ec), nullptr, nullptr, nullptr);
        EC_KEY_set_public_key(ec, pub);
        EC_POINT_free(pub);
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec);
        return pkey;
    }

    EVP_PKEY* publicKey() const {
        if (key_.x.empty() || key_.y.empty()) return nullptr;
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec) return nullptr;
        std::vector<uint8_t> x = detail::base64UrlDecode(key_.x);
        std::vector<uint8_t> y = detail::base64UrlDecode(key_.y);
        BIGNUM* bx = BN_bin2bn(x.data(), static_cast<int>(x.size()), nullptr);
        BIGNUM* by = BN_bin2bn(y.data(), static_cast<int>(y.size()), nullptr);
        EC_POINT* pub = EC_POINT_new(EC_KEY_get0_group(ec));
        EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec), pub, bx, by, nullptr);
        EC_KEY_set_public_key(ec, pub);
        BN_free(bx);
        BN_free(by);
        EC_POINT_free(pub);
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec);
        return pkey;
    }

    Key key_;
};
#else
// Placeholder so user code can reference the name; throws if used without OpenSSL.
class EcdsaP256Signer : public Signer {
public:
    explicit EcdsaP256Signer(const Key&) {
        throw std::runtime_error("ES256 requires OpenSSL: rebuild with EUDI_GW_HAS_OPENSSL");
    }
    std::string alg() const override { return "ES256"; }
    std::string sign(const std::string&) const override { throw std::runtime_error("unavailable"); }
    bool verify(const std::string&, const std::string&) const { return false; }
};
#endif

inline std::shared_ptr<Signer> makeSigner(const Key& key) {
    if (key.alg == "HS256") return std::make_shared<Hs256Signer>(key);
    if (key.alg == "ES256") return std::make_shared<EcdsaP256Signer>(key);
    throw std::runtime_error("unsupported key algorithm: " + key.alg);
}

inline int64_t now() { return static_cast<int64_t>(std::time(nullptr)); }

// ===========================================================================
// Issuer
// ===========================================================================

struct IssueOptions {
    std::string vct;
    Json claims = Json::object();
    std::vector<std::string> disclosable;
    int64_t iat = 0;
    int64_t exp = 0;
    std::string sub;
    Key holderKey;
    std::vector<std::string> salts; // optional, for deterministic tests
    Json extraPayload = Json::object();
};

class Issuer {
public:
    Issuer(std::string iss, Key issuerKey)
        : iss_(std::move(iss)), signer_(makeSigner(issuerKey)) {}

    const std::string& id() const { return iss_; }

    std::string issue(const IssueOptions& options) const {
        if (options.iat == 0 || options.exp == 0) throw GwError(errors::Malformed);
        if (options.vct.empty()) throw GwError(errors::Malformed);

        for (const std::string& name : options.disclosable) {
            if (!options.claims.has(name)) throw GwError(errors::Malformed);
            if (detail::isReserved(name)) throw GwError(errors::Malformed);
        }

        std::vector<std::string> disclosures;
        Json sd = Json::array();
        for (size_t i = 0; i < options.disclosable.size(); ++i) {
            const std::string& name = options.disclosable[i];
            std::string salt = i < options.salts.size() ? options.salts[i] : detail::randomBase64Url(16);
            std::string segment = detail::makeDisclosure(salt, name, *options.claims.find(name));
            disclosures.push_back(segment);
            sd.arrayValue.push_back(Json::string(detail::disclosureDigest(segment)));
        }

        Json payload = Json::object();
        payload["_sd"] = sd;
        payload["_sd_alg"] = Json::string("sha-256");
        payload["cnf"] = options.holderKey.toJson();
        payload["exp"] = Json::integer(options.exp);
        payload["iat"] = Json::integer(options.iat);
        payload["iss"] = Json::string(iss_);
        payload["vct"] = Json::string(options.vct);
        if (!options.sub.empty()) payload["sub"] = Json::string(options.sub);
        for (const auto& kv : options.claims.objectValue) {
            if (std::find(options.disclosable.begin(), options.disclosable.end(), kv.first) != options.disclosable.end()) continue;
            if (payload.has(kv.first)) throw GwError(errors::Malformed);
            payload[kv.first] = kv.second;
        }
        for (const auto& kv : options.extraPayload.objectValue) {
            if (payload.has(kv.first)) throw GwError(errors::Malformed);
            payload[kv.first] = kv.second;
        }

        Json header = Json::object();
        header["alg"] = Json::string(signer_->alg());
        header["typ"] = Json::string("gw+jwt");
        std::string signingInput = detail::jsonSegment(header) + "." + detail::jsonSegment(payload);
        std::string jwt = signingInput + "." + signer_->sign(signingInput);

        std::string credential = jwt;
        for (const std::string& d : disclosures) credential += "~" + d;
        credential += "~";
        return credential;
    }

private:
    std::string iss_;
    std::shared_ptr<Signer> signer_;
};

// ===========================================================================
// Wallet (holder)
// ===========================================================================

class Wallet {
public:
    explicit Wallet(Key holderKey) : key_(std::move(holderKey)), signer_(makeSigner(key_)) {}

    void store(const std::string& credential) {
        detail::parseCredential(credential); // validate before storing
        credentials_.push_back(credential);
    }

    const std::vector<std::string>& credentials() const { return credentials_; }

    std::vector<std::string> claimsOf(const std::string& credential) const {
        detail::ParsedCredential parsed = detail::parseCredential(credential);
        std::vector<std::string> names;
        for (const auto& kv : parsed.payload.objectValue) {
            if (!detail::isReserved(kv.first)) names.push_back(kv.first);
        }
        for (const std::string& segment : parsed.disclosures) {
            names.push_back(detail::parseDisclosure(segment).name);
        }
        return names;
    }

    std::string present(const std::string& credential,
                        const std::vector<std::string>& requestedClaims,
                        const std::string& aud,
                        const std::string& nonce,
                        int64_t issuedAt) const {
        detail::ParsedCredential parsed = detail::parseCredential(credential);
        std::map<std::string, std::string> byDigest;
        for (const std::string& segment : parsed.disclosures) {
            byDigest[detail::disclosureDigest(segment)] = segment;
        }
        std::vector<std::string> selected;
        const Json* sd = parsed.payload.find("_sd");
        for (const std::string& name : requestedClaims) {
            if (!detail::isReserved(name) && parsed.payload.has(name)) continue; // plaintext claim
            bool found = false;
            if (sd && sd->isArray()) {
                for (const Json& digestJson : sd->arrayValue) {
                    if (!digestJson.isString()) continue;
                    auto it = byDigest.find(digestJson.stringValue);
                    if (it == byDigest.end()) continue;
                    if (detail::parseDisclosure(it->second).name == name) {
                        selected.push_back(it->second);
                        found = true;
                        break;
                    }
                }
            }
            if (!found) throw GwError(errors::ClaimMissing);
        }

        std::string base = parsed.jwt;
        for (const std::string& segment : selected) base += "~" + segment;

        const Json* cnf = parsed.payload.find("cnf");
        if (cnf && cnf->isObject()) {
            Key cnfKey = Key::fromJson(*cnf);
            if (cnfKey.k != key_.k && cnfKey.d != key_.d) throw GwError(errors::KbInvalid);
        }

        Json kb = Json::object();
        kb["aud"] = Json::string(aud);
        kb["iat"] = Json::integer(issuedAt);
        kb["nonce"] = Json::string(nonce);
        kb["sd_hash"] = Json::string(detail::sdHash(base));

        Json header = Json::object();
        header["alg"] = Json::string(signer_->alg());
        header["typ"] = Json::string("kb+jwt");
        std::string signingInput = detail::jsonSegment(header) + "." + detail::jsonSegment(kb);
        std::string kbJwt = signingInput + "." + signer_->sign(signingInput);
        return base + "~" + kbJwt;
    }

private:
    Key key_;
    std::shared_ptr<Signer> signer_;
    std::vector<std::string> credentials_;
};

// ===========================================================================
// Verifier (relying party)
// ===========================================================================

struct VerifyResult {
    bool ok = false;
    Json claims = Json::object();
    std::vector<std::string> errors;
};

class Verifier {
public:
    explicit Verifier(std::string aud) : aud_(std::move(aud)) {}

    void trust(const std::string& iss, const Key& key) { trust_[iss] = key; }
    void requireKeyBinding(bool value) { requireKeyBinding_ = value; }
    void setClockSkew(int64_t seconds) { clockSkew_ = seconds; }
    void markNonceUsed(const std::string& iss, const std::string& nonce) { usedNonces_.insert(iss + "|" + nonce); }

    Json createRequest(const std::vector<std::string>& vct,
                       const std::vector<std::string>& claims,
                       const std::string& purpose = "",
                       int64_t ttlSeconds = 60) {
        Json request = Json::object();
        request["aud"] = Json::string(aud_);
        request["nonce"] = Json::string(detail::randomBase64Url(16));
        request["vct"] = Json::fromStrings(vct);
        request["claims"] = Json::fromStrings(claims);
        if (!purpose.empty()) request["purpose"] = Json::string(purpose);
        request["expires_at"] = Json::integer(now() + ttlSeconds);
        return request;
    }

    VerifyResult verify(const Json& request, const std::string& presentation, int64_t currentTime) {
        VerifyResult result;
        try {
            result.claims = verifyInternal(request, presentation, currentTime);
            result.ok = true;
        } catch (const GwError& err) {
            result.errors.push_back(err.code);
        } catch (const std::exception&) {
            result.errors.push_back(errors::Malformed);
        }
        return result;
    }

private:
    Json verifyInternal(const Json& request, const std::string& presentation, int64_t currentTime) {
        std::vector<std::string> parts = detail::splitTilde(presentation);
        if (parts.size() < 2) throw GwError(errors::Malformed);

        std::string jwt = parts[0];
        bool hasKb = !parts.back().empty();
        std::string kbJwt = hasKb ? parts.back() : "";
        std::vector<std::string> disclosures(parts.begin() + 1, hasKb ? parts.end() - 1 : parts.end());
        disclosures.erase(std::remove(disclosures.begin(), disclosures.end(), std::string()), disclosures.end());

        detail::Token token = detail::decodeToken(jwt);
        if (token.header.getString("typ") != "gw+jwt") throw GwError(errors::Malformed);

        std::string iss = token.payload.getString("iss");
        if (iss.empty()) throw GwError(errors::Malformed);
        auto trusted = trust_.find(iss);
        if (trusted == trust_.end()) throw GwError(errors::IssuerUnknown);
        if (token.header.getString("alg") != trusted->second.alg) throw GwError(errors::Malformed);

        if (trusted->second.alg == "HS256") {
            Hs256Signer signer(trusted->second);
            if (!signer.verify(token.signingInput, token.signature)) throw GwError(errors::SignatureInvalid);
        } else {
#if defined(EUDI_GW_HAS_OPENSSL)
            EcdsaP256Signer signer(trusted->second);
            if (!signer.verify(token.signingInput, token.signature)) throw GwError(errors::SignatureInvalid);
#else
            throw GwError(errors::SignatureInvalid);
#endif
        }

        int64_t exp = token.payload.getInt("exp", -1);
        int64_t iat = token.payload.getInt("iat", -1);
        if (exp < 0 || iat < 0) throw GwError(errors::Malformed);
        if (currentTime > exp + clockSkew_) throw GwError(errors::Expired);
        if (currentTime < iat - clockSkew_) throw GwError(errors::NotYetValid);

        std::string vct = token.payload.getString("vct");
        bool vctAllowed = false;
        const Json* allowedVct = request.find("vct");
        if (allowedVct && allowedVct->isArray()) {
            for (const Json& candidate : allowedVct->arrayValue) {
                if (candidate.isString() && candidate.stringValue == vct) vctAllowed = true;
            }
        }
        if (!vctAllowed) throw GwError(errors::VctNotAllowed);

        if (token.payload.getString("_sd_alg") != "sha-256") throw GwError(errors::Malformed);
        const Json* sd = token.payload.find("_sd");
        if (!sd || !sd->isArray()) throw GwError(errors::Malformed);

        Json claims = Json::object();
        for (const auto& kv : token.payload.objectValue) {
            if (!detail::isReserved(kv.first)) claims[kv.first] = kv.second;
        }

        std::vector<std::string> covered;
        for (const Json& digest : sd->arrayValue) {
            if (digest.isString()) covered.push_back(digest.stringValue);
        }

        std::vector<std::string> seen;
        for (const std::string& segment : disclosures) {
            std::string digest = detail::disclosureDigest(segment);
            if (std::find(covered.begin(), covered.end(), digest) == covered.end()) throw GwError(errors::DisclosureUnknown);
            if (std::find(seen.begin(), seen.end(), digest) != seen.end()) throw GwError(errors::DisclosureUnknown);
            seen.push_back(digest);
            detail::ParsedDisclosure parsed = detail::parseDisclosure(segment);
            if (claims.has(parsed.name)) throw GwError(errors::DuplicateClaim);
            claims[parsed.name] = parsed.value;
        }

        const Json* requiredClaims = request.find("claims");
        if (requiredClaims && requiredClaims->isArray()) {
            for (const Json& required : requiredClaims->arrayValue) {
                if (required.isString() && !claims.has(required.stringValue)) throw GwError(errors::ClaimMissing);
            }
        }

        if (requireKeyBinding_) {
            if (!hasKb) throw GwError(errors::KbMissing);
            detail::Token kbToken = detail::decodeToken(kbJwt);
            if (kbToken.header.getString("typ") != "kb+jwt") throw GwError(errors::KbInvalid);
            const Json* cnf = token.payload.find("cnf");
            if (!cnf || !cnf->isObject()) throw GwError(errors::KbInvalid);
            Key cnfKey = Key::fromJson(*cnf);
            if (cnfKey.alg != kbToken.header.getString("alg")) throw GwError(errors::KbInvalid);
            if (cnfKey.alg == "HS256") {
                Hs256Signer signer(cnfKey);
                if (!signer.verify(kbToken.signingInput, kbToken.signature)) throw GwError(errors::KbInvalid);
            } else {
#if defined(EUDI_GW_HAS_OPENSSL)
                EcdsaP256Signer signer(cnfKey);
                if (!signer.verify(kbToken.signingInput, kbToken.signature)) throw GwError(errors::KbInvalid);
#else
                throw GwError(errors::KbInvalid);
#endif
            }

            std::string base = jwt;
            for (const std::string& segment : disclosures) base += "~" + segment;
            if (kbToken.payload.getString("sd_hash") != detail::sdHash(base)) throw GwError(errors::SdHashMismatch);
            if (kbToken.payload.getString("aud") != request.getString("aud")) throw GwError(errors::AudMismatch);
            if (kbToken.payload.getString("nonce") != request.getString("nonce")) throw GwError(errors::NonceMismatch);
            int64_t kbIat = kbToken.payload.getInt("iat", -1);
            if (kbIat < 0 || std::llabs(currentTime - kbIat) > clockSkew_) throw GwError(errors::KbInvalid);

            std::string nonceKey = iss + "|" + request.getString("nonce");
            if (usedNonces_.count(nonceKey)) throw GwError(errors::Replay);
            usedNonces_.insert(nonceKey);
        }

        return claims;
    }

    std::string aud_;
    std::map<std::string, Key> trust_;
    std::set<std::string> usedNonces_;
    bool requireKeyBinding_ = true;
    int64_t clockSkew_ = 300;
};

} // namespace eudi::gw
