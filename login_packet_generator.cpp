#define _CRT_SECURE_NO_WARNINGS
#include "login_packet_generator.h"
#include<spdlog/spdlog.h>
#include <openssl/evp.h>
#include"utils/text_parse.h"

static std::string MD5(const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    char md5string[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5string[i * 2], "%02x", (unsigned int)digest[i]);
    }
    md5string[32] = '\0';

    std::string hash = std::string(md5string);
    std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
    return hash;
}
static std::string GenerateKLV(const int protocol, const int hash, const std::string& version, const std::string& rid) {
    constexpr std::array salts = {
        "0b02ea1d8610bab98fbc1d574e5156f3",
        "b414b94c3279a2099bd817ba3a025cfc",
        "bf102589b28a8cc3017cba9aec1306f5",
        "dded9b27d5ce7f8c8ceb1c9ba25f378d"
    };
    return MD5(
        fmt::format("{}{}{}{}{}{}{}{}", salts[0], version, salts[1], hash, salts[2], rid, salts[3], protocol)
    );
}
LoginPacketGenerator::LoginPacketGenerator()
{
	reset();
}

LoginPacketGenerator::~LoginPacketGenerator()
{
}

void LoginPacketGenerator::reset()
{
	randutils::pcg_rng gen{ utils::random::get_generator_local() };
	mac = utils::random::generate_mac(gen);
	mac_hash = utils::proton_hash(fmt::format("{}RT", mac).c_str());
	rid = utils::random::generate_hex(gen, 32, true);
	wk = utils::random::generate_hex(gen, 32, true);
	device_id = utils::random::generate_hex(gen, 16, true);
	device_id_hash = utils::proton_hash(fmt::format("{}RT", device_id).c_str());
    klv = GenerateKLV(189, device_id_hash, "4.23", rid);


}

std::string LoginPacketGenerator::generate()
{
    utils::TextParse var;
    var.add("tankIDName", m_id);
    var.add("tankIDPass", m_pass);
    var.add("requestedName", "WatchSickle");
    var.add("f", "1");
    var.add("protocol", "189");
    var.add("game_version", "4.23");
    var.add("fz", "38905384");
    var.add("lmode", m_lmode);
    var.add("cbits", "1024");
    var.add("player_age", "45");
    var.add("GDPR", "1");
    var.add("category", "_-5100");
    var.add("totalPlaytime", "0");
    var.add("klv", klv);
    var.add("hash2", mac_hash);
    var.add("meta", m_meta);
    var.add("fhash", "-716928004");
    var.add("rid", rid);
    var.add("platformID", "0,1,1");
    var.add("deviceVersion", "0");
    var.add("country", "tr");
    var.add("hash",device_id_hash);
    var.add("mac", mac);
    if (m_subserver)
    {
        var.add("user", m_user);
        var.add("token", m_token);
        var.add("UUIDToken", m_UUIDToken);
        var.add("doorID", m_doorID);
    }
    var.add("wk", wk);
    var.add("zf", "1439718481");
    
    return var.get_all_raw();
}
