#pragma once
#include"utils/random.h"
class LoginPacketGenerator
{
public:
	LoginPacketGenerator();
	~LoginPacketGenerator();

    void reset();
    void set_id( const std::string& id) { m_id = id; }
    void set_pass(const std::string& pass) { m_pass = pass; }
    void set_lmode(const std::string& lmode) { m_lmode = lmode; }
    void set_meta(const std::string& meta) { m_meta = meta; }

    void set_subserver_mode(bool subserver) { m_subserver = subserver; }
    void set_user(const std::string& user) { m_user = user; }
    void set_token(const std::string& token) { m_token = token; }
    void set_UUIDToken(const std::string& UUIDToken) { m_UUIDToken = UUIDToken; }
    void set_doorID(const std::string& doorID) { m_doorID = doorID; }
    std::string generate();

private:
    std::string m_id = "";
    std::string m_pass = "";
    std::string m_lmode = "";
    std::string m_meta = "";

    bool m_subserver = false;
    std::string m_user = "";
    std::string m_token = "";
    std::string m_UUIDToken = "";
    std::string m_doorID = "";


    std::string mac;
    uint32_t mac_hash;
    std::string rid;
    std::string wk;
    std::string device_id;
    uint32_t device_id_hash;
    std::string klv;
};

