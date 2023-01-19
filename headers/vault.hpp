#pragma once

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

const std::string_view DB_PATH = "test.db";

class PassVault {
public:
    PassVault();
    void save_pass(const std::string& service, const std::string& password);
    std::string get_pass(const std::string& service) const;
    void dump_db();
    void load_db();
    ~PassVault();
private:
    std::map<std::string, std::string> _vault;
    std::string _db_path;
    std::string _config_path;
};
