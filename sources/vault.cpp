#include <vault.hpp>

PassVault::PassVault() {
    if (std::filesystem::exists(DB_PATH.data())){
        load_db();
    } 
}

void PassVault::load_db() {
    std::ifstream ifs(DB_PATH.data());
    if (!ifs.is_open()) {
        std::cout << "Failed to open DB" << std::endl;
    }
    std::string service;
    std::string pass;
    while (ifs >> service >> pass) {
        _vault.insert({service, pass}); // mb add check for insertion? auto
                                        // ret=vault.insert();
    }
}

void PassVault::dump_db() {
    std::ofstream ofs(DB_PATH.data());
    for (const auto& [service, pass] : _vault) {
        ofs << service << " " << pass << std::endl;
    }
    // ofs.close()
}


void PassVault::save_pass(const std::string& service, const std::string& password) {
    _vault.insert_or_assign(service, password);
}


std::string PassVault::get_pass(const std::string& service) const {
    return _vault.at(service);
}

PassVault::~PassVault() {
    dump_db();
}
