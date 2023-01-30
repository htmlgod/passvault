#include <vault.hpp>
#include <boost/program_options.hpp>
#include <vector>

namespace po = boost::program_options;


auto main(int argc, char** argv) -> int {
    std::vector<std::string> args;
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("version,v", "print version string with additional info")
        ("init,i", "create master key file and master password")
        ("examine,e", "print DB info")
        ("change_master_password", "change master password")
        ("put,p", po::value<std::vector<std::string> >(&args)->value_name("service login")->multitoken(), "    save password to db")
        ("take,t", po::value<std::vector<std::string> >(&args)->value_name("service")->multitoken(), "    save password to db")
        ("delete,d", po::value<std::vector<std::string> >(&args)->value_name("service"), "    save password to db")
        //("generate,g", po::value<std::vector<std::string> >(&args)->value_name("[service login]")->multitoken(), "    save password to db")

    ;
    po::variables_map vm;
    
    po::options_description config;
    unsigned int weak_pass_entropy_level;
    std::string db_path;
    std::string master_key_path;
    config.add_options()
        ("db_path", po::value<std::string>(&db_path)->default_value("passvault.db"), "path to DB file")
        ("weak_lvl", po::value<unsigned int>(&weak_pass_entropy_level)->default_value(10), "entropy level for weak password")
        ("master_key_path", po::value<std::string>(&master_key_path)->default_value(".master_key"), "path to master key file")
        // DO AFTER GEN
        // password symbols
        // password len
    ;
    po::variables_map config_vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        PassVaultConfig pv_cfg;
        std::ifstream ifs(CONFIG_FILE_NAME);
        // define default values if cfg file not exists
        if (!ifs) {
            std::cout << "Error while opening config file: " << std::endl;
        }
        else {
            po::store(po::parse_config_file(ifs, config), config_vm);
            notify(config_vm);
        }
        if (config_vm.count("db_path") and config_vm.count("weak_lvl")) {
            pv_cfg.db_path = config_vm["db_path"].as<std::string>();
            pv_cfg.weak_password_entropy_level = config_vm["weak_lvl"].as<unsigned int>();
            pv_cfg.master_key_path = config_vm["master_key_path"].as<std::string>();
        }

        if (vm.size() > 1) {
            throw std::logic_error("Error: Too many args");
        }

        PassVault pv{pv_cfg};
        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }
        else if (vm.count("version")) {
            std::cout << VERSION << "\n";
            return 0;
        }
        else if (vm.count("examine")) {
            //std::cout << VERSION << "\n";
            pv.examine();
            return 0;
        }
        else if (vm.count("put")) {
            if (args.size() != 2) {
                std::cout << desc << "\n";
                return 1;
            }
            pv.save_pass(args[0], args[1]);
        }
        else if (vm.count("take")) {
            if (args.size() != 1) {
                std::cout << desc << "\n";
                return 1;
            }
            pv.get_pass(args[0]);
        }
        else if (vm.count("delete")) {
            if (args.size() != 1) {
                std::cout << desc << "\n";
                return 1;
            }
            pv.del_pass(args[0]);
        }
        else if (vm.count("change_master_password")) {
            pv.change_master_password();
        }
        else if (vm.count("init")) {
            pv.init();
        }
    }
    // more types of exceptions
    catch(std::exception& e) {
        std::cout << e.what() << std::endl;
        std::cout << desc << std::endl;
    }
    return 0;
}
