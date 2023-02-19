#include <vault.hpp>
#include <boost/program_options.hpp>
#include <vector>

namespace po = boost::program_options;


auto main(int argc, char** argv) -> int {
    std::vector<std::string> args;
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h",                 "produce help message")
        ("version,v",              "print version string with additional info")
        ("init,i",                 "create master password and master key")
        ("change_master_password", "change master password")
        ("examine,e",              "print DB info")
        ("put,p", po::value<std::vector<std::string> >(&args)->value_name("<service> <login>")->multitoken(), "    save password and login to db for given service")
        ("take,t", po::value<std::vector<std::string> >(&args)->value_name("<service>")->multitoken(), "    get password from db for given service")
        ("delete,d", po::value<std::vector<std::string> >(&args)->value_name("<service>"), "    delete password from db for given service")
        //("generate,g", po::value<std::vector<std::string> >(&args)->value_name("[service login]")->multitoken(), "    save password to db")

    ;
    po::variables_map vm;
    
    po::options_description config;
    float weak_pass_entropy_level;
    std::string db_path;
    std::string master_key_path;
    config.add_options()
        ("database_filename", po::value<std::string>(&db_path)->default_value("PASSVAULT.db"), "path to DB file")
        ("password_weakness_level", po::value<float>(&weak_pass_entropy_level)->default_value(10.0f), "entropy level for weak password")
        ("master_key_filename", po::value<std::string>(&master_key_path)->default_value(".PV_KEY"), "path to master key file")
        // DO AFTER GEN
        // password symbols
        // password len
    ;
    po::variables_map config_vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        std::ifstream ifs(CONFIG_FILE_NAME);
        if (!ifs) {
            std::cout << "Error while opening config file: " << std::endl;
            return 1;
        }
        else {
            po::store(po::parse_config_file(ifs, config), config_vm);
            notify(config_vm);
        }

        PassVaultConfig pv_cfg {
            config_vm["database_filename"].as<std::string>(),
            config_vm["master_key_filename"].as<std::string>(),
            config_vm["password_weakness_level"].as<float>(),
        };

        if (vm.size() > 1) {
            throw po::error("Error: Too many args");
        }

        if (vm.count("help") or vm.size() == 0) {
            std::cout << desc << "\n";
            return 0;
        } 
        else if (vm.count("init")) {
            PassVault pv{pv_cfg, true};
        }
        else if (vm.count("version")) {
            std::cout << VERSION << "\n";
            return 0;
        }
        else {
            PassVault pv{pv_cfg};
            if (vm.count("examine")) {
                pv.examine();
                return 0;
            } else if (vm.count("put")) {
                if (args.size() != 2) {
                    std::cout << desc << "\n";
                    return 1;
                }
                pv.save_pass(args[0], args[1]);
            } else if (vm.count("take")) {
                if (args.size() != 1) {
                    std::cout << desc << "\n";
                    return 1;
                }
                pv.get_pass(args[0]);
            } else if (vm.count("delete")) {
                if (args.size() != 1) {
                    std::cout << desc << "\n";
                    return 1;
                }
                pv.del_pass(args[0]);
            } else if (vm.count("change_master_password")) {
                pv.change_master_password();
            }
        }
    }
    catch(po::error& e) {
        std::cout << e.what() << std::endl;
        std::cout << desc << std::endl;
    }
    catch(std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    return 0;
}
