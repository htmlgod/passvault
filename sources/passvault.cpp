#include <vault.hpp>
#include <clip/clip.h>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

auto main(int argc, char** argv) -> int {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("get_pass", po::value<std::string>(), "get password for site/service")
        ("save_pass", po::value<std::string>(), "save password for site/service from clipboard")
        //("check_pass", po::value<std::string>(), "check password strength")
        //("gen_pass_and_add", po::value<std::string>(), "gen password for site/service")
        //("gen_pass", "gen password")
    ;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);    

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 0;
    }
    if (vm.count("get_pass")) {
        std::string password;
        std::cout << "Enter master pass: ";
        std::getline(std::cin, password);
        PassVault pv(password);
        std::cout << "get_pass" << "\n";
        auto service = vm["get_pass"].as<std::string>();
        std::string pass;
        try {
            pass = pv.get_pass(service);
            clip::set_text(pass);
            return 0;
        }
        catch (std::out_of_range& err) {
            std::cout << err.what() << std::endl;
            return 1;
        }
        catch (std::domain_error& err) {
            std::cout << err.what() << std::endl;
            return 1;
        }
    }
    if (vm.count("save_pass")) {
        std::string password;
        std::cout << "Enter master pass: ";
        std::getline(std::cin, password);
        PassVault pv(password);
        std::cout << "save_pass" << "\n";
        auto service = vm["save_pass"].as<std::string>();
        std::string pass_from_cp;
        clip::get_text(pass_from_cp);
        pv.save_pass(service, pass_from_cp);
        return 0;
    }
    // if (vm.count("check_pass")) {
    //     std::cout << "check_pass" << "\n";
    //     return 0;
    // }
    // if (vm.count("gen_pass_and_add")) {
    //     std::cout << "gen_pass_and_add" << "\n";
    //     return 0;
    // }
    // if (vm.count("gen_pass")) {
    //     std::cout << "gen_pass" << "\n";
    //     return 0;
    // }

    return 0;
}
