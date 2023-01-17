#include <iostream>
#include <string>

#include <clip.h>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

auto main(int argc, char** argv) -> int {
    po::options_description desc("Allowed options");

    desc.add_options()
        ("help", "produce help message")
        ("get_pass", po::value<std::string>(), "get password for site/service")
        ("check_pass", po::value<std::string>(), "check password strength")
        ("gen_pass_and_add", po::value<std::string>(), "gen password for site/service")
        ("gen_pass", "gen password")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);    

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 0;
    }
    if (vm.count("get_pass")) {
        std::cout << "get_pass" << "\n";
        clip::set_text("ABOBA");
        return 0;
    }
    if (vm.count("check_pass")) {
        std::cout << "check_pass" << "\n";
        return 0;
    }
    if (vm.count("gen_pass_and_add")) {
        std::cout << "gen_pass_and_add" << "\n";
        return 0;
    }
    if (vm.count("gen_pass")) {
        std::cout << "gen_pass" << "\n";
        return 0;
    }

    return 0;
}
