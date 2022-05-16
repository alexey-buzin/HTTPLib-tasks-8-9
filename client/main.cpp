#include "httplib.h"
#include <iostream>

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::cerr << "Input error" << std::endl;
        return 1;
    }

    httplib::Client cli("localhost", 8080);

    std::string login = argv[1];
    std::string password = argv[2];

    std::cerr << "login = " << login << " password = " << password << std::endl;

    httplib::Headers log_headers = {
        {"Authorization",
         "Basic " + httplib::detail::base64_encode(login + ":" + password)}};

    auto res = cli.Get("/login", log_headers);
    if (res->status == 401) {
        httplib::Params reg_params = {{"login", login}, {"password", password}};
        res = cli.Post("/register", reg_params);
    }
    std::cout << res->status << "\n";
    std::cout << res->body << std::endl;
    std::cout << res.error() << std::endl;

    return 0;
}