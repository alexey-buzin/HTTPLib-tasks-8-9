#include <iostream>
#include <map>
#include <random>

#include "./../httplib.h"

using std::string;

const char *REGISTER_PAGE = R"REGISTER_PAGE(

<form method="POST">
    <label for="login">Login:</label>
    <input name="login" />

    <label for="password">Password:</label>
    <input name="password" type="password" />

    <input type="submit" />
</form>

)REGISTER_PAGE";

using std::cout;

std::string base64_decode(string s)
{
    static std::map<char, int> mp;
    if (mp.begin() == mp.end()) {

        for (char c = 'A'; c <= 'Z'; ++c) {
            mp[c] = c - 'A';
        }
        for (char c = 'a'; c <= 'z'; ++c) {
            mp[c] = c - 'a' + 26; // NOLINT
        }
        for (char c = '0'; c <= '9'; ++c) {
            mp[c] = c - '0' + 52; // NOLINT
        }
        mp['+'] = 62; // NOLINT
        mp['/'] = 63; // NOLINT
        mp['='] = 0;
    }

    char ns[(s.size() * 3) / 4 + 1];
    ns[(s.size() * 3) / 4] = 0;
    for (int i = 0; i < s.size() / 4; ++i) /*NOLINT*/ {
        int k =
            mp[s[4 * i + 3]] + 64 * ((int)mp[s[4 * i + 2]] + // NOLINT
                                     64 * ((int)mp[s[4 * i + 1]] + // NOLINT
                                           64 * (int)mp[s[4 * i]])); // NOLINT

        ns[3 * i + 2] = (k) % 256; // NOLINT
        ns[3 * i + 1] = k / 256 % 256; // NOLINT
        ns[3 * i] = k / (256 * 256) % 256; // NOLINT
    }

    return ns;
}

//  http://127.0.0.1:8080/login

int main()
{

    srand(1);
    // объявили переменную сервер
    httplib::Server svr;
    std::map<std::string, std::string> salt;
    std::map<std::string, size_t> Hash; // hash(slat+password)

    // Сервер должен запросить имя пользователя и пароль и, если эти данные
    // известны системе, вывести приветствие.
    svr.Get("/login", [&](const httplib::Request &req, httplib::Response &res) {
        for (auto value : req.headers) {
            std::cout << value.first << ": " << value.second << std::endl;
        }
        // Запросить пароль:
        res.status = 401;
        res.set_header("WWW-Authenticate",
                       "Basic realm=\"Enter username\", charset=\"UTF-8\"");

        string b64s = req.get_header_value("Authorization");
        string in = base64_decode(b64s.erase(0, 6));
        string login;
        string password;
        int b = 0;
        for (unsigned i = 0; i < in.size(); ++i) {
            if (in[i] == ':') {
                b = 1;
                continue;
            }
            if (b == 0) {
                login.push_back(in[i]);
            } else {
                password.push_back(in[i]);
            }
        }
        // std::cout<<in<<std::endl;

        std::hash<string> H;
        cout << login << " " << password << "\n";
        // cout << Hash[login] << "\n";
        // cout << H(salt[login] + password) << "\n";
        if (Hash.count(login) != 0) {
            if (H(salt[login] + password) == Hash[login]) {
                string hi =
                    R"( Click <a href="http://127.0.0.1:8080/logout">here to log out</a> )";
                hi = "hi " + login + hi;
                res.set_content(hi, "text/html");
                res.status = 200; // NOLINT
                cout << "logined\n";
                return;
            }
            res.status = 401; // NOLINT
            res.set_content(R"( Incorrect password )", "text/html");
            cout << "Incorrect password \n";
            return;
        }
        res.status = 401; // NOLINT
        cout << "Incorrect username\n";
        res.set_content(
            R"( Incorrect username. Probably, you're not yet registered. 
                Click <a href="http://127.0.0.1:8080/register">here</a> to register)",
            "text/html");
    });

    // Завершить работу пользователя
    svr.Get("/logout", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(R"(<a href="http://127.0.0.1:8080/login">sign in</a>)",
                        "text/html");
    });

    // Вывести форму регистрации
    svr.Get("/register", [](const httplib::Request &, httplib::Response &res) {
        std::cout << "In GET handler" << std::endl;
        res.set_content(REGISTER_PAGE, "text/html");
    });

    // Обработать отправку формы регистрации
    svr.Post("/register",
             [&](const httplib::Request &req, httplib::Response &res) {
                 std::cout << "In POST handler" << std::endl;
                 httplib::Params params;
                 httplib::detail::parse_query_text(req.body, params);
                 for (auto p : params) {
                     std::cout << p.first << " = " << p.second << std::endl;
                 }

                 string login = (*params.find("login")).second;
                 string password = (*params.find("password")).second;
                 if (Hash.count(login) != 0) {
                     res.set_content(R"( This login is already registered! 
            <a href="http://127.0.0.1:8080/login">sign in</a>)",
                                     "text/html");
                     return;
                 }
                 salt[login] = std::to_string(rand());
                 std::hash<string> H;
                 Hash[login] = H(salt[login] + password);
                 res.set_content(R"( You're succesfully registered! 
            <a href="http://127.0.0.1:8080/login">sign in</a>)",
                                 "text/html");
                 cout << salt[login] << "\n";
                 cout << Hash[login] << "\n";
             });

    // запуск сервера:
    // "слушает" (ожидает запросы) на порту с номером 8080
    // адрес 0.0.0.0 — на всех доступных IP-адресах
    svr.listen("0.0.0.0", 8080);
}
