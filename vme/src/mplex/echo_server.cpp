#include "ClientConnector.h"
#include "mplex.h"
#include "slog.h"
#include "textutil.h"

#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

namespace mplex
{

typedef websocketpp::server<websocketpp::config::asio> wsserver;

typedef wsserver::message_ptr message_ptr;

std::map<websocketpp::connection_hdl, cConHook *, std::owner_less<websocketpp::connection_hdl>> g_cMapHandler;

void remove_gmap(cConHook *con)
{
    std::map<websocketpp::connection_hdl, cConHook *, std::owner_less<websocketpp::connection_hdl>>::iterator it;

    for (it = g_cMapHandler.begin(); it != g_cMapHandler.end(); it++)
    {
        if (it->second == con)
        {
            slog(LOG_OFF, 0, "remove_gmap located con class, removed.");
            g_cMapHandler.erase(it);
            return;
        }
    }
}

void on_close(websocketpp::connection_hdl hdl)
{
    cConHook *con = nullptr;
    std::map<websocketpp::connection_hdl, cConHook *, std::owner_less<websocketpp::connection_hdl>>::iterator it;

    it = g_cMapHandler.find(hdl);

    if (it != g_cMapHandler.end())
    {
        con = it->second;
        g_cMapHandler.erase(it);
        con->Close(TRUE);
    }
    else
    {
        slog(LOG_OFF, 0, "on_close unable to locate class.");
    }
}

int ws_send_message(wsserver *s, websocketpp::connection_hdl hdl, const char *txt)
{
    std::string mystr(txt);

    str_correct_utf8(mystr);

    try
    {
        s->send(hdl, mystr.c_str(), mystr.length(), websocketpp::frame::opcode::text);
        return 1;
    }
    catch (websocketpp::exception const &e)
    {
        slog(LOG_OFF, 0, "Send failed: %s", e.what());
        return 0;
    }
}

void on_message(wsserver *s, websocketpp::connection_hdl hdl, message_ptr msg)
{
    cConHook *con = nullptr;

    if (g_cMapHandler.find(hdl) == g_cMapHandler.end())
    {
        con = new cConHook();
        con->SetWebsocket(s, hdl);
        g_cMapHandler[hdl] = con;

        const auto theip = s->get_con_from_hdl(hdl);
        boost::asio::ip::address theadr = theip->get_raw_socket().remote_endpoint().address();
        std::string ip_as_string{theadr.to_string()};
        if (theadr.is_v6())
        {
            auto v6 = boost::asio::ip::make_address_v6(theadr.to_string());
            if (v6.is_v4_mapped())
            {
                auto v4 = boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped_t::v4_mapped, v6);
                ip_as_string = v4.to_string();
            }
            else
            {
                ip_as_string = boost::asio::ip::address_v4::any().to_string();
            }
        }
        strncpy(con->m_aHost, ip_as_string.c_str(), sizeof(con->m_aHost) - 1);
                *(con->m_aHost + sizeof(con->m_aHost) - 1) = '\0';
        slog(LOG_OFF, 0, "IP connection from: %s", con->m_aHost);
    }

    con = (cConHook *)g_cMapHandler[hdl];
    assert(con);

    con->m_pFptr(con, msg->get_payload().c_str());
}

void runechoserver()
{
    wsserver echo_server;

    try
    {
        echo_server.set_access_channels(websocketpp::log::alevel::none);
        echo_server.clear_access_channels(websocketpp::log::alevel::none);

        echo_server.init_asio();

        echo_server.set_tls_init_handler([](websocketpp::connection_hdl){
            auto ctx = websocketpp::lib::make_shared<websocketpp::lib::asio::ssl::context>(websocketpp::lib::asio::ssl::context::tlsv12);

            ctx->use_private_key_file("path_to_private_key.pem", websocketpp::lib::asio::ssl::context::pem);
            ctx->use_certificate_file("path_to_certificate.pem", websocketpp::lib::asio::ssl::context::pem);

            return ctx;
        });

        echo_server.set_close_handler(bind(&on_close, ::_1));
        echo_server.set_message_handler(bind(&on_message, &echo_server, ::_1, ::_2));

        echo_server.set_reuse_addr(true);
        echo_server.listen(websocketpp::lib::asio::ip::tcp::v4(), g_mplex_arg.nMotherPort);

        echo_server.start_accept();

        echo_server.run();
    }
    catch (websocketpp::exception const &e)
    {
        slog(LOG_OFF, 0, "Exception: %s.", e.what());
        exit(42);
    }
    catch (...)
    {
        slog(LOG_OFF, 0, "Exception other");
        exit(42);
    }
}

} // namespace mplex

