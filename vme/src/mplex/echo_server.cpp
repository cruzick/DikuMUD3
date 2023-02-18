#include "ClientConnector.h"
#include "mplex.h"
#include "slog.h"
#include "textutil.h"

#include <websocketpp/config/asio.hpp>  // OLD #include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

// typedef websocketpp::server<websocketpp::config::asio> wsserver;

using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;


namespace mplex
{
typedef websocketpp::lib::shared_ptr<boost::asio::ssl::context> context_ptr;
// No change to TLS init methods from echo_server_tls
std::string get_password() {
    return "test";
}

context_ptr on_tls_init(websocketpp::connection_hdl hdl) {
    std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << std::endl;
    context_ptr ctx(new boost::asio::ssl::context(boost::asio::ssl::context::tlsv1));

    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);
        ctx->set_password_callback(bind(&get_password));
        ctx->use_certificate_chain_file("server.pem");
        ctx->use_private_key_file("server.pem", boost::asio::ssl::context::pem);
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    return ctx;
}

// pull out the type of messages sent by our config
typedef wsserver::message_ptr message_ptr;

// std::map<std::owner_less<websocketpp::connection_hdl>, void *> g_cMapHandler;
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

// send message back to websocket client: 1 is message sent, 0 if failure
int ws_send_message(wsserver *s, websocketpp::connection_hdl hdl, const char *txt)
{
    std::string mystr(txt);

    str_correct_utf8(mystr);

    try
    {
        s->send(hdl, mystr.c_str(), mystr.length(), websocketpp::frame::opcode::text);
        // s->send(hdl, txt, strlen(txt), websocketpp::frame::opcode::text);
        return 1;
    }
    catch (websocketpp::exception const &e)
    {
        slog(LOG_OFF, 0, "Send failed: %s", e.what());
        return 0;
    }
}


// Define a callback to handle incoming messages
void on_message(wsserver *s, websocketpp::connection_hdl hdl, message_ptr msg)
{
    cConHook *con = nullptr;

    if (g_cMapHandler.find(hdl) == g_cMapHandler.end())
    {
        // Crete the con hook
        con = new cConHook();
        con->SetWebsocket(s, hdl);
        g_cMapHandler[hdl] = con;

        // Get the IP address
        const auto theip = s->get_con_from_hdl(hdl);
        boost::asio::ip::address theadr = theip->get_raw_socket().remote_endpoint().address();
        std::string ip_as_string{theadr.to_string()};
        if (theadr.is_v6())
        {
            auto v6 = boost::asio::ip::make_address_v6(theadr.to_string());
            // Lets hope it is a ipv4 mapped to ipv6 address space
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

    // Log here to see all commands received (plus passwords :()
    // slog(LOG_OFF, 0, "on_message called with hdl %p and messsage %s.",
    //        hdl.lock().get(), msg->get_payload().c_str());

    // check for a special command to instruct the server to stop listening so
    // it can be cleanly exited.

    /*
    if (msg->get_payload() == "stop-listening") {
        s->stop_listening();
        con->Close( TRUE );
        return;
    }*/

    con->m_pFptr(con, msg->get_payload().c_str());
}

void runechoserver()
{
     // set up tls endpoint
    wsserver endpoint_tls;
    endpoint_tls.init_asio();
     endpoint_tls.set_message_handler(bind(&on_message<wsserver>,&endpoint_tls,::_1,::_2));
    // TLS endpoint has an extra handler for the tls init
    endpoint_tls.set_tls_init_handler(bind(&on_tls_init,::_1));
    // tls endpoint listens on a different port
    endpoint_tls.set_close_handler(bind(&on_close, ::_1));
    endpoint_tls.set_reuse_addr(true);
    endpoint_tls.listen(g_mplex_arg.nMotherPort);
    endpoint_tls.start_accept();
    endpoint_tls.run();
    // Create a server endpoint
    //OLDwsserver echo_server;
    /*
    try
    {
        // Set logging settings
        // echo_server.set_access_channels(websocketpp::log::alevel::all);
        // echo_server.clear_access_channels(websocketpp::log::alevel::frame_payload);
        echo_server.set_access_channels(websocketpp::log::alevel::none);
        echo_server.clear_access_channels(websocketpp::log::alevel::none);

        // Initialize Asio
        echo_server.init_asio();

        // Register our message handler
        // Look in endpoint.hpp for various types of handlers you can bind, e.g. set_open_handler

        // echo_server.set_open_handler(bind(&on_open, ::_1));
        echo_server.set_close_handler(bind(&on_close, ::_1));
        echo_server.set_message_handler(bind(&on_message, &echo_server, ::_1, ::_2));

        // Listen on port
        echo_server.set_reuse_addr(true);
        echo_server.listen(g_mplex_arg.nMotherPort);

        // Start the server accept loop
        echo_server.start_accept();

        // Start the ASIO io_service run loop
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
    */

}

} // namespace mplex
