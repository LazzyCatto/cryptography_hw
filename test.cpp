#include <iomanip>
#include <format>

#include "crypto/kex/kex_diffie_hellman.h"
#include "crypto/host_key/host_key_rsa_sha2.h"
#include "crypto/cipher/cipher_aes.h"
#include "crypto/mac/mac_sha.h"
#include "crypto/primitives.h"

#include "minissh/transport.h"
#include "logger.h"

int main() {
    minissh::transport_layer transport{"localhost", "22"};
    transport.init_kex();

    struct service_request {
        uint8_t message_number;
        std::string service_name;
    } request{
        5,
        "ssh-userauth"
    };

    transport.send_packet(minissh::packet{request});
    service_request responce = transport.recv_packet().to_struct<service_request>();

    LOG_DEBUG(std::format("responce : {}", minissh::string_repr(responce)));
    return 0;
}