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
    minissh::transport_layer transport{"localhost", "4000", "MINISSH-1.0-client"};
    transport.init_kex();

    LOG_DEBUG("main exit");
    return 0;
}