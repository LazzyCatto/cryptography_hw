#ifndef REGISTRY
#define REGISTRY

#include <memory>
#include <unordered_map>
#include <vector>

#include "crypto/cipher/cipher.h"
#include "crypto/host_key/host_key.h"
#include "crypto/kex/kex.h"
#include "crypto/mac/mac.h"
#include "logger.h"

namespace minissh {
    template <typename T>
    concept namable = requires (T obj) {
        { obj.name() } -> std::convertible_to<std::string>;
    };

    namespace {
        const namelist _none_list{"none"};
    }

    template <namable T>
    class registry {
      public:
        using factory = std::function<std::unique_ptr<T>()>;

        registry() = default;

        const std::vector<std::string>& get_value_names() const {
            return _value_names.empty() ? _none_list : _value_names;
        }
        std::unique_ptr<T> get_value(const std::string& name) {
            auto it = _factories.find(name);
            if (it != _factories.end()) {
                return it->second();
            }
            return nullptr; 

        }
        void register_value(const std::string& name, factory factory) {
            _factories[name] = std::move(factory);
            _value_names.emplace_back(name);
        }

      private:
        std::unordered_map<std::string, factory> _factories;
        std::vector<std::string> _value_names;
    };

    inline registry<kex>& kex_registry() {
        static registry<kex> reg;
        return reg;
    }
    inline registry<host_key>& host_key_registry() {
        static registry<host_key> reg;
        return reg;
    }
    inline registry<cipher>& client_cipher_registry() {
        static registry<cipher> reg;
        return reg;
    }
    inline registry<cipher>& server_cipher_registry() {
        static registry<cipher> reg;
        return reg;
    }
    inline registry<mac>& client_mac_registry() {
        static registry<mac> reg;
        return reg;
    }
    inline registry<mac>& server_mac_registry() {
        static registry<mac> reg;
        return reg;
    }

    template <namable T>
    struct registrar {
        registrar(registry<T>& current_registry, const std::string& name, registry<T>::factory factory) {
            LOG_DEBUG(std::format("register \"{}\".", name));
            current_registry.register_value(name, factory);
        }
    };

#define REGISTRAR_KEX(name, cls)\
    static minissh::registrar<minissh::kex> regisrar_##cls{ \
        minissh::kex_registry(), \
        name, \
        [](){ return std::make_unique<cls>(); } \
    };

#define REGISTRAR_HOST_KEY(name, cls)\
    static minissh::registrar<minissh::host_key> regisrar_##cls{ \
        minissh::host_key_registry(), \
        name, \
        [](){ return std::make_unique<cls>(); } \
    };

#define REGISTRAR_CIPHER(name, cls)\
    static minissh::registrar<minissh::cipher> client_regisrar_##cls{ \
        minissh::client_cipher_registry(), \
        name, \
        [](){ return std::make_unique<cls>(); } \
    }; \
    static minissh::registrar<minissh::cipher> server_regisrar_##cls{ \
        minissh::server_cipher_registry(), \
        name, \
        [](){ return std::make_unique<cls>(); } \
    };

#define REGISTRAR_MAC(name, cls)\
    static minissh::registrar<minissh::mac> client_regisrar_##cls{ \
        minissh::client_mac_registry(), \
        name, \
        [](){ return std::make_unique<cls>(); } \
    }; \
    static minissh::registrar<minissh::mac> server_regisrar_##cls{ \
        minissh::server_mac_registry(), \
        name, \
        [](){ return std::make_unique<cls>(); } \
    };
}

#endif
