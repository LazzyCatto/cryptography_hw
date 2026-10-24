## ОБЩАЯ ИНФОРМАЦИЯ

Библиотека построена вокруг нескольких ключевых компонентов:

#### Базовые типы:
- **`secure_buffer`** — безопасный буфер для бинарных данных.
- **`mpint`** — целое число произвольной точности.
- **`packet`** — пакет протокола, автоматически сериализующийся из структур и обратно.

#### Логические слои:
- **`transport_layer`** — транспортный слой (установка соединения, шифрование, MAC).
- **`core`** — высокоуровневый клиент (KEX, авторизация, перехват, соединение).

#### Работа с байтовыми представлениями:
- **`_bit_convertion`** — шаблонная функция преобразования между структурами и байтовым представлением.
- **`_read_from_buffer`**, **`_read_from_buffer_no_offset`** — функция для чтения типов данных из буфера.
- **`_write_in_buffer`**, **`write_in_buffer_no_offset`** — функция для записи типов данных в буффер

Все структуры сообщений описываются как обычные C++ структуры, а их преобразование в байты и обратно берёт на себя `_bit_convertion` и `packet`.

---

## БАЗОВЫЕ ТИПЫ

### secure_buffer

`secure_buffer` — это буфер, хранящий последовательность байт и свою длину.  
Он используется для передачи бинарных данных (ключи, подписи, полезная нагрузка пакетов).

```cpp
// Создание буфера заданного размера
secure_buffer buf{1024};

// Создание из сырых данных
secure_buffer buf2{data_ptr, data_len};

// Доступ к данным
uint8_t* ptr = buf.data();
size_t len = buf.length();

// Поэлементный доступ
buf[0] = 0x42;
```

### mpint

`mpint` — целое число произвольной точности. Поддерживает арифметические операции, сравнение, сдвиги, возведение в степень по модулю.

```cpp
// Создание из буфера (интерпретируется как число в big-endian)
mpint a = mpint::from_buffer(buf);

// Создание из целого литерала
mpint b{12345};

// Арифметика
mpint c = a + b;
c %= MODY_2048_BIT_RABIN;
c = mpint::pow_mod(a, b, MODP_2048_BIT_PRIME);

// Проверка на ноль
if (a.is_zero()) { /* ... */ }

// Размер в байтах
size_t sz = a.size();

// Доступ к младшему байту
uint8_t low = a[0];
```

### packet

`packet` — это класс пакета. Он умеет:

- создаваться из структуры сообщения (первое поле структуры должно быть `uint8_t` — номер сообщения);
- возвращать номер сообщения;
- преобразовываться в структуру.

```cpp
// Определение структуры сообщения
struct my_message {
    uint8_t message_number; // например, MINISSH_DEBUG
    std::string text;
};

// Создание пакета из структуры
my_message msg{MINISSH_DEBUG, "hello"};
packet p{msg};

// Номер сообщения
uint8_t num = p.message_number();

// Преобразование в структуру
auto received = p.to_struct<my_message>();
```

---

## БАЙТОВОЕ ПРЕДСТАВЛЕНИЕ

### _bit_convertion

Шаблонная функция `_bit_convertion<From, To>(source)` преобразует значение типа `From` в тип `To`.  
Она автоматически применяет правила байтового представления протокола (см. раздел [БАЙТОВОЕ ПРЕДСТАВЛЕНИЕ] в документации протокола).

```cpp
struct my_struct {
    uint32_t a;
    std::string b;
};

// Структура -> буфер
my_struct obj{42, "hello"};
secure_buffer buf = _bit_convertion<my_struct, secure_buffer>(obj);

// Буфер -> структура
my_struct obj2 = _bit_convertion<secure_buffer, my_struct>(buf);
```

Функция корректно обрабатывает вложенные структуры, строки, `namelist`, `mpint` и другие типы, определённые в протоколе.

### Чтение из буферов

Для низкоуровневого чтения значений из сырых байтовых массивов используются функции:

- `_read_from_buffer(buffer, &offset, &value)` — читает значение типа `T` из буфера, сдвигая его на `offset`. После чего значение `offset` увеличивается на размер данных.
- `_read_from_buffer_no_offset(buffer, &value)` — читает значение без сдвига.

Пример:

```cpp
uint8_t buffer[4] = { /* ... */ };
uint32_t value;
_read_from_buffer_no_offset(buffer, &value);
// теперь value содержит прочитанное 32-битное число
```

### Запись в буферы

Для низкоуровневой записи значений в сырой байтовый массив используются функции, аналогичные `_read_from`:

- `_write_in_buffer(buffer, &offset, value)` 
- `_write_in_buffer_no_offset(buffer, value)`

Пример:

```cpp
uint8_t buffer[6];
std::string str{"hi"};
_write_in_buffer_no_offset(buffer, str);
// теперь buffer содержит байтовое представление строки "hi"
```

---

## ТРАНСПОРТНЫЙ СЛОЙ И КЛИЕНТ

### Создание транспортного слоя

```cpp
#include "src/minissh/transport.h"
#include "src/minissh/core.h"
#include "src/logger.h"

using namespace minissh;

int main(int argc, char* argv[]) {
    // Инициализация логгера (необязательно, но полезно)
    int logger_id;
    fs::path exec_file = argv[0];
    fs::path logger_dir = exec_file.parent_path() / "log";
    logger::get_instance().init(false, _get_free_logger_name(logger_dir, "logger", &logger_id));

    // Создание транспортного слоя
    auto transport = std::make_unique<transport_layer>(
        "ip",                   // IP сервера
        "port",                 // Порт
        "MINISSH-1.0-name\r\n"  // Название протокола. Должно иметь вид "MINISSH-*"
    );

    // Создание клиента поверх транспортного уровня
    minissh::core client{std::move(transport)};

    // Инициализация обмена ключами
    client.init_kex();

    // Авторизация
    client.authorize("username", "password");

    // Перехват сообщений
    std::optional<message> intercepted = client.read_tunnel();
    if (!intercepted) {
        std::cout << "no message" << std::endl;
    } else {
        std::cout << "to: " << intercepted->destination
                  << "\ndata: " << string_repr(intercepted->data) << std::endl;
    }

    // Предоставление секрета
    client.connect("key");

    // Запуск основного цикла
    client.run();

    return 0;
}
```

### Основные методы `core`

- `init_kex()` — инициализирует обмен ключами.
- `authorize(username, password)` — выполняет авторизацию.
- `read_tunnel()` — читает перехваченное сообщение из туннеля. Возвращает `std::optional<message>`.
- `write_in_tunnel(message)` — отправляет сообщение в туннель.
- `connect(secret)` — передаёт секрет для проверки и открытия канала.
- `run()` — запускает основной цикл обмена данными.

Структура `message` содержит:
- `std::string destination` — адресат;
- `secure_buffer data` — данные сообщения.

---

## ПЕРЕХВАТ СООБЩЕНИЙ

Сервис `intercept` позволяет читать и модифицировать сообщения между Алисой и Бобом.  
Клиент может:

- получать сообщения из `send_queue` через `read_tunnel()`;
- отправлять сообщения в `recv_queue` через `write_in_tunnel()`;
- изменять содержимое сообщений перед отправкой.

Пример цикла перехвата:

```cpp
char cmd;
while (true) {
    std::optional<message> intercepted = client.read_tunnel();
    if (!intercepted) {
        std::cout << "no message" << std::endl;
    } else {
        std::cout << "to: " << intercepted->destination
                  << "\ndata: " << string_repr(intercepted->data);
    }

    std::cin >> cmd;
    if (cmd == 'q') break;
    else if (cmd == 'n') {
        client.write_in_tunnel(std::move(intercepted.value()));
    } else if (cmd == 'r') {
        // Замена данных на новые байты
        std::vector<uint8_t> vec_buf;
        uint32_t length;
        std::cin >> length;
        for (uint32_t i = 0; i < length; ++i) {
            int val;
            std::cin >> std::hex >> val;
            vec_buf.push_back(static_cast<uint8_t>(val));
        }
        intercepted->data = secure_buffer{vec_buf.data(), vec_buf.size()};
        client.write_in_tunnel(std::move(intercepted.value()));
    } else if (cmd == 'c') {
        // Модификация данных XOR-ом
        std::string old_data, new_data;
        std::cin >> old_data >> new_data;
        for (int i = 0; i < old_data.length(); ++i) {
            intercepted->data.data()[i + 10] ^= static_cast<uint8_t>(old_data[i]);
            intercepted->data.data()[i + 10] ^= static_cast<uint8_t>(new_data[i]);
        }
        client.write_in_tunnel(std::move(intercepted.value()));
    }
}
```

---

## ПРИМЕЧАНИЕ

Криптографические примитивы (KEX, host key, cipher, MAC) в данном README не описаны, подробнее про них описано на соответствующих уровнях.
