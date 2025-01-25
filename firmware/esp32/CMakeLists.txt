# firmware/esp32/CMakeLists.txt
# Component build for the ESP-IDF project. Build with `idf.py build` from firmware/esp32.

idf_component_register(
    SRCS
        "main.cpp"
        "ble_observer.cpp"
        "event_matcher.cpp"
        "counter.cpp"
        "storage_nvs.cpp"
        "signer.cpp"
        "reporter.cpp"
    INCLUDE_DIRS
        "."
    REQUIRES
        bt
        nvs_flash
        esp_http_client
        esp_timer
        mbedtls
        libsodium
)

target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra)
