enable_testing()

set(TEST_SOURCES
    # unit tests
    tests/unit/test_LogEntry.cpp
    tests/unit/test_Logger.cpp
    tests/unit/test_BufferQueue.cpp
    tests/unit/test_Compression.cpp
    tests/unit/test_Crypto.cpp
    tests/unit/test_Writer.cpp
    tests/unit/test_SegmentedStorage.cpp
    tests/unit/test_LoggingManager.cpp
    # integration tests
    tests/integration/test_CompressionCrypto.cpp
    tests/integration/test_WriterQueue.cpp
    tests/integration/test_RoundTrip.cpp
    tests/integration/test_Export.cpp
    tests/integration/test_TamperSeqnum.cpp
)

macro(add_test_suite TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME}
        PRIVATE
        GDPR_Logging_lib
        GTest::GTest 
        GTest::Main
        OpenSSL::SSL 
        OpenSSL::Crypto 
        ZLIB::ZLIB
    )
    add_test(NAME ${TEST_NAME}_test COMMAND ${TEST_NAME})
endmacro()

# unit tests
add_test_suite(test_log_entry tests/unit/test_LogEntry.cpp)
add_test_suite(test_logger tests/unit/test_Logger.cpp)
add_test_suite(test_buffer_queue tests/unit/test_BufferQueue.cpp)
add_test_suite(test_compression tests/unit/test_Compression.cpp)
add_test_suite(test_crypto tests/unit/test_Crypto.cpp)
add_test_suite(test_writer tests/unit/test_Writer.cpp)
add_test_suite(test_segmented_storage tests/unit/test_SegmentedStorage.cpp)
add_test_suite(test_logging_manager tests/unit/test_LoggingManager.cpp)
# integration tests
add_test_suite(test_compression_crypto tests/integration/test_CompressionCrypto.cpp)
add_test_suite(test_writer_queue tests/integration/test_WriterQueue.cpp)
add_test_suite(test_round_trip tests/integration/test_RoundTrip.cpp)
add_test_suite(test_export tests/integration/test_Export.cpp)
add_test_suite(test_tamper_seqnum tests/integration/test_TamperSeqnum.cpp)