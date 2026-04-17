set(LIBRARY_SOURCES
    src/LogEntry.cpp
    src/Logger.cpp
    src/BufferQueue.cpp
    src/Compression.cpp
    src/Crypto.cpp
    src/Writer.cpp
    src/SegmentedStorage.cpp
    src/LoggingManager.cpp
    src/LogExporter.cpp
    benchmarks/BenchmarkUtils.cpp
)

add_library(GDPR_Logging_lib ${LIBRARY_SOURCES})

target_link_libraries(GDPR_Logging_lib 
    PUBLIC 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ZLIB::ZLIB
)

target_include_directories(GDPR_Logging_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(GDPR_Logging_lib PUBLIC external/concurrentqueue)