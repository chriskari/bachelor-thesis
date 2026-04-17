# Local (laptop) mirrors of the workload benchmarks.
# Sources live in benchmarks/local/ and are scaled down for a MacBook-class
# machine. Binaries are suffixed _local_benchmark to avoid collision with the
# server versions built from cmake/benchmarks.cmake.
# Relies on BENCHMARK_LIBS and the benchmarks/ include directory set by
# cmake/benchmarks.cmake, so include this module AFTER that one.

set(LOCAL_WORKLOAD_BENCHMARKS
    compression_ratio
    diverse_filepaths
    large_batches
    main
    multi_producer_small_batches
    single_entry_appends
)

foreach(benchmark ${LOCAL_WORKLOAD_BENCHMARKS})
    add_executable(${benchmark}_local_benchmark benchmarks/local/${benchmark}.cpp)
    target_link_libraries(${benchmark}_local_benchmark ${BENCHMARK_LIBS})
endforeach()
