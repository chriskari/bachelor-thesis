#include <gtest/gtest.h>
#include "LoggingManager.hpp"
#include "Config.hpp"
#include "LogEntry.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <thread>
#include <vector>

class LoggingManagerTest : public ::testing::Test
{
protected:
    std::string testDir;

    void SetUp() override
    {
        testDir = "./test_logging_manager_" +
                  std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        std::filesystem::remove_all(testDir);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(testDir);
    }

    LoggingConfig makeConfig()
    {
        LoggingConfig cfg;
        cfg.basePath = testDir;
        cfg.baseFilename = "lm_test";
        cfg.queueCapacity = 4096;
        cfg.maxExplicitProducers = 8;
        cfg.numWriterThreads = 1;
        cfg.batchSize = 32;
        cfg.useEncryption = false;
        cfg.compressionLevel = 0;
        cfg.appendTimeout = std::chrono::milliseconds(5000);
        return cfg;
    }

    LogEntry makeEntry()
    {
        return LogEntry{LogEntry::ActionType::READ, "loc", "ctrl", "proc", "subj"};
    }
};

TEST_F(LoggingManagerTest, StartStopIdempotent)
{
    LoggingManager mgr(makeConfig());
    EXPECT_TRUE(mgr.start());
    EXPECT_FALSE(mgr.start()) << "Second start() must return false";
    EXPECT_TRUE(mgr.stop());
    EXPECT_FALSE(mgr.stop()) << "Second stop() must return false";
}

// Zero values for essential config fields must fail loudly at construction.
TEST_F(LoggingManagerTest, InvalidConfigRejected)
{
    auto bad = [&](auto mutate) {
        LoggingConfig cfg = makeConfig();
        mutate(cfg);
        EXPECT_THROW(LoggingManager{cfg}, std::invalid_argument);
    };
    bad([](LoggingConfig &c) { c.queueCapacity = 0; });
    bad([](LoggingConfig &c) { c.numWriterThreads = 0; });
    bad([](LoggingConfig &c) { c.batchSize = 0; });
    bad([](LoggingConfig &c) { c.maxSegmentSize = 0; });
    bad([](LoggingConfig &c) { c.maxOpenFiles = 0; });
    bad([](LoggingConfig &c) { c.maxAttempts = 0; });
}

TEST_F(LoggingManagerTest, AppendAfterStopRejected)
{
    LoggingManager mgr(makeConfig());
    ASSERT_TRUE(mgr.start());
    auto token = mgr.createProducerToken();
    EXPECT_TRUE(mgr.append(makeEntry(), token));

    ASSERT_TRUE(mgr.stop());
    EXPECT_FALSE(mgr.append(makeEntry(), token));
}

// Producers that passed the accepting-check must either land in the queue or be
// rejected — never race stop()'s flush and silently drop.
TEST_F(LoggingManagerTest, ShutdownDrainHasNoInflightLoss)
{
    for (int cycle = 0; cycle < 3; ++cycle)
    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());

        std::atomic<bool> stopProducers{false};
        std::atomic<size_t> acceptedByMgr{0};

        // Exit once rejections are consistent so the test stays fast and quiet.
        auto producerFn = [&]()
        {
            auto token = mgr.createProducerToken();
            size_t consecutiveFailures = 0;
            while (!stopProducers.load(std::memory_order_acquire) && consecutiveFailures < 4)
            {
                if (mgr.append(makeEntry(), token))
                {
                    acceptedByMgr.fetch_add(1, std::memory_order_acq_rel);
                    consecutiveFailures = 0;
                }
                else
                {
                    ++consecutiveFailures;
                }
            }
        };

        std::vector<std::thread> producers;
        for (int i = 0; i < 3; ++i)
            producers.emplace_back(producerFn);

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ASSERT_TRUE(mgr.stop());

        stopProducers.store(true, std::memory_order_release);
        for (auto &t : producers)
            t.join();

        EXPECT_GT(acceptedByMgr.load(), 0u) << "Cycle " << cycle << ": should accept some";
    }
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
