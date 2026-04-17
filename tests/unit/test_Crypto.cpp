#include <gtest/gtest.h>
#include "Crypto.hpp"
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

class CryptoTest : public ::testing::Test
{
protected:
    Crypto crypto;

    std::vector<uint8_t> createRandomKey()
    {
        std::vector<uint8_t> key(Crypto::KEY_SIZE);
        for (size_t i = 0; i < key.size(); ++i)
        {
            key[i] = static_cast<uint8_t>(rand() % 256);
        }
        return key;
    }

    std::vector<uint8_t> stringToBytes(const std::string &str)
    {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    std::string bytesToString(const std::vector<uint8_t> &bytes)
    {
        return std::string(bytes.begin(), bytes.end());
    }

    void SetUp() override
    {
        srand(42);
    }
};

TEST_F(CryptoTest, EmptyData)
{
    std::vector<uint8_t> emptyData;
    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(emptyData), key);
    EXPECT_TRUE(encrypted.empty());

    std::vector<uint8_t> decrypted = crypto.decrypt(encrypted, key);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(CryptoTest, BasicEncryptDecrypt)
{
    std::string testMessage = "This is a test message for encryption";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> dataCopy = data;
    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(data), key);
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(dataCopy, encrypted);

    std::vector<uint8_t> decrypted = crypto.decrypt(encrypted, key);
    EXPECT_EQ(dataCopy, decrypted);
    EXPECT_EQ(testMessage, bytesToString(decrypted));
}

TEST_F(CryptoTest, VariousDataSizes)
{
    std::vector<size_t> sizes = {10, 100, 1000, 10000};
    std::vector<uint8_t> key = createRandomKey();

    for (size_t size : sizes)
    {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i)
        {
            data[i] = static_cast<uint8_t>(i % 256);
        }

        std::vector<uint8_t> dataCopy = data;
        std::vector<uint8_t> encrypted = crypto.encrypt(std::move(data), key);
        EXPECT_FALSE(encrypted.empty());

        std::vector<uint8_t> decrypted = crypto.decrypt(encrypted, key);
        EXPECT_EQ(dataCopy, decrypted);
    }
}

TEST_F(CryptoTest, InvalidKeySize)
{
    std::string testMessage = "Testing invalid key size";
    std::vector<uint8_t> data = stringToBytes(testMessage);

    std::vector<uint8_t> shortKey(16);
    std::vector<uint8_t> longKey(64);

    std::vector<uint8_t> dataCopy1 = data;
    std::vector<uint8_t> dataCopy2 = data;
    EXPECT_THROW(crypto.encrypt(std::move(dataCopy1), shortKey), std::runtime_error);
    EXPECT_THROW(crypto.encrypt(std::move(dataCopy2), longKey), std::runtime_error);
}

// Decryption with wrong key must raise TamperDetectedException.
TEST_F(CryptoTest, WrongKey)
{
    std::string testMessage = "This should not decrypt correctly with wrong key";
    std::vector<uint8_t> data = stringToBytes(testMessage);

    std::vector<uint8_t> correctKey = createRandomKey();
    std::vector<uint8_t> wrongKey = createRandomKey();
    ASSERT_NE(correctKey, wrongKey);

    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(data), correctKey);
    EXPECT_THROW(crypto.decrypt(encrypted, wrongKey), TamperDetectedException);
}

// Flipping a byte anywhere in the blob (including the embedded IV) must raise
// TamperDetectedException, not silently return empty.
TEST_F(CryptoTest, TamperingDetection)
{
    std::string testMessage = "This message should be protected against tampering";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(data), key);
    ASSERT_FALSE(encrypted.empty());
    ASSERT_GT(encrypted.size(), 20u);

    encrypted[encrypted.size() / 2] ^= 0xFF;

    EXPECT_THROW(crypto.decrypt(encrypted, key), TamperDetectedException);
}

// Tampering with the embedded IV alone must also be caught.
TEST_F(CryptoTest, TamperingIV)
{
    std::string testMessage = "IV tamper test";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(data), key);
    ASSERT_FALSE(encrypted.empty());

    const size_t ivOffset = sizeof(uint32_t) + Crypto::SEQNUM_SIZE;
    encrypted[ivOffset] ^= 0xFF;

    EXPECT_THROW(crypto.decrypt(encrypted, key), TamperDetectedException);
}

TEST_F(CryptoTest, TamperingSeqnumField)
{
    std::string testMessage = "Seqnum tamper test";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> encrypted;
    crypto.encrypt(data.data(), data.size(), key, encrypted,
                   /*seqnum=*/42, nullptr, 0);
    ASSERT_FALSE(encrypted.empty());

    encrypted[sizeof(uint32_t)] ^= 0x01;

    EXPECT_THROW(crypto.decrypt(encrypted, key, nullptr, 0), TamperDetectedException);
}

TEST_F(CryptoTest, TargetNameMismatchDetected)
{
    std::string testMessage = "Target mismatch test";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    const std::string targetA = "fileA";
    const std::string targetB = "fileB";

    std::vector<uint8_t> encrypted;
    crypto.encrypt(data.data(), data.size(), key, encrypted,
                   /*seqnum=*/7,
                   reinterpret_cast<const uint8_t *>(targetA.data()), targetA.size());

    EXPECT_THROW(crypto.decrypt(encrypted, key,
                                reinterpret_cast<const uint8_t *>(targetB.data()),
                                targetB.size()),
                 TamperDetectedException);
}

TEST_F(CryptoTest, SeqnumAndTargetRoundTrip)
{
    std::string testMessage = "Round trip with seqnum + target";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    const std::string target = "my_target_file";
    const uint64_t seqnum = 12345;

    std::vector<uint8_t> encrypted;
    crypto.encrypt(data.data(), data.size(), key, encrypted,
                   seqnum,
                   reinterpret_cast<const uint8_t *>(target.data()), target.size());
    ASSERT_FALSE(encrypted.empty());

    uint64_t peeked = 0;
    ASSERT_TRUE(Crypto::peekSeqnum(encrypted, peeked));
    EXPECT_EQ(peeked, seqnum);

    std::vector<uint8_t> decrypted = crypto.decrypt(
        encrypted, key,
        reinterpret_cast<const uint8_t *>(target.data()), target.size());
    EXPECT_EQ(data, decrypted);
}

TEST_F(CryptoTest, SeqnumSpliceAcrossBlobsRejected)
{
    std::vector<uint8_t> data = stringToBytes("abcdefghij");
    std::vector<uint8_t> key = createRandomKey();
    const std::string target = "t";

    std::vector<uint8_t> blobA;
    std::vector<uint8_t> blobB;
    crypto.encrypt(data.data(), data.size(), key, blobA, 1,
                   reinterpret_cast<const uint8_t *>(target.data()), target.size());
    crypto.encrypt(data.data(), data.size(), key, blobB, 2,
                   reinterpret_cast<const uint8_t *>(target.data()), target.size());

    // Claim blob B is at position 1; its tag was computed for seqnum=2.
    std::memcpy(blobB.data() + sizeof(uint32_t),
                blobA.data() + sizeof(uint32_t),
                Crypto::SEQNUM_SIZE);

    EXPECT_THROW(crypto.decrypt(blobB, key,
                                reinterpret_cast<const uint8_t *>(target.data()),
                                target.size()),
                 TamperDetectedException);
}

TEST_F(CryptoTest, BinaryData)
{
    std::vector<uint8_t> binaryData(256);
    for (int i = 0; i < 256; ++i)
    {
        binaryData[i] = static_cast<uint8_t>(i);
    }

    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> dataCopy = binaryData;
    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(binaryData), key);
    EXPECT_FALSE(encrypted.empty());

    std::vector<uint8_t> decrypted = crypto.decrypt(encrypted, key);
    EXPECT_EQ(dataCopy, decrypted);
}

TEST_F(CryptoTest, LargeData)
{
    const size_t size = 1024 * 1024;
    std::vector<uint8_t> largeData(size);
    for (size_t i = 0; i < size; ++i)
    {
        largeData[i] = static_cast<uint8_t>(i % 256);
    }

    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> dataCopy = largeData;
    std::vector<uint8_t> encrypted = crypto.encrypt(std::move(largeData), key);
    EXPECT_FALSE(encrypted.empty());

    std::vector<uint8_t> decrypted = crypto.decrypt(encrypted, key);
    EXPECT_EQ(dataCopy, decrypted);
}

// Same plaintext + same key must yield DIFFERENT ciphertexts, because a fresh
// random IV is generated per call. This is the core correctness property of
// the new IV strategy — if it regresses (e.g. IV generation becomes constant),
// nonce reuse under the same key becomes catastrophic.
TEST_F(CryptoTest, FreshIVPerEncryption)
{
    std::string testMessage = "Same plaintext should produce different ciphertexts";
    std::vector<uint8_t> data = stringToBytes(testMessage);
    std::vector<uint8_t> key = createRandomKey();

    std::vector<uint8_t> dataCopy1 = data;
    std::vector<uint8_t> dataCopy2 = data;
    std::vector<uint8_t> encrypted1 = crypto.encrypt(std::move(dataCopy1), key);
    std::vector<uint8_t> encrypted2 = crypto.encrypt(std::move(dataCopy2), key);

    ASSERT_EQ(encrypted1.size(), encrypted2.size());
    EXPECT_NE(encrypted1, encrypted2);

    // Both blobs must still decrypt to the same plaintext.
    EXPECT_EQ(data, crypto.decrypt(encrypted1, key));
    EXPECT_EQ(data, crypto.decrypt(encrypted2, key));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
