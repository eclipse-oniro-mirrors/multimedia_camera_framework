/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "camera_deferred_manager_unittest.h"

#include <fcntl.h>
#include "demuxer.h"
#include "media_manager.h"
#include "mpeg_manager_factory.h"
#include "track.h"
#include "gmock/gmock.h"
#include "test_common.h"
#include "camera_log.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
const std::string MEDIA_ROOT = "/data/test/media/";
const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
constexpr int32_t VIDEO_WIDTH = 1920;
constexpr int32_t VIDEO_HIGHT = 1080;

void DeferredManagerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredManagerUnitTest::SetUpTestCase started!");
}

void DeferredManagerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredManagerUnitTest::TearDownTestCase started!");
}

void DeferredManagerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
    fd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
}

void DeferredManagerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("DeferredManagerUnitTest::TearDown started!");
    if (fd_ > 0) {
        close(fd_);
    }
}

/*
 * Feature: Framework
 * Function: Test demuxer with SetTrackId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetTrackId  for abnormal branch and normal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_001, TestSize.Level0)
{
    auto demuxer = std::make_shared<Demuxer>();
    ASSERT_NE(demuxer, nullptr);
    Media::Plugins::MediaType trackType1 = Media::Plugins::MediaType::UNKNOWN;
    int32_t trackId = 0;
    demuxer->SetTrackId(trackType1, trackId);
    EXPECT_EQ(demuxer->GetTrackId(trackType1), INVALID_TRACK_ID);
    Media::Plugins::MediaType trackType2 = Media::Plugins::MediaType::AUDIO;
    demuxer->SetTrackId(trackType2, trackId);
    EXPECT_EQ(demuxer->GetTrackId(trackType2), trackId);
}

/*
 * Feature: Framework
 * Function: Test MediaManager with WriteSample
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WriteSample for abnormal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_003, TestSize.Level0)
{
    auto mediaManager = std::make_shared<MediaManager>();
    ASSERT_NE(mediaManager, nullptr);
    mediaManager->outputWriter_ = std::make_shared<Writer>();
    ASSERT_NE(mediaManager->outputWriter_, nullptr);
    mediaManager->outputWriter_->outputMuxer_ = std::make_shared<Muxer>();
    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    Media::Plugins::MediaType type1 = Media::Plugins::MediaType::TIMEDMETA;
    uint8_t randomIndex = 1;
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = 1;
    std::shared_ptr<AVBuffer> sample = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    mediaManager->started_ = false;
    EXPECT_EQ(mediaManager->WriteSample(type1, sample), ERROR_FAIL);
    Media::Plugins::MediaType type2 = Media::Plugins::MediaType::AUDIO;
    EXPECT_EQ(mediaManager->WriteSample(type2, sample), ERROR_FAIL);
}

/*
 * Feature: Framework
 * Function: Test MpegManagerFactory with Acquire
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Acquire for abnormal branch and normal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_004, TestSize.Level0)
{
    auto mpegManagerFactory = std::make_shared<MpegManagerFactory>();
    ASSERT_NE(mpegManagerFactory, nullptr);
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = {"20240101240000000", "20250101240000001"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(fd_));
    ASSERT_NE(inputFd, nullptr);
    EXPECT_NE(mpegManagerFactory->Acquire(requestId, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), nullptr);
    EXPECT_EQ(mpegManagerFactory->refCount_, 1);
}

/*
 * Feature: Framework
 * Function: Test MpegManager with UnInit, UnInitVideoCodec, GetFileFd
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnInit, UnInitVideoCodec, GetFileFd for abnormal branch and normal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_005, TestSize.Level0)
{
    auto mpegManager = std::make_shared<MpegManager>();
    ASSERT_NE(mpegManager, nullptr);
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = {"20250101240000000", "20250101240000001"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    int flags = 1;
    EXPECT_NE(mpegManager->GetFileFd(requestId, flags, "_vid"), nullptr);
    mpegManager->isRunning_.store(false);
    mpegManager->UnInitVideoCodec();
    MediaResult result1 = MediaResult::FAIL;
    MediaResult result2 = MediaResult::PAUSE;
    EXPECT_EQ(mpegManager->UnInit(result1), OK);
    EXPECT_EQ(mpegManager->UnInit(result2), OK);
}

/*
 * Feature: Framework
 * Function: Test Track with SetFormat, GetFormat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFormat, GetFormat for just call
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_006, TestSize.Level0)
{
    int32_t trackId = 1;
    Media::Plugins::MediaType type = Media::Plugins::MediaType::AUDIO;
    auto track1 = std::make_shared<Track>(trackId, nullptr, type);
    ASSERT_NE(track1, nullptr);
    EXPECT_EQ(track1->GetMeta(), nullptr);

    auto format = std::make_unique<Format>();
    auto track2 = std::make_shared<Track>(trackId, std::move(format), type);
    ASSERT_NE(track2, nullptr);
    ASSERT_NE(track2->format_, nullptr);
    EXPECT_NE(track2->GetMeta(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test Create
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Create
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_007, TestSize.Level0)
{
    auto mediaManager = std::make_shared<MediaManager>();
    ASSERT_NE(mediaManager, nullptr);
    EXPECT_NE(mediaManager->Create(0, 0, -1), MediaManagerError::OK);
}

/*
 * Feature: Framework
 * Function: Test WriteSample
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WriteSample
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_008, TestSize.Level0)
{
    auto mediaManager = std::make_shared<MediaManager>();
    ASSERT_NE(mediaManager, nullptr);
    mediaManager->outputWriter_ = std::make_shared<Writer>();
    ASSERT_NE(mediaManager->outputWriter_, nullptr);
    mediaManager->outputWriter_->outputMuxer_ = std::make_shared<Muxer>();
    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    Media::Plugins::MediaType type1 = Media::Plugins::MediaType::VIDEO;
    uint8_t randomIndex = 1;
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = 1;
    std::shared_ptr<AVBuffer> sample = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    mediaManager->started_ = false;
    EXPECT_EQ(mediaManager->WriteSample(type1, sample), ERROR_FAIL);
}

/*
 * Feature: Framework
 * Function: Test InitWriter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test InitWriter
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_009, TestSize.Level0)
{
    auto mediaManager = std::make_shared<MediaManager>();
    ASSERT_NE(mediaManager, nullptr);
    mediaManager->inputReader_ = std::make_shared<Reader>();
    ASSERT_NE(mediaManager->inputReader_, nullptr);
    int32_t trackId = 1;
    Media::Plugins::MediaType type = Media::Plugins::MediaType::AUDIO;
    auto format = std::make_unique<Format>();
    auto track = std::make_shared<Track>(trackId, std::move(format), type);
    mediaManager->inputReader_->tracks_[Media::Plugins::MediaType::AUDIO] = track;
    mediaManager->mediaInfo_ = std::make_shared<DeferredProcessing::MediaInfo>();
    EXPECT_EQ(mediaManager->InitWriter(), MediaManagerError::ERROR_FAIL);
}

/*
 * Feature: Framework
 * Function: Test MpegManagerFactory with Acquire
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Acquire for abnormal branch and normal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_010, TestSize.Level0)
{
    auto mpegManagerFactory = std::make_shared<MpegManagerFactory>();
    ASSERT_NE(mpegManagerFactory, nullptr);
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = {"20250101240000000", "20250101240000001"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(fd_));
    ASSERT_NE(inputFd, nullptr);
    EXPECT_NE(mpegManagerFactory->Acquire(requestId, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), nullptr);
    EXPECT_EQ(mpegManagerFactory->refCount_, 1);
}

/*
 * Feature: Framework
 * Function: Test SetAuxiliaryType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetAuxiliaryType
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_011, TestSize.Level0)
{
    int32_t trackId = 1;
    Media::Plugins::MediaType type = Media::Plugins::MediaType::AUDIO;
    auto format = std::make_unique<Format>();
    auto track = std::make_shared<Track>(trackId, std::move(format), type);
    DeferredProcessing::AuxiliaryType type_ = DeferredProcessing::AuxiliaryType::RAW_AUDIO;
    track->SetAuxiliaryType(type_);
    EXPECT_EQ(type_, track->GetAuxiliaryType());
}
} // CameraStandard
} // OHOS
