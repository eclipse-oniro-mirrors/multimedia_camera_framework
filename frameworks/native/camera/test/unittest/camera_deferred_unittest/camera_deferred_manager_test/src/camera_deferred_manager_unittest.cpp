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
constexpr int VIDEO_REQUEST_FD_ID = 1;

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
}

void DeferredManagerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("DeferredManagerUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test demuxer with SetTrackId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetTrackId  for abnormal branch and normal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_001, TestSize.Level1)
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
 * Function: Test MediaManager with Pause, Stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Pause, Stop for abnormal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_002, TestSize.Level1)
{
    auto mediaManager = std::make_shared<MediaManager>();
    ASSERT_NE(mediaManager, nullptr);
    mediaManager->outputWriter_ = std::make_shared<Writer>();
    ASSERT_NE(mediaManager->outputWriter_, nullptr);
    mediaManager->started_ = false;
    EXPECT_EQ(mediaManager->Pause(), PAUSE_RECEIVED);
    mediaManager->started_ = true;
    mediaManager->hasAudio_ = true;
    EXPECT_EQ(mediaManager->Stop(), ERROR_FAIL);
}

/*
 * Feature: Framework
 * Function: Test MediaManager with WriteSample
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WriteSample for abnormal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_003, TestSize.Level1)
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
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_004, TestSize.Level1)
{
    auto mpegManagerFactory = std::make_shared<MpegManagerFactory>();
    ASSERT_NE(mpegManagerFactory, nullptr);
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> inputFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID);
    ASSERT_NE(inputFd, nullptr);
    EXPECT_EQ(mpegManagerFactory->Acquire(requestId, inputFd), nullptr);
    EXPECT_EQ(mpegManagerFactory->refCount_, 0);
}

/*
 * Feature: Framework
 * Function: Test MpegManager with UnInit, UnInitVideoCodec, GetFileFd
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnInit, UnInitVideoCodec, GetFileFd for abnormal branch and normal branch
 */
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_005, TestSize.Level1)
{
    auto mpegManager = std::make_shared<MpegManager>();
    ASSERT_NE(mpegManager, nullptr);
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    int flags = 1;
    EXPECT_NE(mpegManager->GetFileFd(requestId, flags, "_vid_temp"), nullptr);
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
HWTEST_F(DeferredManagerUnitTest, camera_deferred_manager_unittest_006, TestSize.Level1)
{
    auto track1 = std::make_shared<Track>();
    ASSERT_NE(track1, nullptr);
    std::shared_ptr<Format> format = nullptr;
    int32_t trackId = 1;
    TrackFormat format1 = {format, trackId};
    Media::Plugins::MediaType type = Media::Plugins::MediaType::AUDIO;
    track1->SetFormat(format1, type);
    EXPECT_EQ(track1->GetFormat().format, nullptr);

    auto track2 = std::make_shared<Track>();
    ASSERT_NE(track2, nullptr);
    format = std::make_shared<Format>();
    ASSERT_NE(format, nullptr);
    TrackFormat format2 = {format, trackId};
    track2->SetFormat(format2, type);
    EXPECT_NE(track2->GetFormat().format, nullptr);
}
} // CameraStandard
} // OHOS
