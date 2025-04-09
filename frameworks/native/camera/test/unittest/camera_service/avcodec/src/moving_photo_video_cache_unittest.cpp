/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "moving_photo_video_cache_unittest.h"

#include "avcodec_task_manager.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "camera_server_photo_proxy.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "frame_record.h"
#include "ipc_skeleton.h"
#include "moving_photo_video_cache.h"
#include "native_mfmagic.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

static const int64_t VIDEO_FRAMERATE = 1280;

void MyFunction(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("MyFunction started!");
}

void MovingPhotoVideoCacheUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheUnitTest::SetUpTestCase started!");
}

void MovingPhotoVideoCacheUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheUnitTest::TearDownTestCase started!");
}

void MovingPhotoVideoCacheUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheUnitTest::SetUp started!");
}

void MovingPhotoVideoCacheUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test DoMuxerVideo normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DoMuxerVideo normal branches.
 */
HWTEST_F(MovingPhotoVideoCacheUnitTest, moving_photo_video_cache_unittest_001, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);
    sptr<MovingPhotoVideoCache> cache = new MovingPhotoVideoCache(taskManager);

    sptr<AvcodecTaskManager> manager = new AvcodecTaskManager(session, type, colorSpace);
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t rotation = 1;
    int32_t captureId = 1;
    cache->taskManager_ = nullptr;
    cache->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    cache->taskManager_ = manager;
    cache->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    EXPECT_NE(cache->taskManager_->taskManager_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test Release normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release normal branches.
 */
HWTEST_F(MovingPhotoVideoCacheUnitTest, moving_photo_video_cache_unittest_002, TestSize.Level1)
{
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t rotation = 1;
    int32_t captureId = 1;
    CachedFrameCallbackHandle* handle =
        new CachedFrameCallbackHandle(frameRecords, MyFunction, taskName, rotation, captureId);

    handle->AbortCapture();
    EXPECT_EQ(handle->encodedEndCbFunc_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test OnCacheFrameFinish normal branches while isAbort_ is true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCacheFrameFinish normal branches while isAbort_ is true
 */
HWTEST_F(MovingPhotoVideoCacheUnitTest, moving_photo_video_cache_unittest_003, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> manager = new AvcodecTaskManager(session, type, colorSpace);
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t rotation = 1;
    int32_t captureId = 1;
    sptr<CachedFrameCallbackHandle> handle = sptr<CachedFrameCallbackHandle>
        (new CachedFrameCallbackHandle(frameRecords, MyFunction, taskName, rotation, captureId));

    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord = new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicTransformType);
    ASSERT_NE(frameRecord, nullptr);
    bool cachedSuccess = true;
    handle->OnCacheFrameFinish(frameRecord, cachedSuccess);
    EXPECT_EQ(handle->cacheRecords_.size(), 0);
    handle->isAbort_ = true;
    handle->OnCacheFrameFinish(frameRecord, cachedSuccess);
    ASSERT_NE(handle->encodedEndCbFunc_, nullptr);
    EXPECT_EQ(handle->cacheRecords_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test OnCacheFrameFinish normal branches while find frameRecord successfully
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCacheFrameFinish normal branches while find frameRecord successfully
 */
HWTEST_F(MovingPhotoVideoCacheUnitTest, moving_photo_video_cache_unittest_004, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> manager = new AvcodecTaskManager(session, type, colorSpace);
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t rotation = 1;
    int32_t captureId = 1;
    sptr<CachedFrameCallbackHandle> handle = sptr<CachedFrameCallbackHandle>
        (new CachedFrameCallbackHandle(frameRecords, MyFunction, taskName, rotation, captureId));
    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    uint8_t randomIndex = 1;
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = 1;
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);

    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord_1 = new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicTransformType);
    ASSERT_NE(frameRecord_1, nullptr);
    sptr<FrameRecord> frameRecord_2 = new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicTransformType);
    ASSERT_NE(frameRecord_2, nullptr);
    sptr<FrameRecord> frameRecord_3 = new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicTransformType);
    ASSERT_NE(frameRecord_3, nullptr);
    handle->cacheRecords_.insert(frameRecord_1);
    handle->cacheRecords_.insert(frameRecord_2);
    handle->cacheRecords_.insert(frameRecord_3);
    frameRecord_3->encodedBuffer = std::make_shared<OHOS::Media::AVBuffer>();

    std::vector<sptr<FrameRecord>> records;
    uint64_t param1 = 1;
    int32_t param2 = 1;
    int32_t param3 = 1;
    if (handle->encodedEndCbFunc_) {
        handle->encodedEndCbFunc_(records, param1, param2, param3);
    }
    handle->OnCacheFrameFinish(frameRecord_1, false);
    EXPECT_EQ(handle->successCacheRecords_.size(), 0);
    EXPECT_EQ(handle->errorCacheRecords_.size(), 1);
    handle->OnCacheFrameFinish(frameRecord_2, false);
    EXPECT_EQ(handle->successCacheRecords_.size(), 0);
    EXPECT_EQ(handle->errorCacheRecords_.size(), 1);
    handle->OnCacheFrameFinish(frameRecord_3, true);
    EXPECT_EQ(handle->successCacheRecords_.size(), 0);
    EXPECT_EQ(handle->errorCacheRecords_.size(), 1);
}
} // CameraStandard
} // OHOS
