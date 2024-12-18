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

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

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
HWTEST_F(MovingPhotoVideoCacheUnitTest, moving_photo_video_cache_unittest_001, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);
    sptr<MovingPhotoVideoCache> cache = new MovingPhotoVideoCache(taskManager);

    sptr<AvcodecTaskManager> manager = new AvcodecTaskManager(session, type);
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t rotation = 1;
    int32_t captureId = 1;
    cache->taskManager_ = manager;
    cache->DoMuxerVideo(frameRecords, taskName, rotation, captureId);

    cache->taskManager_ = nullptr;
    cache->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
}

/*
 * Feature: Framework
 * Function: Test Release normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release normal branches.
 */
HWTEST_F(MovingPhotoVideoCacheUnitTest, moving_photo_video_cache_unittest_002, TestSize.Level0)
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
} // CameraStandard
} // OHOS
