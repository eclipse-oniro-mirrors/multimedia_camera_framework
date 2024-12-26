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

#include "audio_video_muxer_unittest.h"

#include "avmuxer.h"
#include "avmuxer_impl.h"
#include "audio_video_muxer.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "capture_scene_const.h"
#include <fcntl.h>
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

const std::string TEST_FILE_PATH = "/data/test/media/";

void AudioVideoMuxerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioVideoMuxerUnitTest::SetUpTestCase started!");
}

void AudioVideoMuxerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioVideoMuxerUnitTest::TearDownTestCase started!");
}

void AudioVideoMuxerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("AudioVideoMuxerUnitTest::SetUp started!");
}

void AudioVideoMuxerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("AudioVideoMuxerUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test WriteSampleBuffer abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WriteSampleBuffer abnormal branches.
 */
HWTEST_F(AudioVideoMuxerUnitTest, audio_video_muxer_unittest_001, TestSize.Level0)
{
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    OH_AVOutputFormat format = AV_OUTPUT_FORMAT_MPEG_4;
    int32_t ret = muxer->Create(format, nullptr);
    EXPECT_EQ(ret, 1);

    std::shared_ptr<OHOS::Media::AVBuffer> sample = make_shared<OHOS::Media::AVBuffer>();
    TrackType type = AUDIO_TRACK;
    std::shared_ptr<AVMuxerImpl> impl = std::make_shared<AVMuxerImpl>();
    muxer->muxer_ = impl;
    ret = muxer->WriteSampleBuffer(sample, type);
    EXPECT_EQ(ret, 1);

    type = VIDEO_TRACK;
    ret = muxer->WriteSampleBuffer(sample, type);
    EXPECT_EQ(ret, 1);

    type = META_TRACK;
    ret = muxer->WriteSampleBuffer(sample, type);
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test AddTrack abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddTrack abnormal branches.
 */
HWTEST_F(AudioVideoMuxerUnitTest, audio_video_muxer_unittest_002, TestSize.Level0)
{
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    int trackId = -1;
    std::shared_ptr<Format> format = make_shared<Format>();
    TrackType type = AUDIO_TRACK;
    std::shared_ptr<AVMuxerImpl> impl = std::make_shared<AVMuxerImpl>();
    muxer->muxer_ = impl;
    int32_t ret = muxer->AddTrack(trackId, format, type);
    EXPECT_EQ(ret, 0);

    type = VIDEO_TRACK;
    ret = muxer->AddTrack(trackId, format, type);
    EXPECT_EQ(ret, 0);

    type = META_TRACK;
    ret = muxer->AddTrack(trackId, format, type);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test WriteSampleBuffer normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WriteSampleBuffer normal branches.
 */
HWTEST_F(AudioVideoMuxerUnitTest, audio_video_muxer_unittest_003, TestSize.Level0)
{
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    OH_AVOutputFormat format = AV_OUTPUT_FORMAT_MPEG_4;
    int32_t ret = muxer->Create(format, nullptr);
    EXPECT_EQ(ret, 1);

    std::shared_ptr<OHOS::Media::AVBuffer> sample = make_shared<OHOS::Media::AVBuffer>();
    TrackType type = AUDIO_TRACK;
    std::shared_ptr<AVMuxerImpl> impl = std::make_shared<AVMuxerImpl>();
    muxer->muxer_ = impl;
    ret = muxer->WriteSampleBuffer(sample, type);
    EXPECT_EQ(ret, 1);

    type = VIDEO_TRACK;
    ret = muxer->WriteSampleBuffer(sample, type);
    EXPECT_EQ(ret, 1);

    type = META_TRACK;
    ret = muxer->WriteSampleBuffer(sample, type);
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test Create and Release normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Create and Release normal branches.
 */
HWTEST_F(AudioVideoMuxerUnitTest, audio_video_muxer_unittest_004, TestSize.Level0)
{
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    OH_AVOutputFormat format = AV_OUTPUT_FORMAT_MPEG_4;
    
    int32_t ret = muxer->Create(format, nullptr);
    EXPECT_EQ(ret, 1);
    muxer->muxer_ = nullptr;
}
} // CameraStandard
} // OHOS
