/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "video_encoder_unittest.h"

#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"
#include "external_window.h"
#include "native_avbuffer.h"
#include "native_avcodec_base.h"
#include "native_avcodec_videoencoder.h"
#include "sample_callback.h"
#include "video_encoder.h"

using namespace testing::ext;
static const int64_t VIDEO_FRAMERATE = 1280;

namespace OHOS {
namespace CameraStandard {

void VideoEncoderUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("VideoEncoderUnitTest::SetUpTestCase started!");
}

void VideoEncoderUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("VideoEncoderUnitTest::TearDownTestCase started!");
}

void VideoEncoderUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("VideoEncoderUnitTest::SetUp started!");
}

void VideoEncoderUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("VideoEncoderUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test RestartVideoCodec normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RestartVideoCodec normal branches.
 */
HWTEST_F(VideoEncoderUnitTest, video_encoder_unittest_001, TestSize.Level0)
{
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    std::shared_ptr<VideoEncoder> encoder = make_unique<VideoEncoder>(type);
    int32_t rotation = 1;
    std::shared_ptr<Size> size = std::make_shared<Size>();
    encoder->RestartVideoCodec(size, rotation);
    encoder->videoCodecType_ = VideoCodecType::VIDEO_ENCODE_TYPE_HEVC;
    encoder->RestartVideoCodec(size, rotation);
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord = new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicTransformType);
    int32_t keyFrameInterval = 10;
    EXPECT_FALSE(encoder->EnqueueBuffer(frameRecord, keyFrameInterval));
    EXPECT_FALSE(encoder->EnqueueBuffer(frameRecord, rotation));
}

/*
 * Feature: Framework
 * Function: Test EncodeSurfaceBuffer normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EncodeSurfaceBuffer normal branches.
 */
HWTEST_F(VideoEncoderUnitTest, video_encoder_unittest_002, TestSize.Level0)
{
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    std::shared_ptr<VideoEncoder> encoder = make_unique<VideoEncoder>(type);

    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord = new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicTransformType);
    frameRecord->timestamp_ = 1600000001LL;
    encoder->EncodeSurfaceBuffer(frameRecord);
    EXPECT_EQ(encoder->keyFrameInterval_, KEY_FRAME_INTERVAL);

    encoder->preFrameTimestamp_ = 0;
    frameRecord->timestamp_ = 1000000000LL;
    encoder->keyFrameInterval_ = 0;
    encoder->EncodeSurfaceBuffer(frameRecord);
    EXPECT_EQ(encoder->keyFrameInterval_, KEY_FRAME_INTERVAL);

    encoder->preFrameTimestamp_ = 0;
    frameRecord->timestamp_ = 1000000000LL;
    encoder->keyFrameInterval_ = 5;
    encoder->EncodeSurfaceBuffer(frameRecord);
    EXPECT_EQ(encoder->keyFrameInterval_, 5);

    std::string imageId = "testImageId";
    encoder->encoder_ = VideoEncoderFactory::CreateByMime(imageId);
    EXPECT_EQ(encoder->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test Release normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release normal branches.
 */
HWTEST_F(VideoEncoderUnitTest, video_encoder_unittest_003, TestSize.Level0)
{
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    std::shared_ptr<VideoEncoder> encoder = make_unique<VideoEncoder>(type);
    encoder->encoder_ = nullptr;
    EXPECT_EQ(encoder->Release(), 0);
}
} // CameraStandard
} // OHOS
