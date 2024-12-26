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

#include "camera_log.h"
#include "frame_record_unittest.h"
#include "avcodec/common/frame_record.h"
#include "hcamera_service.h"
#include "surface_buffer.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void FrameRecordtUnit::SetUpTestCase(void) {}

void FrameRecordtUnit::TearDownTestCase(void) {}

void FrameRecordtUnit::SetUp() {}

void FrameRecordtUnit::TearDown() {}

/*
 * Feature: Framework
 * Function: Test ReleaseSurfaceBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReleaseSurfaceBuffer with a null wrapper. Verify videoBuffer is set to nullptr.
 */
HWTEST_F(FrameRecordtUnit, frame_record_unittest_001, TestSize.Level0)
{
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    ASSERT_NE(frameRecord, nullptr);
    sptr<MovingPhotoSurfaceWrapper> surfaceWrapper = nullptr;
    frameRecord->videoBuffer_ = videoBuffer;
    frameRecord->ReleaseSurfaceBuffer(surfaceWrapper);
    ASSERT_EQ(frameRecord->videoBuffer_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test ReleaseSurfaceBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReleaseSurfaceBuffer with a valid wrapper. Verify videoBuffer is set to nullptr.
 */
HWTEST_F(FrameRecordtUnit, frame_record_unittest_002, TestSize.Level0)
{
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    ASSERT_NE(frameRecord, nullptr);
    int32_t width = 1;
    int32_t height = 1;
    sptr<MovingPhotoSurfaceWrapper> moving = MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper(width, height);
    ASSERT_NE(moving, nullptr);
    sptr<MovingPhotoSurfaceWrapper> surfaceWrapper = moving;
    frameRecord->videoBuffer_ = videoBuffer;
    frameRecord->ReleaseSurfaceBuffer(surfaceWrapper);
    ASSERT_EQ(frameRecord->videoBuffer_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test ReleaseSurfaceBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReleaseSurfaceBuffer with a null videoBuffer. Verify videoBuffer remains nullptr.
 */
HWTEST_F(FrameRecordtUnit, frame_record_unittest_003, TestSize.Level0)
{
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    ASSERT_NE(frameRecord, nullptr);
    sptr<MovingPhotoSurfaceWrapper> surfaceWrapper = nullptr;
    frameRecord->videoBuffer_ = nullptr;
    frameRecord->ReleaseSurfaceBuffer(surfaceWrapper);
    ASSERT_EQ(frameRecord->videoBuffer_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test ReleaseMetaBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReleaseMetaBuffer with reuse set to true. Verify metaBuffer is not set to nullptr.
 */
HWTEST_F(FrameRecordtUnit, frame_record_unittest_004, TestSize.Level0)
{
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    ASSERT_NE(frameRecord, nullptr);
    frameRecord->status = FrameRecord::STATUS_READY_CONVERT;
    frameRecord->metaBuffer_ = videoBuffer;
    sptr<IConsumerSurface> consumerSurface = IConsumerSurface::Create();
    ASSERT_NE(consumerSurface, nullptr);
    sptr<IBufferProducer> producer = consumerSurface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    bool reuse = true;
    frameRecord->ReleaseMetaBuffer(surface, reuse);
    ASSERT_NE(frameRecord->metaBuffer_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test ReleaseMetaBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReleaseMetaBuffer with reuse set to false. Verify metaBuffer remains nullptr.
 */
HWTEST_F(FrameRecordtUnit, frame_record_unittest_005, TestSize.Level0)
{
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    ASSERT_NE(frameRecord, nullptr);
    frameRecord->status = FrameRecord::STATUS_NONE;
    frameRecord->metaBuffer_ = nullptr;
    sptr<IConsumerSurface> consumerSurface = IConsumerSurface::Create();
    ASSERT_NE(consumerSurface, nullptr);
    sptr<IBufferProducer> producer = consumerSurface->GetProducer();
    ASSERT_NE(producer, nullptr);
    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    bool reuse = false;
    frameRecord->ReleaseMetaBuffer(surface, reuse);
    ASSERT_EQ(frameRecord->metaBuffer_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test DeepCopyBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeepCopyBuffer with the same buffer. Verify newSurfaceBuffer width matches original.
 */
HWTEST_F(FrameRecordtUnit, frame_record_unittest_006, TestSize.Level0)
{
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    ASSERT_NE(frameRecord, nullptr);
    sptr<SurfaceBuffer> newSurfaceBuffer = videoBuffer;
    sptr<SurfaceBuffer> surfaceBuffer = videoBuffer;
    frameRecord->DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer);
    EXPECT_EQ(newSurfaceBuffer->GetWidth(), surfaceBuffer->GetWidth());
}
}
}