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
#include "hstream_repeat_unittest.h"
#include "camera_util.h"
#include "test_common.h"
#include "camera_service_ipc_interface_code.h"
#include "surface_type.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
void HStreamRepeatUnitTest::SetUpTestCase(void) {}

void HStreamRepeatUnitTest::TearDownTestCase(void) {}

void HStreamRepeatUnitTest::TearDown(void) {}

void HStreamRepeatUnitTest::SetUp(void) {}

HStreamRepeat* HStreamRepeatUnitTest::CreateHStreamRepeat()
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    auto streamRepeat = new (std::nothrow)
        HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);
    return streamRepeat;
}

/*
 * Feature: Framework
 * Function: Test SetStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the SetStreamInfo function when mEnableSecure is true.
 *    The extendedStreamInfos should not be empty after setting stream info.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_001, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    StreamInfo_V1_1 streamInfo;
    streamRepeat->repeatStreamType_ = RepeatStreamType::PREVIEW;
    streamRepeat->mEnableSecure = true;
    streamRepeat->SetStreamInfo(streamInfo);
    EXPECT_FALSE(streamInfo.extendedStreamInfos.empty());
}

/*
 * Feature: Framework
 * Function: Test SetStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the SetStreamInfo function when mEnableSecure is false.
 *    The extendedStreamInfos should be empty after setting stream info.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_002, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    StreamInfo_V1_1 streamInfo;
    streamRepeat->repeatStreamType_ = RepeatStreamType::PREVIEW;
    streamRepeat->mEnableSecure = false;
    streamRepeat->SetStreamInfo(streamInfo);
    EXPECT_TRUE(streamInfo.extendedStreamInfos.empty());
}

/*
 * Feature: Framework
 * Function: Test UpdateSketchStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the UpdateSketchStatus function. When the sketch status is updated to STOPED,
 *    the parentStreamRepeat should remain unchanged.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_003, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    SketchStatus status = SketchStatus::STOPED;
    streamRepeat->repeatStreamType_ = RepeatStreamType::SKETCH;
    streamRepeat->sketchStatus_ = SketchStatus::STARTED;
    streamRepeat->mEnableSecure = false;
    streamRepeat->UpdateSketchStatus(status);
    EXPECT_EQ(streamRepeat->parentStreamRepeat_.promote(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test Start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the Start function. When the stream is not in a valid state,
 *    the expected return value is CAMERA_INVALID_STATE.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_004, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    bool isUpdateSeetings = false;
    int32_t ret = streamRepeat->Start(settings, isUpdateSeetings);
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test ReleaseStream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the ReleaseStream function.
 *    When the stream is released without delay, the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_005, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    bool isDelay = false;
    int32_t ret = streamRepeat->ReleaseStream(isDelay);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OnDeferredVideoEnhancementInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the OnDeferredVideoEnhancementInfo function.
 * When the deferred video enhancement info is received,
 *    the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_006, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    CaptureEndedInfoExt captureEndedInfo = {1, 100, true, "video123"};
    streamRepeat->repeatStreamType_ = RepeatStreamType::PREVIEW;
    int32_t ret = streamRepeat->OnDeferredVideoEnhancementInfo(captureEndedInfo);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OnFrameError
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the OnFrameError function. When a frame error of type HIGH_TEMPERATURE_ERROR is reported,
 *    the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_007, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t errorType = HDI::Camera::V1_3::HIGH_TEMPERATURE_ERROR;
    int32_t ret = streamRepeat->OnFrameError(errorType);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test SetMirrorForLivePhoto
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetMirrorForLivePhoto when the mirror mode is supported.
 *    The expected return value is CAM_META_SUCCESS.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_008, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(1, 1024);
    ASSERT_NE(cameraAbility, nullptr);
    streamRepeat->cameraAbility_ = cameraAbility;
    uint8_t dfxSwitch = true;
    bool isEnable = true;
    camera_metadata_item_t item;
    int32_t mode = 110;
    int32_t res;
    streamRepeat->cameraAbility_->addEntry(OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &dfxSwitch, 1);
    streamRepeat->SetMirrorForLivePhoto(isEnable, mode);
    res = OHOS::Camera::FindCameraMetadataItem(streamRepeat->cameraAbility_->get(),
        OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    EXPECT_EQ(res, CAM_META_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test SetMirrorForLivePhoto
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetMirrorForLivePhoto when the mirror mode is not supported.
 *    The expected return value is CAM_META_ITEM_NOT_FOUND.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_009, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(1, 1024);
    ASSERT_NE(cameraAbility, nullptr);
    streamRepeat->cameraAbility_ = cameraAbility;
    bool isEnable = true;
    camera_metadata_item_t item;
    int32_t mode = 110;
    int32_t res;
    streamRepeat->SetMirrorForLivePhoto(isEnable, mode);
    res = OHOS::Camera::FindCameraMetadataItem(streamRepeat->cameraAbility_->get(),
        OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    EXPECT_EQ(res, CAM_META_ITEM_NOT_FOUND);
}

/*
 * Feature: Framework
 * Function: Test SetStreamTransform
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStreamTransform for front camera.
 *    The expected camera position remains OHOS_CAMERA_POSITION_FRONT.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_010, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(1, 1024);
    ASSERT_NE(cameraAbility, nullptr);
    streamRepeat->cameraAbility_ = cameraAbility;
    streamRepeat->cameraUsedAsPosition_ = OHOS_CAMERA_POSITION_FRONT;
    int disPlayRotation = -1;
    streamRepeat->SetStreamTransform(disPlayRotation);
    EXPECT_EQ(streamRepeat->cameraUsedAsPosition_, OHOS_CAMERA_POSITION_FRONT);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraSetRotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraSetRotation for front camera with 180-degree sensor orientation.
 *    The expected sensor orientation is 0.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_011, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    streamRepeat->setCameraRotation_ = STREAM_ROTATE_180;
    int32_t sensorOrientation = STREAM_ROTATE_180;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessCameraSetRotation(sensorOrientation, cameraPosition);
    EXPECT_EQ(sensorOrientation, STREAM_ROTATE_0);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraSetRotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraSetRotation for back camera with 90-degree sensor orientation.
 *    The expected sensor orientation is 270.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_012, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_90;
    streamRepeat->setCameraRotation_ = STREAM_ROTATE_90;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessCameraSetRotation(sensorOrientation, cameraPosition);
    EXPECT_EQ(sensorOrientation, STREAM_ROTATE_270);

}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for front camera with 90-degree sensor orientation.
 *    The expected transform is GRAPHIC_FLIP_H_ROT90.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_013, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_90;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H_ROT90;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for front camera with 180-degree sensor orientation.
 *    The expected transform is GRAPHIC_FLIP_H_ROT180.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_014, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_180;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H_ROT180;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for front camera with 360-degree sensor orientation.
 *    The expected transform is GRAPHIC_FLIP_H_ROT90.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_015, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_360;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H_ROT90;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);

}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for back camera with 360-degree sensor orientation.
 *    The expected transform is GRAPHIC_ROTATE_NONE.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_016, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_360;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for back camera with 270-degree sensor orientation.
 *    The expected transform is GRAPHIC_ROTATE_90.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_017, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_270;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_90;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for back camera with 180-degree sensor orientation.
 *    The expected transform is GRAPHIC_ROTATE_180.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_018, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_180;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_180;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessVerticalCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVerticalCameraPosition for back camera with 0-degree sensor orientation.
 *    The expected transform is GRAPHIC_ROTATE_180.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_019, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t sensorOrientation = STREAM_ROTATE_0;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_180;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for front camera with 0-degree stream rotation.
 *    The expected transform is GRAPHIC_FLIP_H.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_020, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_0;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for front camera with 90-degree stream rotation.
 *    The expected transform is GRAPHIC_FLIP_H_ROT90.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_021, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_90;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H_ROT90;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for front camera with 180-degree stream rotation.
 *    The expected transform is GRAPHIC_FLIP_H_ROT180.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_022, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_180;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H_ROT180;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for front camera with 270-degree stream rotation.
 *    The expected transform is GRAPHIC_FLIP_H_ROT270.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_023, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_270;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_FLIP_H_ROT270;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for front camera with 360-degree stream rotation.
 *    The expected transform is GRAPHIC_ROTATE_NONE.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_024, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_360;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for back camera with 0-degree stream rotation.
 *    The expected transform is GRAPHIC_ROTATE_NONE.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_025, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_0;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for back camera with 90-degree stream rotation.
 *    The expected transform is GRAPHIC_ROTATE_90.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_026, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_90;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_90;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for back camera with 180-degree stream rotation.
 *    The expected transform is GRAPHIC_ROTATE_180.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_027, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_180;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_180;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for back camera with 270-degree stream rotation.
 *    The expected transform is GRAPHIC_ROTATE_270.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_028, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_270;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_270;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test ProcessCameraPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCameraPosition for back camera with 360-degree stream rotation.
 *    The expected transform is GRAPHIC_ROTATE_NONE.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_029, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t streamRotation = STREAM_ROTATE_360;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    streamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    EXPECT_EQ(streamRepeat->producer_->GetTransform(transform), GSERROR_OK);
}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OperatePermissionCheck for an unauthorized caller token.
 *    The expected return value is CAMERA_OPERATION_NOT_ALLOWED.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_030, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    uint32_t interfaceCode = CAMERA_FORK_SKETCH_STREAM_REPEAT;
    streamRepeat->callerToken_ = 111;
    int32_t ret = streamRepeat->OperatePermissionCheck(interfaceCode);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OpenVideoDfxSwitch to ensure the debug switch is set correctly in camera ability metadata.
 *    The expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_031, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(1, 1024);
    ASSERT_NE(cameraAbility, nullptr);
    streamRepeat->cameraAbility_ = cameraAbility;
    streamRepeat->OpenVideoDfxSwitch(cameraAbility);
    streamRepeat->OpenVideoDfxSwitch(cameraAbility);
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(),
        OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &item);
    EXPECT_EQ(ret, CAMERA_OK);
}
} // CameraStandard
} // OHOS