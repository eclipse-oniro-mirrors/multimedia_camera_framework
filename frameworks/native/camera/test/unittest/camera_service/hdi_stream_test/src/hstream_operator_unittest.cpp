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

#include "camera_log.h"
#include "camera_server_photo_proxy.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hstream_capture.h"
#include "hstream_operator_unittest.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::Return;

namespace OHOS {
namespace CameraStandard {

void HStreamOperatorUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HStreamOperatorUnitTest::SetUpTestCase started!");
}

void HStreamOperatorUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HStreamOperatorUnitTest::TearDownTestCase started!");
}

void HStreamOperatorUnitTest::SetUp()
{
    streamOp_ = new HStreamOperator();
    MEDIA_DEBUG_LOG("HStreamOperatorUnitTest::SetUp started!");
}

void HStreamOperatorUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("HStreamOperatorUnitTest::TearDown started!");
}

sptr<HStreamCapture> HStreamOperatorUnitTest::GenStreamCapture(int32_t w, int32_t h)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_RETURN_RET_ELOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_RETURN_RET_ELOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamCapture> stream = new (std::nothrow) HStreamCapture(producer, format, w, h);
    return stream;
}

sptr<HStreamMetadata> HStreamOperatorUnitTest::GenStreamMetadata(std::vector<int32_t> metadataTypes)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_RETURN_RET_ELOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_RETURN_RET_ELOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamMetadata> stream = new (std::nothrow) HStreamMetadata(producer, format, {});
    return stream;
}

sptr<HStreamRepeat> HStreamOperatorUnitTest::GenStreamRepeat(RepeatStreamType type, int32_t w, int32_t h)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_RETURN_RET_ELOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_RETURN_RET_ELOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamRepeat> stream = new (std::nothrow) HStreamRepeat(producer, format, w, h, type);
    return stream;
}

sptr<HStreamDepthData> HStreamOperatorUnitTest::GenStreamDepthData(int32_t w, int32_t h)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_RETURN_RET_ELOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_RETURN_RET_ELOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamDepthData> stream = new (std::nothrow) HStreamDepthData(producer, format, w, h);
    return stream;
}

/**
 * @tc.name  : Test GetCurrentStreamInfos API
 * @tc.number: GetCurrentStreamInfos_001
 * @tc.desc  : Test GetCurrentStreamInfos API, when StreamType == METADATA
 */
HWTEST_F(HStreamOperatorUnitTest, GetCurrentStreamInfos_001, TestSize.Level1)
{
    streamOp_->streamContainer_.AddStream(GenStreamMetadata());
    std::vector<StreamInfo_V1_5> streamInfos;
    auto rc = streamOp_->GetCurrentStreamInfos(streamInfos);
    EXPECT_EQ(rc, CAMERA_OK);
    EXPECT_TRUE(streamInfos.empty());
}

/**
 * @tc.name  : Test GetCurrentStreamInfos API
 * @tc.number: GetCurrentStreamInfos_002
 * @tc.desc  : Test GetCurrentStreamInfos API, when StreamType == CAPTURE
 */
HWTEST_F(HStreamOperatorUnitTest, GetCurrentStreamInfos_002, TestSize.Level1)
{
    streamOp_->streamContainer_.AddStream(GenStreamCapture());
    std::vector<StreamInfo_V1_5> streamInfos;
    auto rc = streamOp_->GetCurrentStreamInfos(streamInfos);
    EXPECT_EQ(rc, CAMERA_OK);
    EXPECT_EQ(streamInfos.size(), 1);
}

/**
 * @tc.name  : Test StartMovingPhotoStream API
 * @tc.number: StartMovingPhotoStream_001
 * @tc.desc  : Test StartMovingPhotoStream API, when isSetMotionPhoto_ is true
 */
HWTEST_F(HStreamOperatorUnitTest, StartMovingPhotoStream_001, TestSize.Level0)
{
    auto ret = streamOp_->streamContainer_.AddStream(GenStreamRepeat(RepeatStreamType::PREVIEW));
    EXPECT_TRUE(ret);
    ret = streamOp_->streamContainer_.AddStream(GenStreamRepeat(RepeatStreamType::LIVEPHOTO));
    EXPECT_TRUE(ret);
    streamOp_->isSetMotionPhoto_ = true;
    streamOp_->StartMovingPhotoStream(nullptr);
}

/**
 * @tc.name  : Test StartMovingPhotoStream API
 * @tc.number: StartMovingPhotoStream_002
 * @tc.desc  : Test StartMovingPhotoStream API, when isSetMotionPhoto_ is false
 */
HWTEST_F(HStreamOperatorUnitTest, StartMovingPhotoStream_002, TestSize.Level0)
{
    auto ret = streamOp_->streamContainer_.AddStream(GenStreamRepeat(RepeatStreamType::PREVIEW));
    EXPECT_TRUE(ret);
    ret = streamOp_->streamContainer_.AddStream(GenStreamRepeat(RepeatStreamType::LIVEPHOTO));
    EXPECT_TRUE(ret);
    streamOp_->isSetMotionPhoto_ = false;
    streamOp_->StartMovingPhotoStream(nullptr);
}

/**
 * @tc.name  : Test RegisterDisplayListener API
 * @tc.number: RegisterDisplayListener_001
 * @tc.desc  : Test RegisterDisplayListener API, when displayListener_ is not nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, RegisterDisplayListener_001, TestSize.Level0)
{
    sptr<HStreamOperator::DisplayRotationListener> listener(new HStreamOperator::DisplayRotationListener());
    streamOp_->displayListener_ = listener;
    streamOp_->RegisterDisplayListener(GenStreamRepeat(RepeatStreamType::PREVIEW));
    EXPECT_NE(streamOp_->displayListener_, nullptr);
}

/**
 * @tc.name  : Test RegisterDisplayListener API
 * @tc.number: RegisterDisplayListener_002
 * @tc.desc  : Test RegisterDisplayListener API, when displayListener_ is nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, RegisterDisplayListener_002, TestSize.Level0)
{
    streamOp_->displayListener_ = nullptr;
    streamOp_->RegisterDisplayListener(GenStreamRepeat(RepeatStreamType::PREVIEW));
    EXPECT_NE(streamOp_->displayListener_, nullptr);
}

/**
 * @tc.name  : Test AddOutput API
 * @tc.number: AddOutput_001
 * @tc.desc  : Test AddOutput API, when stream is nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, AddOutput_001, TestSize.Level1)
{
    auto rc = streamOp_->AddOutput(StreamType::CAPTURE, nullptr);
    EXPECT_EQ(rc, CAMERA_INVALID_ARG);
}

/**
 * @tc.name  : Test AddOutput API
 * @tc.number: AddOutput_002
 * @tc.desc  : Test AddOutput API, when StreamType is invalid
 */
HWTEST_F(HStreamOperatorUnitTest, AddOutput_002, TestSize.Level1)
{
    auto rc = streamOp_->AddOutput(static_cast<StreamType>(0), GenStreamCapture());
    EXPECT_EQ(rc, CAMERA_INVALID_ARG);
}

/**
 * @tc.name  : Test RemoveOutput API
 * @tc.number: RemoveOutput_001
 * @tc.desc  : Test RemoveOutput API, when stream is nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, RemoveOutput_001, TestSize.Level1)
{
    auto rc = streamOp_->RemoveOutput(StreamType::CAPTURE, nullptr);
    EXPECT_EQ(rc, CAMERA_INVALID_ARG);
}

/**
 * @tc.name  : Test RemoveOutput API
 * @tc.number: RemoveOutput_002
 * @tc.desc  : Test RemoveOutput API, when StreamType is invalid
 */
HWTEST_F(HStreamOperatorUnitTest, RemoveOutput_002, TestSize.Level1)
{
    auto rc = streamOp_->RemoveOutput(static_cast<StreamType>(0), nullptr);
    EXPECT_EQ(rc, CAMERA_INVALID_ARG);
}

/**
 * @tc.name  : Test RemoveOutput API
 * @tc.number: RemoveOutput_003
 * @tc.desc  : Test RemoveOutput API, when StreamType is METAdATA
 */
HWTEST_F(HStreamOperatorUnitTest, RemoveOutput_003, TestSize.Level1)
{
    auto streamMetadata = GenStreamMetadata();
    auto rc = streamOp_->RemoveOutput(StreamType::METADATA, streamMetadata);
    EXPECT_EQ(rc, CAMERA_INVALID_SESSION_CFG);
}

/**
 * @tc.name  : Test RemoveOutput API
 * @tc.number: RemoveOutput_004
 * @tc.desc  : Test RemoveOutput API, when StreamType is CAPTURE
 */
HWTEST_F(HStreamOperatorUnitTest, RemoveOutput_004, TestSize.Level1)
{
    auto streamCapture = GenStreamCapture();
    auto rc = streamOp_->RemoveOutput(StreamType::CAPTURE, streamCapture);
    EXPECT_EQ(rc, CAMERA_INVALID_SESSION_CFG);
}

/**
 * @tc.name  : Test GetStreamOperator API
 * @tc.number: GetStreamOperator_001
 * @tc.desc  : Test GetStreamOperator API, when cameraDevice_ is nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, GetStreamOperator_001, TestSize.Level1)
{
    streamOp_->cameraDevice_ = nullptr;
    streamOp_->GetStreamOperator();
    EXPECT_EQ(streamOp_->cameraDevice_, nullptr);
}

/**
 * @tc.name  : Test GetHdiStreamByStreamID API
 * @tc.number: GetHdiStreamByStreamID_001
 * @tc.desc  : Test GetHdiStreamByStreamID API, when stream is nullptr(not found stream by id)
 */
HWTEST_F(HStreamOperatorUnitTest, GetHdiStreamByStreamID_001, TestSize.Level1)
{
    streamOp_->streamContainer_.Clear();
    auto ret = streamOp_->GetHdiStreamByStreamID(0);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name  : Test SetColorSpace API
 * @tc.number: SetColorSpace_001
 * @tc.desc  : Test SetColorSpace API, when result is CAMERA_OK
 */
HWTEST_F(HStreamOperatorUnitTest, SetColorSpace_001, TestSize.Level1)
{
    streamOp_->currColorSpace_ = COLOR_SPACE_UNKNOWN;
    auto rc = streamOp_->SetColorSpace(ColorSpace::BT709, true);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test CancelStreamsAndGetStreamInfos API
 * @tc.number: CancelStreamsAndGetStreamInfos_001
 * @tc.desc  : Test CancelStreamsAndGetStreamInfos API, when isSessionStarted_ is true
 */
HWTEST_F(HStreamOperatorUnitTest, CancelStreamsAndGetStreamInfos_001, TestSize.Level1)
{
    streamOp_->isSessionStarted_ = true;

    streamOp_->streamContainer_.AddStream(GenStreamCapture());
    streamOp_->streamContainer_.AddStream(GenStreamRepeat(RepeatStreamType::PREVIEW));
    std::vector<StreamInfo_V1_5> streamInfos;
    streamOp_->CancelStreamsAndGetStreamInfos(streamInfos);
    EXPECT_FALSE(streamInfos.empty());
}

/**
 * @tc.name  : Test CancelStreamsAndGetStreamInfos API
 * @tc.number: CancelStreamsAndGetStreamInfos_002
 * @tc.desc  : Test CancelStreamsAndGetStreamInfos API, when isSessionStarted_ is false
 */
HWTEST_F(HStreamOperatorUnitTest, CancelStreamsAndGetStreamInfos_002, TestSize.Level1)
{
    streamOp_->isSessionStarted_ = false;

    streamOp_->streamContainer_.AddStream(GenStreamCapture());
    streamOp_->streamContainer_.AddStream(GenStreamRepeat(RepeatStreamType::PREVIEW));
    std::vector<StreamInfo_V1_5> streamInfos;
    streamOp_->CancelStreamsAndGetStreamInfos(streamInfos);
    EXPECT_FALSE(streamInfos.empty());
}

/**
 * @tc.name  : Test StartPreviewStream API
 * @tc.number: StartPreviewStream_001
 * @tc.desc  : Test StartPreviewStream API, when repeatType != PREVIEW or LIVEPHOTO
 */
HWTEST_F(HStreamOperatorUnitTest, StartPreviewStream_001, TestSize.Level1)
{
    auto streamRep = GenStreamRepeat(RepeatStreamType::SKETCH);
    streamOp_->streamContainer_.AddStream(streamRep);
    auto rc = streamOp_->StartPreviewStream(nullptr, camera_position_enum_t::OHOS_CAMERA_POSITION_BACK);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test StartPreviewStream API
 * @tc.number: StartPreviewStream_002
 * @tc.desc  : Test StartPreviewStream API, when repeatType == PREVIEW and CaptureId != CAPTURE_ID_UNSET
 */
HWTEST_F(HStreamOperatorUnitTest, StartPreviewStream_002, TestSize.Level1)
{
    auto streamRep = GenStreamRepeat(RepeatStreamType::PREVIEW);
    streamRep->curCaptureID_ = 999;
    streamOp_->streamContainer_.AddStream(streamRep);
    auto rc = streamOp_->StartPreviewStream(nullptr, camera_position_enum_t::OHOS_CAMERA_POSITION_BACK);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test Stop API
 * @tc.number: Stop_001
 * @tc.desc  : Test Stop API, when StreamType is DEPTH
 */
HWTEST_F(HStreamOperatorUnitTest, Stop_001, TestSize.Level1)
{
    streamOp_->streamContainer_.AddStream(GenStreamDepthData());
    auto rc = streamOp_->Stop();
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test Stop API
 * @tc.number: Stop_002
 * @tc.desc  : Test Stop API, when StreamType is invalid
 */
HWTEST_F(HStreamOperatorUnitTest, Stop_002, TestSize.Level1)
{
    auto streamDepth = GenStreamDepthData();
    streamDepth->streamType_ = static_cast<StreamType>(0);
    streamOp_->streamContainer_.AddStream(streamDepth);
    auto rc = streamOp_->Stop();
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test ReleaseStreams API
 * @tc.number: ReleaseStreams_001
 * @tc.desc  : Test ReleaseStreams API, when stream IsHasSwitchToOffline
 */
HWTEST_F(HStreamOperatorUnitTest, ReleaseStreams_001, TestSize.Level1)
{
    auto streamCap = GenStreamCapture();
    streamCap->mSwitchToOfflinePhoto_ = true;
    streamOp_->ReleaseStreams();
    EXPECT_TRUE(streamCap->mSwitchToOfflinePhoto_);
}

/**
 * @tc.name  : Test ReleaseStreams API
 * @tc.number: ReleaseStreams_002
 * @tc.desc  : Test ReleaseStreams API, when IsHasSwitchToOffline is false and fwkStreamId == STREAM_ID_UNSET
 */
HWTEST_F(HStreamOperatorUnitTest, ReleaseStreams_002, TestSize.Level1)
{
    auto streamCap = GenStreamCapture();
    streamCap->mSwitchToOfflinePhoto_ = false;
    streamCap->fwkStreamId_ = STREAM_ID_UNSET;
    streamOp_->ReleaseStreams();
    EXPECT_EQ(streamCap->fwkStreamId_, STREAM_ID_UNSET);
}

/**
 * @tc.name  : Test ReleaseStreams API
 * @tc.number: ReleaseStreams_003
 * @tc.desc  : Test ReleaseStreams API, when fwkStreamId != STREAM_ID_UNSET and hdiStreamId != STREAM_ID_UNSET
 */
HWTEST_F(HStreamOperatorUnitTest, ReleaseStreams_003, TestSize.Level1)
{
    auto streamCap = GenStreamCapture();
    streamCap->mSwitchToOfflinePhoto_ = false;
    streamCap->fwkStreamId_ = 100;
    streamCap->hdiStreamId_ = 200;
    streamOp_->ReleaseStreams();
    EXPECT_NE(streamCap->hdiStreamId_, STREAM_ID_UNSET);
}

/**
 * @tc.name  : Test ReleaseStreams API
 * @tc.number: ReleaseStreams_004
 * @tc.desc  : Test ReleaseStreams API, when streamType is't CAPTURE
 */
HWTEST_F(HStreamOperatorUnitTest, ReleaseStreams_004, TestSize.Level1)
{
    auto streamDepth = GenStreamDepthData();
    streamDepth->fwkStreamId_ = 100;
    streamDepth->hdiStreamId_ = 200;
    streamOp_->ReleaseStreams();
    EXPECT_NE(streamDepth->hdiStreamId_, STREAM_ID_UNSET);
}

/**
 * @tc.name  : Test EnableMovingPhotoMirror API
 * @tc.number: EnableMovingPhotoMirror_001
 * @tc.desc  : Test EnableMovingPhotoMirror API, when isConfig is false
 */
HWTEST_F(HStreamOperatorUnitTest, EnableMovingPhotoMirror_001, TestSize.Level1)
{
    auto rc = streamOp_->EnableMovingPhotoMirror(true, false);
    EXPECT_NE(rc, CAMERA_OK);
    EXPECT_NE(streamOp_->isMovingPhotoMirror_, true);
}

/**
 * @tc.name  : Test OnCaptureStarted API
 * @tc.number: OnCaptureStarted_001
 * @tc.desc  : Test OnCaptureStarted API, when streamType is invalid(DEPTH)
 */
HWTEST_F(HStreamOperatorUnitTest, OnCaptureStarted_001, TestSize.Level1)
{
    auto depthStream = GenStreamDepthData();
    const int32_t STREAM_ID = 999;
    depthStream->hdiStreamId_ = STREAM_ID;
    streamOp_->streamContainer_.AddStream(depthStream);
    auto rc = streamOp_->OnCaptureStarted(1, { STREAM_ID });
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test OnCaptureStarted_V1_2 API
 * @tc.number: OnCaptureStarted_V1_2_001
 * @tc.desc  : Test OnCaptureStarted_V1_2 API, when StreamType is't CAPTURE
 */
HWTEST_F(HStreamOperatorUnitTest, OnCaptureStarted_V1_2_001, TestSize.Level1)
{
    const int32_t STREAM_ID = 999;
    const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> infos { { STREAM_ID, 0 } };

    auto depthStream = GenStreamDepthData();
    depthStream->hdiStreamId_ = STREAM_ID;
    streamOp_->streamContainer_.AddStream(depthStream);
    auto rc = streamOp_->OnCaptureStarted_V1_2(0, infos);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test GetOutputStatus API
 * @tc.number: GetOutputStatus_001
 * @tc.desc  : Test GetOutputStatus API, when streamType != VIDEO
 */
HWTEST_F(HStreamOperatorUnitTest, GetOutputStatus_001, TestSize.Level1)
{
    auto streamRep = GenStreamRepeat(RepeatStreamType::LIVEPHOTO);
    int32_t status = 0;
    streamOp_->GetOutputStatus(status);
    EXPECT_EQ(status, 0);
}

/**
 * @tc.name  : Test GetOutputStatus API
 * @tc.number: GetOutputStatus_002
 * @tc.desc  : Test GetOutputStatus API, when streamType == VIDEO and captureId == CAPTURE_ID_UNSET
 */
HWTEST_F(HStreamOperatorUnitTest, GetOutputStatus_002, TestSize.Level1)
{
    auto streamRep = GenStreamRepeat(RepeatStreamType::VIDEO);
    streamRep->curCaptureID_ = CAPTURE_ID_UNSET;
    streamOp_->streamContainer_.AddStream(streamRep);
    int32_t status = 0;
    streamOp_->GetOutputStatus(status);
    EXPECT_EQ(status, 0);
}

/**
 * @tc.name  : Test GetOutputStatus API
 * @tc.number: GetOutputStatus_002
 * @tc.desc  : Test GetOutputStatus API, when streamType == VIDEO and captureId != CAPTURE_ID_UNSET
 */
HWTEST_F(HStreamOperatorUnitTest, GetOutputStatus_003, TestSize.Level0)
{
    auto streamRep = GenStreamRepeat(RepeatStreamType::VIDEO);
    streamRep->curCaptureID_ = 1;
    streamOp_->streamContainer_.AddStream(streamRep);
    int32_t status = 0;
    streamOp_->GetOutputStatus(status);
    EXPECT_EQ(status, 2);
}

/**
 * @tc.name  : Test RegisterSensorCallback API
 * @tc.number: RegisterSensorCallback_001
 * @tc.desc  : Test RegisterSensorCallback API, when isRegisterSensorSuccess_ is true
 */
HWTEST_F(HStreamOperatorUnitTest, RegisterSensorCallback_001, TestSize.Level1)
{
    streamOp_->isRegisterSensorSuccess_ = true;
    streamOp_->RegisterSensorCallback();
    EXPECT_EQ(streamOp_->isRegisterSensorSuccess_, true);
}

/**
 * @tc.name  : Test RegisterSensorCallback API
 * @tc.number: RegisterSensorCallback_002
 * @tc.desc  : Test RegisterSensorCallback API, when isRegisterSensorSuccess_ is false
 */
HWTEST_F(HStreamOperatorUnitTest, RegisterSensorCallback_002, TestSize.Level1)
{
    streamOp_->isRegisterSensorSuccess_ = false;
    streamOp_->RegisterSensorCallback();
    EXPECT_EQ(streamOp_->isRegisterSensorSuccess_, true);
}

/**
 * @tc.name  : Test CalcSensorRotation API
 * @tc.number: CalcSensorRotation_001
 * @tc.desc  : Test CalcSensorRotation API, when return STREAM_ROTATE_0
 */
HWTEST_F(HStreamOperatorUnitTest, CalcSensorRotation_001, TestSize.Level0)
{
    EXPECT_EQ(streamOp_->CalcSensorRotation(0), STREAM_ROTATE_0);
    EXPECT_EQ(streamOp_->CalcSensorRotation(15), STREAM_ROTATE_0);
    EXPECT_EQ(streamOp_->CalcSensorRotation(30), STREAM_ROTATE_0);
    EXPECT_EQ(streamOp_->CalcSensorRotation(330), STREAM_ROTATE_0);
    EXPECT_EQ(streamOp_->CalcSensorRotation(359), STREAM_ROTATE_0);
}

/**
 * @tc.name  : Test CalcSensorRotation API
 * @tc.number: CalcSensorRotation_002
 * @tc.desc  : Test CalcSensorRotation API, when return STREAM_ROTATE_90
 */
HWTEST_F(HStreamOperatorUnitTest, CalcSensorRotation_002, TestSize.Level0)
{
    EXPECT_EQ(streamOp_->CalcSensorRotation(60), STREAM_ROTATE_90);
    EXPECT_EQ(streamOp_->CalcSensorRotation(90), STREAM_ROTATE_90);
    EXPECT_EQ(streamOp_->CalcSensorRotation(120), STREAM_ROTATE_90);
}

/**
 * @tc.name  : Test CalcSensorRotation API
 * @tc.number: CalcSensorRotation_003
 * @tc.desc  : Test CalcSensorRotation API, when return STREAM_ROTATE_180
 */
HWTEST_F(HStreamOperatorUnitTest, CalcSensorRotation_003, TestSize.Level0)
{
    EXPECT_EQ(streamOp_->CalcSensorRotation(150), STREAM_ROTATE_180);
    EXPECT_EQ(streamOp_->CalcSensorRotation(180), STREAM_ROTATE_180);
    EXPECT_EQ(streamOp_->CalcSensorRotation(210), STREAM_ROTATE_180);
}

/**
 * @tc.name  : Test CalcSensorRotation API
 * @tc.number: CalcSensorRotation_004
 * @tc.desc  : Test CalcSensorRotation API, when return STREAM_ROTATE_270
 */
HWTEST_F(HStreamOperatorUnitTest, CalcSensorRotation_004, TestSize.Level0)
{
    EXPECT_EQ(streamOp_->CalcSensorRotation(240), STREAM_ROTATE_270);
    EXPECT_EQ(streamOp_->CalcSensorRotation(270), STREAM_ROTATE_270);
    EXPECT_EQ(streamOp_->CalcSensorRotation(300), STREAM_ROTATE_270);
}

/**
 * @tc.name  : Test CalcSensorRotation API
 * @tc.number: CalcSensorRotation_005
 * @tc.desc  : Test CalcSensorRotation API, when sensorDegree is invalid
 */
HWTEST_F(HStreamOperatorUnitTest, CalcSensorRotation_005, TestSize.Level1)
{
    int32_t sensorRotation = -1;
    EXPECT_EQ(streamOp_->CalcSensorRotation(sensorRotation), 0);
}

/**
 * @tc.name  : Test CalcRotationDegree API
 * @tc.number: CalcRotationDegree_001
 * @tc.desc  : Test CalcRotationDegree API, when fn return invalid degree
 */
HWTEST_F(HStreamOperatorUnitTest, CalcRotationDegree_001, TestSize.Level1)
{
    GravityData data = { 1.0f, 1.0f, 4.0f }; // (x * x + y * y) * VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT < z * z
    EXPECT_EQ(streamOp_->CalcRotationDegree(data), -1);
}

/**
 * @tc.name  : Test CalcRotationDegree API
 * @tc.number: CalcRotationDegree_002
 * @tc.desc  : Test CalcRotationDegree API, when fn return normal degree
 */
HWTEST_F(HStreamOperatorUnitTest, CalcRotationDegree_002, TestSize.Level0)
{
    GravityData data = { 1.0f, 1.0f, 1.0f };
    EXPECT_NE(streamOp_->CalcRotationDegree(data), -1);
}

/**
 * @tc.name  : Test StartMovingPhotoEncode API
 * @tc.number: StartMovingPhotoEncode_001
 * @tc.desc  : Test StartMovingPhotoEncode API, when isSetMotionPhoto_ is false
 */
HWTEST_F(HStreamOperatorUnitTest, StartMovingPhotoEncode_001, TestSize.Level1)
{
    streamOp_->isSetMotionPhoto_ = false;
    streamOp_->StartMovingPhotoEncode(STREAM_ROTATE_0, 0, 0, 0);
    EXPECT_FALSE(streamOp_->isSetMotionPhoto_);
}

/**
 * @tc.name  : Test StartMovingPhotoEncode API
 * @tc.number: StartMovingPhotoEncode_002
 * @tc.desc  : Test StartMovingPhotoEncode API, when isHorizontal
 */
HWTEST_F(HStreamOperatorUnitTest, StartMovingPhotoEncode_002, TestSize.Level1)
{
    streamOp_->isSetMotionPhoto_ = true;
    streamOp_->isMovingPhotoMirror_ = true;
    streamOp_->StartMovingPhotoEncode(STREAM_ROTATE_0, 0, 0, 0);
    EXPECT_TRUE(streamOp_->isSetMotionPhoto_);
}

/**
 * @tc.name  : Test SetCameraPhotoProxyInfo API
 * @tc.number: SetCameraPhotoProxyInfo_001
 * @tc.desc  : Test SetCameraPhotoProxyInfo API, when isBursting
 */
HWTEST_F(HStreamOperatorUnitTest, SetCameraPhotoProxyInfo_001, TestSize.Level1)
{
    sptr<CameraServerPhotoProxy> proxy{new CameraServerPhotoProxy()};
    int32_t cameraShotType;
    bool isBursting;
    std::string burstKey;

    auto capStream = GenStreamCapture();
    capStream->burstkeyMap_[proxy->GetCaptureId()] = "key";
    streamOp_->streamContainer_.AddStream(capStream);
    streamOp_->SetCameraPhotoProxyInfo(proxy, cameraShotType, isBursting, burstKey);
    EXPECT_EQ(burstKey, "key");
}

/**
 * @tc.name  : Test OnCaptureError API
 * @tc.number: OnCaptureError_001
 * @tc.desc  : Test OnCaptureError API, when StreamType is REPEAT
 */
HWTEST_F(HStreamOperatorUnitTest, OnCaptureError_001, TestSize.Level1)
{
    auto streamRep = GenStreamRepeat(RepeatStreamType::PREVIEW);
    const int32_t STREAM_ID = 999;
    streamRep->hdiStreamId_ = STREAM_ID;
    streamOp_->streamContainer_.AddStream(streamRep);

    std::vector<CaptureErrorInfo> infos { { .streamId_ = STREAM_ID,
        .error_ = OHOS::HDI::Camera::V1_0::StreamError::UNKNOWN_ERROR } };
    auto rc = streamOp_->OnCaptureError(0, infos);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test OnCaptureError API
 * @tc.number: OnCaptureError_002
 * @tc.desc  : Test OnCaptureError API, when StreamType is CAPTURE
 */
HWTEST_F(HStreamOperatorUnitTest, OnCaptureError_002, TestSize.Level1)
{
    auto streamCap = GenStreamCapture();
    const int32_t STREAM_ID = 999;
    streamCap->hdiStreamId_ = STREAM_ID;
    streamOp_->streamContainer_.AddStream(streamCap);

    std::vector<CaptureErrorInfo> infos { { .streamId_ = STREAM_ID,
        .error_ = OHOS::HDI::Camera::V1_0::StreamError::UNKNOWN_ERROR } };
    auto rc = streamOp_->OnCaptureError(0, infos);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test OnCaptureError API
 * @tc.number: OnCaptureError_003
 * @tc.desc  : Test OnCaptureError API, when StreamType is INVALID
 */
HWTEST_F(HStreamOperatorUnitTest, OnCaptureError_003, TestSize.Level1)
{
    auto streamCap = GenStreamCapture();
    streamCap->streamType_ = static_cast<StreamType>(0);
    const int32_t STREAM_ID = 999;
    streamCap->hdiStreamId_ = STREAM_ID;
    streamOp_->streamContainer_.AddStream(streamCap);

    std::vector<CaptureErrorInfo> infos { { .streamId_ = STREAM_ID,
        .error_ = OHOS::HDI::Camera::V1_0::StreamError::UNKNOWN_ERROR } };
    auto rc = streamOp_->OnCaptureError(0, infos);
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test AddStream API
 * @tc.number: AddStream_001
 * @tc.desc  : Test AddStream API, when stream is added twice
 */
HWTEST_F(HStreamOperatorUnitTest, AddStream_001, TestSize.Level0)
{
    auto depthStream = GenStreamDepthData();
    auto rc = streamOp_->streamContainer_.AddStream(depthStream);
    EXPECT_EQ(rc, true);
    // add twice
    rc = streamOp_->streamContainer_.AddStream(depthStream);
    EXPECT_EQ(rc, false);
}

/**
 * @tc.name  : Test GetStream API
 * @tc.number: GetStream_001
 * @tc.desc  : Test GetStream API, when stream is found
 */
HWTEST_F(HStreamOperatorUnitTest, GetStream_001, TestSize.Level0)
{
    auto streamCap = GenStreamCapture();
    const int32_t STREAM_ID = 999;
    streamCap->fwkStreamId_ = STREAM_ID;
    auto rc = streamOp_->streamContainer_.AddStream(streamCap);
    ASSERT_TRUE(rc);
    auto ret = streamOp_->streamContainer_.GetStream(STREAM_ID);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name  : Test GetStream API
 * @tc.number: GetStream_002
 * @tc.desc  : Test GetStream API, when stream is't found
 */
HWTEST_F(HStreamOperatorUnitTest, GetStream_002, TestSize.Level0)
{
    auto streamCap = GenStreamCapture();
    const int32_t STREAM_ID = 999;
    streamCap->fwkStreamId_ = STREAM_ID;
    auto rc = streamOp_->streamContainer_.AddStream(streamCap);
    ASSERT_TRUE(rc);
    auto ret = streamOp_->streamContainer_.GetStream(0);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name  : Test GetSupportRedoXtStyle API
 * @tc.number: GetSupportRedoXtStyle_001
 * @tc.desc  : Test GetSupportRedoXtStyle API, supportXtStyleRedoFlag_ is already initialized
 */
HWTEST_F(HStreamOperatorUnitTest, GetSupportRedoXtStyle_001, TestSize.Level0)
{
    streamOp_->supportXtStyleRedoFlag_ = ColorStylePhotoType::EFFECT;
    EXPECT_EQ(streamOp_->GetSupportRedoXtStyle(), ColorStylePhotoType::EFFECT);
}

/**
 * @tc.name  : Test GetSupportRedoXtStyle API
 * @tc.number: GetSupportRedoXtStyle_002
 * @tc.desc  : Test GetSupportRedoXtStyle API, cameraDevice_  is nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, GetSupportRedoXtStyle_002, TestSize.Level0)
{
    streamOp_->cameraDevice_ = nullptr;
    ColorStylePhotoType flag = streamOp_->GetSupportRedoXtStyle();
    EXPECT_EQ(flag, ColorStylePhotoType::UNSET);
}
} // namespace CameraStandard
} // namespace OHOS