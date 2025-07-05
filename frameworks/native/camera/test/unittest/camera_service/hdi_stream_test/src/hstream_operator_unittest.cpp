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
#include "moving_photo_proxy.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hstream_capture.h"
#include "stream_capture_callback_stub.h"
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
    CHECK_ERROR_RETURN_RET_LOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamCapture> stream = new (std::nothrow) HStreamCapture(producer, format, w, h);
    return stream;
}

sptr<HStreamMetadata> HStreamOperatorUnitTest::GenSteamMetadata(std::vector<int32_t> metadataTypes)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_RET_LOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamMetadata> stream = new (std::nothrow) HStreamMetadata(producer, format, {});
    return stream;
}

sptr<HStreamRepeat> HStreamOperatorUnitTest::GenSteamRepeat(RepeatStreamType type, int32_t w, int32_t h)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_RET_LOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamRepeat> stream = new (std::nothrow) HStreamRepeat(producer, format, w, h, type);
    return stream;
}

sptr<HStreamDepthData> HStreamOperatorUnitTest::GenSteamDepthData(int32_t w, int32_t h)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_RET_LOG(!surface, nullptr, "surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(!producer, nullptr, "producer is nullptr");
    sptr<HStreamDepthData> stream = new (std::nothrow) HStreamDepthData(producer, format, w, h);
    return stream;
}

/**
 * @tc.name  : Test GetCurrentStreamInfos API
 * @tc.number: GetCurrentStreamInfos_001
 * @tc.desc  : Test GetCurrentStreamInfos API, when steamType == METADATA
 */
HWTEST_F(HStreamOperatorUnitTest, GetCurrentStreamInfos_001, TestSize.Level1)
{
    streamOp_->streamContainer_.AddStream(GenSteamMetadata());
    std::vector<StreamInfo_V1_1> streamInfos;
    auto rc = streamOp_->GetCurrentStreamInfos(streamInfos);
    EXPECT_EQ(rc, CAMERA_OK);
    EXPECT_TRUE(streamInfos.empty());
}

/**
 * @tc.name  : Test GetCurrentStreamInfos API
 * @tc.number: GetCurrentStreamInfos_002
 * @tc.desc  : Test GetCurrentStreamInfos API, when steamType == METADATA
 */
HWTEST_F(HStreamOperatorUnitTest, GetCurrentStreamInfos_002, TestSize.Level1)
{
    streamOp_->streamContainer_.AddStream(GenStreamCapture());
    std::vector<StreamInfo_V1_1> streamInfos;
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
    streamOp_->streamContainer_.AddStream(GenSteamRepeat(RepeatStreamType::PREVIEW));
    streamOp_->streamContainer_.AddStream(GenSteamRepeat(RepeatStreamType::LIVEPHOTO));
    streamOp_->isSetMotionPhoto_ = true;
    streamOp_->StartMovingPhotoStream(nullptr);
}

/**
 * @tc.name  : Test StartMovingPhotoStream API
 * @tc.number: StartMovingPhotoStream_002
 * @tc.desc  : Test StartMovingPhotoStream API, when isSetMotionPhoto_ is true
 */
HWTEST_F(HStreamOperatorUnitTest, StartMovingPhotoStream_002, TestSize.Level0)
{
    streamOp_->streamContainer_.AddStream(GenSteamRepeat(RepeatStreamType::PREVIEW));
    streamOp_->streamContainer_.AddStream(GenSteamRepeat(RepeatStreamType::LIVEPHOTO));
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
    streamOp_->RegisterDisplayListener(GenSteamRepeat(RepeatStreamType::PREVIEW));
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
    streamOp_->RegisterDisplayListener(GenSteamRepeat(RepeatStreamType::PREVIEW));
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
 * @tc.number: RemoveOutput_002
 * @tc.desc  : Test RemoveOutput API, when StreamType is METAdATA
 */
HWTEST_F(HStreamOperatorUnitTest, RemoveOutput_003, TestSize.Level1)
{
    auto streamMetadata = GenSteamMetadata();
    auto rc = streamOp_->RemoveOutput(StreamType::METADATA, streamMetadata);
    EXPECT_EQ(rc, CAMERA_INVALID_SESSION_CFG);
}

/**
 * @tc.name  : Test CreateMovingPhotoStreamRepeat API
 * @tc.number: CreateMovingPhotoStreamRepeat_001
 * @tc.desc  : Test CreateMovingPhotoStreamRepeat API, when CreateMovingPhotoStreamRepeat is not nullptr
 */
HWTEST_F(HStreamOperatorUnitTest, CreateMovingPhotoStreamRepeat_001, TestSize.Level1)
{
    streamOp_->livePhotoStreamRepeat_ = GenSteamRepeat(RepeatStreamType::LIVEPHOTO);
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    ASSERT_EQ(streamOp_->metaSurface_, nullptr);
    auto rc = streamOp_->CreateMovingPhotoStreamRepeat(0, PHOTO_DEFAULT_WIDTH, PHOTO_DEFAULT_HEIGHT, producer);
    EXPECT_EQ(rc, CAMERA_INVALID_STATE);
    EXPECT_NE(streamOp_->livePhotoStreamRepeat_, nullptr);
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
    streamOp_->streamContainer_.AddStream(GenSteamRepeat(RepeatStreamType::PREVIEW));
    std::vector<StreamInfo_V1_1> streamInfos;
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
    streamOp_->streamContainer_.AddStream(GenSteamRepeat(RepeatStreamType::PREVIEW));
    std::vector<StreamInfo_V1_1> streamInfos;
    streamOp_->CancelStreamsAndGetStreamInfos(streamInfos);
    EXPECT_FALSE(streamInfos.empty());
}

/**
 * @tc.name  : Test Stop API
 * @tc.number: Stop_001
 * @tc.desc  : Test Stop API, when StreamType is DEPTH
 */
HWTEST_F(HStreamOperatorUnitTest, Stop_001, TestSize.Level1)
{
    streamOp_->streamContainer_.AddStream(GenSteamDepthData());
    auto rc = streamOp_->Stop();
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test Stop API
 * @tc.number: Stop_002
 * @tc.desc  : Test Stop API, when StreamType is Invalid
 */
HWTEST_F(HStreamOperatorUnitTest, Stop_002, TestSize.Level1)
{
    auto stream = GenSteamDepthData();
    stream->streamType_ = static_cast<StreamType>(0);
    streamOp_->streamContainer_.AddStream(GenSteamDepthData());
    auto rc = streamOp_->Stop();
    EXPECT_EQ(rc, CAMERA_OK);
}

/**
 * @tc.name  : Test ReleaseStreams API
 * @tc.number: ReleaseStreams_001
 * @tc.desc  : Test ReleaseStreams API, when stream->IsHasSwitchToOffline() is true
 */
HWTEST_F(HStreamOperatorUnitTest, ReleaseStreams_001, TestSize.Level1)
{
    auto stream = GenStreamCapture();
    stream->mSwitchToOfflinePhoto_ = true;
    streamOp_->streamContainer_.AddStream(GenSteamDepthData());
    streamOp_->ReleaseStreams();
    EXPECT_NE(streamOp_->streamContainer_.Size(), 0);
}

/**
 * @tc.name  : Test EnableMovingPhotoMirror API
 * @tc.number: EnableMovingPhotoMirror_001
 * @tc.desc  : Test EnableMovingPhotoMirror API, when isConfig is false
 */
HWTEST_F(HStreamOperatorUnitTest, EnableMovingPhotoMirror_001, TestSize.Level1)
{
    auto rc = streamOp_->EnableMovingPhotoMirror(true, false);
    EXPECT_EQ(rc, CAMERA_OK);
    EXPECT_EQ(streamOp_->isMovingPhotoMirror_, true);
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
 * @tc.desc  : Test CalcRotationDegree API, when return invalid degree
 */
HWTEST_F(HStreamOperatorUnitTest, CalcRotationDegree_001, TestSize.Level1)
{
    GravityData data = { 1.0f, 1.0f, 4.0f }; // (x * x + y * y) * VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT < z * z
    EXPECT_EQ(streamOp_->CalcRotationDegree(data), -1);
}

/**
 * @tc.name  : Test CalcRotationDegree API
 * @tc.number: CalcRotationDegree_002
 * @tc.desc  : Test CalcRotationDegree API, when return normal degree
 */
HWTEST_F(HStreamOperatorUnitTest, CalcRotationDegree_002, TestSize.Level0)
{
    GravityData data = { 1.0f, 1.0f, 1.0f };
    EXPECT_NE(streamOp_->CalcRotationDegree(data), -1);
}

/**
 * @tc.name  : Test SetSensorRotation API
 * @tc.number: SetSensorRotation_001
 * @tc.desc  : Test SetSensorRotation API, when cameraPosition is invalid
 */
HWTEST_F(HStreamOperatorUnitTest, SetSensorRotation_001, TestSize.Level1)
{
    int32_t cameraPosition = -1;
    streamOp_->sensorRotation_ = -999;
    streamOp_->SetSensorRotation(1, 2, cameraPosition);
    EXPECT_EQ(streamOp_->sensorRotation_, -999);
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
    sptr<MovingPhotoIntf> movingPhotoProxy = MovingPhotoProxy::CreateMovingPhotoProxy();
    movingPhotoProxy->CreateCameraServerProxy();
    int32_t cameraShotType;
    bool isBursting;
    std::string burstKey;

    auto capStream = GenStreamCapture();
    capStream->burstkeyMap_[movingPhotoProxy->GetCaptureId()] = "key";
    streamOp_->streamContainer_.AddStream(capStream);
    streamOp_->SetCameraPhotoProxyInfo(movingPhotoProxy, cameraShotType, isBursting, burstKey);
    EXPECT_EQ(burstKey, "key");
}

} // namespace CameraStandard
} // namespace OHOS
