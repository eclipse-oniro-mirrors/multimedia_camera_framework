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

#include "photo_output_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "picture_proxy.h"
#include "test_token.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

const int32_t VALUE_FOUR = 4;
const int32_t VALUE_ROTATION = 270;

void CameraPhotoOutputUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPhotoOutputUnit::TearDownTestCase(void) {}

void CameraPhotoOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
}

void CameraPhotoOutputUnit::TearDown()
{
    cameraManager_ = nullptr;
}

sptr<CaptureOutput> CameraPhotoOutputUnit::CreatePhotoOutput()
{
    std::vector<Profile> photoProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    if (!outputCapability) {
        return nullptr;
    }

    photoProfile = outputCapability->GetPhotoProfiles();
    if (photoProfile.empty()) {
        return nullptr;
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile[0], surfaceProducer);
}

MATCHER_P(matchCaptureSetting, captureSetting, "Match Capture Setting")
{
    std::vector<uint8_t> result;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureSetting, result);
    return (arg.captureSetting_ == result);
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetNativeSurface and SeteCallbackFlag
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetNativeSurface and SeteCallbackFlag when isEnableDeeferred is oppsite
 *          and session is start
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    bool isNativeSurface = true;
    phtOutput->SetNativeSurface(isNativeSurface);
    EXPECT_EQ(phtOutput->isNativeSurface_, true);

    phtOutput->callbackFlag_ = VALUE_FOUR;
    uint8_t callbackFlag = 1;
    phtOutput->SetCallbackFlag(callbackFlag);

    session->Stop();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test PhotoCaptureSetting with SetGpsLocation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoCaptureSetting with SetGpsLocation
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_033, TestSize.Level1)
{
    std::shared_ptr<PhotoCaptureSetting> settings = std::make_shared<PhotoCaptureSetting>();
    double latitude = 1.0;
    double longitude = 1.0;
    std::shared_ptr<Location> location = std::make_shared<Location>();
    location->latitude = latitude;
    location->longitude = longitude;
    settings->SetGpsLocation(latitude, longitude);
    EXPECT_EQ(settings->location_->latitude, location->latitude);
    EXPECT_EQ(settings->location_->longitude, location->longitude);
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetNativeSurface and SeteCallbackFlag
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetNativeSurface and SeteCallbackFlag when isEnableDeeferred is oppsite
 *          and session is commit
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    bool isNativeSurface = true;
    phtOutput->SetNativeSurface(isNativeSurface);
    EXPECT_EQ(phtOutput->isNativeSurface_, true);

    phtOutput->callbackFlag_ = VALUE_FOUR;
    uint8_t callbackFlag = 1;
    phtOutput->SetCallbackFlag(callbackFlag);

    session->Stop();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetNativeSurface and SeteCallbackFlag
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetNativeSurface and SeteCallbackFlag when isEnableDeeferred is not oppsite
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    bool isNativeSurface = true;
    phtOutput->SetNativeSurface(isNativeSurface);
    EXPECT_EQ(phtOutput->isNativeSurface_, true);

    phtOutput->callbackFlag_ = VALUE_FOUR;
    uint8_t callbackFlag = VALUE_FOUR;
    phtOutput->SetCallbackFlag(callbackFlag);
    EXPECT_NE(phtOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test photooutput with IsYuvOrHeifPhoto
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with IsYuvOrHeifPhoto when photoProfile_ is not nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    bool ret = phtOutput->IsYuvOrHeifPhoto();
    EXPECT_FALSE(ret);

    phtOutput->photoProfile_ = nullptr;
    ret = phtOutput->IsYuvOrHeifPhoto();
    EXPECT_EQ(ret, false);
}

/*
 * Feature: Framework
 * Function: Test photooutput with Set and Get AuxiliaryPhotoHandle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with Set and Get AuxiliaryPhotoHandle
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    uint32_t handle = 0;
    phtOutput->SetAuxiliaryPhotoHandle(handle);
    uint32_t ret = phtOutput->GetAuxiliaryPhotoHandle();
    EXPECT_EQ(ret, handle);
}

/*
 * Feature: Framework
 * Function: Test photooutput with CreateMultiChanneland and EnableRawDelivery
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with CreateMultiChannel and EnableRawDelivery when stream is not nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput->GetStream().GetRefPtr(), nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    phtOutput->gainmapSurface_ = nullptr;
    phtOutput->deepSurface_ = nullptr;
    phtOutput->exifSurface_ = nullptr;
    phtOutput->debugSurface_ = nullptr;
    phtOutput->rawPhotoSurface_ = nullptr;
    phtOutput->CreateMultiChannel();
    EXPECT_NE(phtOutput->gainmapSurface_, nullptr);
    if (phtOutput->isDepthBufferSupported_) {
        EXPECT_NE(phtOutput->deepSurface_, nullptr);
    }
    EXPECT_NE(phtOutput->exifSurface_, nullptr);
    EXPECT_NE(phtOutput->debugSurface_, nullptr);

    bool enabled = true;
    EXPECT_EQ(phtOutput->EnableRawDelivery(enabled), CameraErrorCode::SUCCESS);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with CreateMultiChannel
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with CreateMultiChannel when stream is nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_007, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    phtOutput->stream_ = nullptr;
    phtOutput->gainmapSurface_ = nullptr;
    phtOutput->deepSurface_ = nullptr;
    phtOutput->exifSurface_ = nullptr;
    phtOutput->debugSurface_ = nullptr;
    phtOutput->rawPhotoSurface_ = nullptr;
    phtOutput->CreateMultiChannel();
    EXPECT_EQ(phtOutput->gainmapSurface_, nullptr);
    EXPECT_EQ(phtOutput->deepSurface_, nullptr);
    EXPECT_EQ(phtOutput->exifSurface_, nullptr);
    EXPECT_EQ(phtOutput->debugSurface_, nullptr);

    bool enabled = true;
    phtOutput->EnableRawDelivery(enabled);
    EXPECT_EQ(phtOutput->rawPhotoSurface_, nullptr);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with CreateMultiChannel
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with CreateMultiChannel when surface is not nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_008, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput->GetStream().GetRefPtr(), nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    phtOutput->gainmapSurface_ = Surface::CreateSurfaceAsConsumer("gainmapImage");
    phtOutput->deepSurface_ = Surface::CreateSurfaceAsConsumer("deepSurface");
    phtOutput->exifSurface_ = Surface::CreateSurfaceAsConsumer("exifSurface");
    phtOutput->debugSurface_ = Surface::CreateSurfaceAsConsumer("debugSurface");
    phtOutput->rawPhotoSurface_ = Surface::CreateSurfaceAsConsumer("rawPhotoSurface");
    phtOutput->CreateMultiChannel();
    EXPECT_NE(phtOutput->gainmapSurface_, nullptr);
    EXPECT_NE(phtOutput->deepSurface_, nullptr);
    EXPECT_NE(phtOutput->exifSurface_, nullptr);
    EXPECT_NE(phtOutput->debugSurface_, nullptr);

    bool enabled = true;
    int32_t ret = phtOutput->EnableRawDelivery(enabled);
    EXPECT_EQ(ret, CAMERA_OK);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetThumbnailListener
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetThumbnailListener
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_009, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetThumbnail EnableAutoHighQualityPhoto and EnableMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetThumbnail EnableAutoHighQualityPhoto and EnableMirror
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_010, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    bool isEnabled = true;
    phtOutput->thumbnailSurface_ = Surface::CreateSurfaceAsConsumer("thumbnailSurface");
    int32_t ret = phtOutput->SetThumbnail(isEnabled);
    EXPECT_EQ(ret, CAMERA_OK);
    session->currentMode_ = SceneMode::PROFESSIONAL_PHOTO;
    ret = phtOutput->EnableMirror(isEnabled);
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);

    ret = phtOutput->EnableAutoHighQualityPhoto(isEnabled);
    EXPECT_EQ(ret, INVALID_ARGUMENT);

    isEnabled = false;
    ret = phtOutput->EnableMirror(isEnabled);
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);

    ret = phtOutput->EnableAutoHighQualityPhoto(isEnabled);
    EXPECT_EQ(ret, INVALID_ARGUMENT);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with IsQuickThumbnailSupported and IsRawDeliverySupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with IsQuickThumbnailSupported and IsRawDeliverySupported
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_011, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    session->currentMode_ = SceneMode::NIGHT;
    int32_t ret = phtOutput->IsQuickThumbnailSupported();
    EXPECT_EQ(ret, -1);

    session->currentMode_ =SceneMode::PROFESSIONAL_PHOTO;
    bool isEnable = true;
    ret = phtOutput->IsRawDeliverySupported(isEnable);
    EXPECT_EQ(ret, 0);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with DeferredImageDelivery
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with DeferredImageDelivery
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_012, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    DeferredDeliveryImageType type = DeferredDeliveryImageType::DELIVERY_VIDEO;
    DeferredDeliveryImageType type_1 = DeferredDeliveryImageType::DELIVERY_NONE;
    int32_t ret = phtOutput->DeferImageDeliveryFor(type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(phtOutput->IsDeferredImageDeliverySupported(type_1), -1);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branches with DeferredImageDelivery
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_013, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    DeferredDeliveryImageType type = DeferredDeliveryImageType::DELIVERY_PHOTO;
    int32_t ret = phtOutput->DeferImageDeliveryFor(type);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);
    EXPECT_EQ(phtOutput->IsDeferredImageDeliverySupported(type), CameraErrorCode::SESSION_NOT_RUNNING);

    phtOutput->session_ = session;
    type = DeferredDeliveryImageType::DELIVERY_PHOTO;
    ret = phtOutput->DeferImageDeliveryFor(type);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);
    EXPECT_EQ(phtOutput->IsDeferredImageDeliverySupported(type), CameraErrorCode::SESSION_NOT_RUNNING);

    phtOutput->session_->SetInputDevice(input);
    type = DeferredDeliveryImageType::DELIVERY_PHOTO;
    ret = phtOutput->DeferImageDeliveryFor(type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(phtOutput->IsDeferredImageDeliverySupported(type), -1);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with ProcessSnapshotDurationUpdates
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with ProcessSnapshotDurationUpdates
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_014, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    int32_t snapshotDuration = 1;
    std::shared_ptr<PhotoStateCallback> setCallback =
        std::make_shared<TestPhotoOutputCallback>("PhotoStateCallback");
    phtOutput->SetCallback(setCallback);
    EXPECT_NE(phtOutput->appCallback_, nullptr);
    phtOutput->ProcessSnapshotDurationUpdates(snapshotDuration);
    EXPECT_NE(phtOutput, nullptr);

    pid_t pid = 0;
    phtOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test photooutput with ProcessSnapshotDurationUpdates
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with ProcessSnapshotDurationUpdates
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_015, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    std::shared_ptr<PhotoCaptureSetting> settings = std::make_shared<PhotoCaptureSetting>();
    phtOutput->defaultCaptureSetting_ = settings;
    std::shared_ptr<PhotoCaptureSetting> ret = phtOutput->GetDefaultCaptureSetting();
    EXPECT_EQ(ret, settings);
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetMovingPhotoVideoCodecType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetMovingPhotoVideoCodecType
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_016, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    int32_t videoCodecType = 1;
    int32_t ret = phtOutput->SetMovingPhotoVideoCodecType(videoCodecType);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test photooutput with DepthDataDelivery
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with DepthDataDelivery
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_017, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    bool enabled = true;
    EXPECT_EQ(phtOutput->IsDepthDataDeliverySupported(), false);
    int32_t ret = phtOutput->EnableDepthDataDelivery(enabled);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test photooutput with GetPhotoRotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with GetPhotoRotation
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_018, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput->GetStream().GetRefPtr(), nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    sptr<CameraDevice> cameraObj = phtOutput->session_->GetInputDevice()->GetCameraDeviceInfo();
    int32_t imageRotation = 90;
    cameraObj->cameraPosition_ = CAMERA_POSITION_BACK;
    cameraObj->cameraOrientation_ = imageRotation;
    int32_t ret = phtOutput->GetPhotoRotation(imageRotation);
    EXPECT_EQ(ret, 180);

    cameraObj->cameraPosition_ = CAMERA_POSITION_FRONT;
    imageRotation = 180;
    ret = phtOutput->GetPhotoRotation(imageRotation);
    EXPECT_EQ(ret, VALUE_ROTATION);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test PhotoCaptureSetting with GetQuality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoCaptureSetting with Quality and Rotation
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_019, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    std::shared_ptr<PhotoCaptureSetting> settings = std::make_shared<PhotoCaptureSetting>();
    settings->captureMetadataSetting_ = session->GetMetadata();
    PhotoCaptureSetting::QualityLevel quality = PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM;
    settings->SetQuality(quality);
    PhotoCaptureSetting::QualityLevel ret = settings->GetQuality();
    EXPECT_EQ(ret, PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);

    quality = PhotoCaptureSetting::QUALITY_LEVEL_HIGH;
    settings->SetQuality(quality);
    ret = settings->GetQuality();
    EXPECT_EQ(ret, PhotoCaptureSetting::QUALITY_LEVEL_HIGH);

    OHOS::Camera::DeleteCameraMetadataItem(settings->captureMetadataSetting_->get(), OHOS_JPEG_QUALITY);
    ret = settings->GetQuality();
    EXPECT_EQ(ret, PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);
    settings->SetQuality(quality);

    PhotoCaptureSetting::RotationConfig rotationValue = PhotoCaptureSetting::RotationConfig::Rotation_0;
    settings->SetRotation(rotationValue);
    PhotoCaptureSetting::RotationConfig ret_2 = settings->GetRotation();
    EXPECT_EQ(ret_2, PhotoCaptureSetting::RotationConfig::Rotation_0);

    OHOS::Camera::DeleteCameraMetadataItem(settings->captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION);
    ret_2 = settings->GetRotation();
    EXPECT_EQ(ret_2, PhotoCaptureSetting::RotationConfig::Rotation_0);

    rotationValue = PhotoCaptureSetting::RotationConfig::Rotation_90;
    settings->SetRotation(rotationValue);
    ret_2 = settings->GetRotation();
    EXPECT_EQ(ret_2, PhotoCaptureSetting::RotationConfig::Rotation_90);

    uint8_t burstState = 1;
    settings->captureMetadataSetting_ = std::make_shared<OHOS::Camera::CameraMetadata>(16, 128);
    settings->SetBurstCaptureState(burstState);
    camera_metadata_item_t item;
    int ret_3 = OHOS::Camera::FindCameraMetadataItem(settings->captureMetadataSetting_->get(),
        OHOS_CONTROL_BURST_CAPTURE, &item);
    ASSERT_TRUE(ret_3 == CAM_META_SUCCESS && item.count > 0);
    EXPECT_EQ(item.data.u8[0], 1);
    settings->SetBurstCaptureState(2);
    ret_3 = OHOS::Camera::FindCameraMetadataItem(settings->captureMetadataSetting_->get(),
        OHOS_CONTROL_BURST_CAPTURE, &item);
    ASSERT_TRUE(ret_3 == CAM_META_SUCCESS && item.count > 0);
    EXPECT_EQ(item.data.u8[0], 2);
}

/*
 * Feature: Framework
 * Function: Test HStreamCaptureCallbackImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamCaptureCallbackImpl
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_020, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    int32_t time = 1;
    metadata->addEntry(OHOS_ABILITY_CAPTURE_EXPECT_TIME, &time, sizeof(int32_t));
    session->currentMode_ = SceneMode::HIGH_RES_PHOTO;
    phtOutput->appCallback_ = std::make_shared<TestPhotoOutputCallback>("PhotoStateCallback");
    int32_t captureId = 1;
    sptr<HStreamCaptureCallbackImpl> callback = new (std::nothrow) HStreamCaptureCallbackImpl(phtOutput);
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnCaptureStarted(captureId), 0);

    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAPTURE_EXPECT_TIME);
    EXPECT_EQ(callback->OnCaptureStarted(captureId), 0);

    phtOutput->appCallback_ = nullptr;
    pid_t pid = 0;
    phtOutput->CameraServerDied(pid);

    metadata->addEntry(OHOS_ABILITY_CAPTURE_EXPECT_TIME, &time, sizeof(int32_t));

    if (callback) {
        callback = nullptr;
    }
}

/*
 * Feature: Framework
 * Function: Test photooutput when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput when destruction
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_021, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    EXPECT_EQ(phtOutput->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photooutput with IsQuickThumbnailSupported when Mode is different
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with IsQuickThumbnailSupported when Mode is different
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_022, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    session->GetInputDevice()->GetCameraDeviceInfo()->cameraPosition_ = CAMERA_POSITION_BACK;
    session->currentMode_ =SceneMode::NIGHT;
    int32_t ret = phtOutput->IsQuickThumbnailSupported();
    EXPECT_EQ(ret, -1);

    session->currentMode_ = SceneMode::LIGHT_PAINTING;
    ret = phtOutput->IsQuickThumbnailSupported();
    EXPECT_EQ(ret, -1);

    int32_t isAutoHighQualityPhotoSupported = 1;
    ret = phtOutput->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE);
    ret = phtOutput->IsQuickThumbnailSupported();
    EXPECT_EQ(ret, -1);

    uint8_t uintValue = 0;
    metadata->addEntry(OHOS_ABILITY_CAPTURE_EXPECT_TIME, &uintValue, sizeof(uint8_t));
    ret = phtOutput->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    EXPECT_EQ(ret, CAMERA_OK);

    input->Close();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test photooutput with cameraserverdied when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with cameraserverdied when stream_ is nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_023, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    pid_t pid = 0;
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->stream_ = nullptr;
    photoOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test PhotoCaptureSetting with GetLocation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoCaptureSetting with GetLocation
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_024, TestSize.Level1)
{
    std::shared_ptr<PhotoCaptureSetting> settings = std::make_shared<PhotoCaptureSetting>();
    std::shared_ptr<Location> location;
    settings->GetLocation(location);
    EXPECT_EQ(location, settings->location_);
}

/*
 * Feature: Framework
 * Function: Test PhotoCaptureSetting with SetMirror and GetMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoCaptureSetting with SetMirror and GetMirror
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_025, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    std::shared_ptr<PhotoCaptureSetting> settings = std::make_shared<PhotoCaptureSetting>();
    settings->captureMetadataSetting_ = session->GetMetadata();
    settings->SetMirror(true);
    settings->SetMirror(false);
    EXPECT_FALSE(settings->GetMirror());
}

/*
 * Feature: Framework
 * Function: Test PhotoCaptureSetting with UpdateMediaLibraryPhotoAssetProxy
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoCaptureSetting with UpdateMediaLibraryPhotoAssetProxy
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_026, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    phtOutput->stream_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test PhotoCaptureSetting with GetLocation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoCaptureSetting with GetLocation
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_027, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_CLOUD_IMAGE_ENHANCE);
    bool isAutoCloudImageEnhancementSupported;
    int32_t ret = phtOutput->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhancementSupported);
    EXPECT_EQ(ret, CAMERA_OK);

    int32_t value = 0;
    metadata->addEntry(OHOS_ABILITY_AUTO_CLOUD_IMAGE_ENHANCE, &value, sizeof(int32_t));
}

/*
 * Feature: Framework
 * Function: Test photooutput with EnableMovingPhoto when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with EnableMovingPhoto when stream_ is nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_028, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    bool enabled = false;
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->stream_ = nullptr;
    EXPECT_EQ(phtOutput->EnableMovingPhoto(enabled), SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test SetThumbnailCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetThumbnailCallback
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_029, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->SetThumbnailCallback(nullptr);
}
/*
 * Feature: Framework
 * Function: Test UnSetThumbnailAvailableCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnSetThumbnailAvailableCallback
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_030, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->UnSetThumbnailAvailableCallback();
}
/*
 * Feature: Framework
 * Function: Test GetAppPhotoCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetAppPhotoCallback
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_031, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->GetAppPhotoCallback();
}
/*
 * Feature: Framework
 * Function: Test GetAppThumbnailCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetAppThumbnailCallback
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_032, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->GetAppThumbnailCallback();
}

/*
 * Feature: Framework
 * Function: Test photooutput with ProcessConstellationDrawingState
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with ProcessConstellationDrawingState
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_034, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    int32_t drawingState = 1;
    std::shared_ptr<PhotoStateCallback> setCallback =
        std::make_shared<TestPhotoOutputCallback>("PhotoStateCallback");
    phtOutput->SetCallback(setCallback);
    EXPECT_NE(phtOutput->appCallback_, nullptr);
    phtOutput->ProcessConstellationDrawingState(drawingState);
    EXPECT_NE(phtOutput, nullptr);

    pid_t pid = 0;
    phtOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test photooutput with CreateMediaLibrary
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with CreateMediaLibrary
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_035, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    phtOutput->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
}

/*
 * Feature: Framework
 * Function: Test HStreamCaptureCallbackImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamCaptureCallbackImpl
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_036, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    session->currentMode_ = SceneMode::HIGH_RES_PHOTO;
    phtOutput->appCallback_ = std::make_shared<TestPhotoOutputCallback>("PhotoStateCallback");
    int32_t captureId = 1;
    sptr<HStreamCaptureCallbackImpl> callback = new (std::nothrow) HStreamCaptureCallbackImpl(phtOutput);
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnOfflineDeliveryFinished(captureId), 0);

    phtOutput->appCallback_ = nullptr;
    pid_t pid = 0;
    phtOutput->CameraServerDied(pid);

    if (callback) {
        callback = nullptr;
    }
}

/*
 * Feature: Framework
 * Function: IsOfflineSupported_ShouldReturnFalse_WhenSessionIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when session is nullptr then IsOfflineSupported returns false
 */
HWTEST_F(CameraPhotoOutputUnit, IsOfflineSupported_001, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    EXPECT_EQ(phtOutput->IsOfflineSupported(), false);
}

/*
 * Feature: Framework
 * Function: IsOfflineSupported_ShouldReturnFalse_WhenInputDeviceIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when inputDevice is nullptr then IsOfflineSupported returns false
 */
HWTEST_F(CameraPhotoOutputUnit, IsOfflineSupported_002, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->CommitConfig(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->Start(), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(phtOutput->IsOfflineSupported(), false);
}

/*
 * Feature: Framework
 * Function: IsOfflineSupported_ShouldReturnFalse_WhenOfflineSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when offline is supported then IsOfflineSupported returns false
 */
HWTEST_F(CameraPhotoOutputUnit, IsOfflineSupported_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    bool isOfflineSupported = phtOutput->IsOfflineSupported();
    if(!isOfflineSupported){
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR);
    int8_t value = 1;
    metadata->addEntry(OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR, &value, sizeof(int8_t));
    }
    EXPECT_EQ(phtOutput->IsOfflineSupported(), true);
}

/*
 * Feature: Framework
 * Function: EnableOfflinePhoto_ShouldReturnError_WhenSessionIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when session is nullptr then EnableOfflinePhoto returns false
 */
HWTEST_F(CameraPhotoOutputUnit, EnableOfflinePhoto_001, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    EXPECT_EQ(phtOutput->EnableOfflinePhoto(), CameraErrorCode::SESSION_NOT_RUNNING);
}

/*
 * Feature: Framework
 * Function: EnableOfflinePhoto_ShouldReturnError_WhenInputDeviceIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when inputDevice is null then EnableOfflinePhoto returns error
 */
HWTEST_F(CameraPhotoOutputUnit, EnableOfflinePhoto_002, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->CommitConfig(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->Start(), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(phtOutput->EnableOfflinePhoto(), CameraErrorCode::SESSION_NOT_RUNNING);
}

/*
 * Feature: Framework
 * Function: EnableOfflinePhoto_ShouldReturnError_WhenOfflineNotSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when OfflineSupported is false then EnableOfflinePhoto returns error
 */
HWTEST_F(CameraPhotoOutputUnit, EnableOfflinePhoto_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    bool isOfflineSupported = phtOutput->IsOfflineSupported();
    if(isOfflineSupported){
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR);
    int8_t value = 0;
    metadata->addEntry(OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR, &value, sizeof(int8_t));
    }
    EXPECT_EQ(phtOutput->IsOfflineSupported(), false);
    EXPECT_EQ(phtOutput->EnableOfflinePhoto(), CameraErrorCode::OPERATION_NOT_ALLOWED);
}

/*
 * Feature: Framework
 * Function: EnableOfflinePhoto_ShouldReturnTrue_WhenOfflineSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when OfflineSupported is true then EnableOfflinePhoto returns ture
 */
HWTEST_F(CameraPhotoOutputUnit, EnableOfflinePhoto_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    bool isOfflineSupported = phtOutput->IsOfflineSupported();
    if(!isOfflineSupported){
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR);
    int8_t value = 1;
    metadata->addEntry(OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR, &value, sizeof(int8_t));
    }
    EXPECT_EQ(phtOutput->IsOfflineSupported(), true);
    EXPECT_EQ(phtOutput->EnableOfflinePhoto(), CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: GetPhotoSurface_ShouldReturnNull_WhenPhotoSurfaceIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when photoSurface_ is nullptr then GetPhotoSurface returns nullptr
 */
HWTEST_F(CameraPhotoOutputUnit, GetPhotoSurface_001, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    sptr<Surface> result = phtOutput->GetPhotoSurface();
    EXPECT_EQ(result, nullptr);
}

/*
 * Feature: Framework
 * Function: SetSwitchOfflinePhotoOutput_ShouldSet_WhenTrue
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSwitchOfflinePhotoOutput method when input is true
 */
HWTEST_F(CameraPhotoOutputUnit, SetSwitchOfflinePhotoOutput_ShouldSet_WhenTrue, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    phtOutput->SetSwitchOfflinePhotoOutput(true);
    EXPECT_TRUE(phtOutput->IsHasSwitchOfflinePhoto());
}

/*
 * Feature: Framework
 * Function: SetSwitchOfflinePhotoOutput_ShouldSet_WhenFalse
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSwitchOfflinePhotoOutput method when input is false
 */
HWTEST_F(CameraPhotoOutputUnit, SetSwitchOfflinePhotoOutput_ShouldSet_WhenFalse, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    phtOutput->SetSwitchOfflinePhotoOutput(false);
    EXPECT_FALSE(phtOutput->IsHasSwitchOfflinePhoto());
}

/*
 * Feature: Framework
 * Function: IsAutoAigcPhotoSupported_ShouldReturnFalse_WhenSessionIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when session is nullptr then IsAutoAigcPhotoSupported returns false
 */
HWTEST_F(CameraPhotoOutputUnit, IsAutoAigcPhotoSupported_001, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    bool isAutoAigcPhotoSupported = false;
    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: IsAutoAigcPhotoSupported_ShouldReturnError_WhenInputDeviceIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when inputDevice is null then IsAutoAigcPhotoSupported returns error
 */
HWTEST_F(CameraPhotoOutputUnit, IsAutoAigcPhotoSupported_002, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->CommitConfig(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->Start(), CameraErrorCode::SESSION_NOT_CONFIG);
    bool isAutoAigcPhotoSupported = false;
    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: IsAutoAigcPhotoSupported_ShouldReturnError_WhenInputDeviceIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when inputDevice is null then IsAutoAigcPhotoSupported returns error
 */
HWTEST_F(CameraPhotoOutputUnit, IsAutoAigcPhotoSupported_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    bool isAutoAigcPhotoSupported = false;
    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), CAMERA_OK);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_AIGC_PHOTO);
    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenSessionIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when session is nullptr then EnableAutoAigcPhoto returns false
 */
HWTEST_F(CameraPhotoOutputUnit, EnableAutoAigcPhoto_001, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput, nullptr);
    bool enabled = true;
    EXPECT_EQ(phtOutput->EnableAutoAigcPhoto(enabled), CameraErrorCode::SESSION_NOT_RUNNING);
}

/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenInputDeviceIsNull
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when inputDevice is null then EnableAutoAigcPhoto returns error
 */
HWTEST_F(CameraPhotoOutputUnit, EnableAutoAigcPhoto_002, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->CommitConfig(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(session->Start(), CameraErrorCode::SESSION_NOT_CONFIG);
    bool enabled = true;
    EXPECT_EQ(phtOutput->EnableAutoAigcPhoto(enabled), CameraErrorCode::SESSION_NOT_RUNNING);
}

/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenOfflineNotSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when OfflineSupported is false then EnableAutoAigcPhoto returns error
 */
HWTEST_F(CameraPhotoOutputUnit, EnableAutoAigcPhoto_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);
    bool isAutoAigcPhotoSupported = false;
    phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported);
    if(isAutoAigcPhotoSupported){
        bool enabled = true;
        EXPECT_EQ(phtOutput->EnableAutoAigcPhoto(enabled), CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenOfflineNotSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test est photooutput with IsAutoAigcPhotoSupported.
 */
HWTEST_F(CameraPhotoOutputUnit, IsAutoAigcPhotoSupported_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    phtOutput->session_ = nullptr;
    bool isAutoAigcPhotoSupported = false;
    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), SERVICE_FATL_ERROR);

    phtOutput->session_ = session;
    session->SetMode(SceneMode::CAPTURE);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    ASSERT_NE(metadata, nullptr);

    uint8_t aigcSupport = static_cast<uint8_t>(SceneMode::CAPTURE);
    bool status = AddOrUpdateMetadata(metadata, OHOS_ABILITY_AUTO_AIGC_PHOTO, &aigcSupport, 1);
    ASSERT_TRUE(status);

    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), CAMERA_OK);
    EXPECT_TRUE(isAutoAigcPhotoSupported);

    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_AIGC_PHOTO);
    EXPECT_EQ(phtOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), CAMERA_OK);
    EXPECT_FALSE(isAutoAigcPhotoSupported);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenOfflineNotSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test est photooutput with EnableMirror.
 */
HWTEST_F(CameraPhotoOutputUnit, EnableMirror_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    bool isEnabled = true;
    session->currentMode_ = SceneMode::PROFESSIONAL_PHOTO;
    int32_t ret;
    if (phtOutput->IsMirrorSupported()) {
        auto isSessionConfiged = session->IsSessionCommited() || session->IsSessionStarted();
        ret = session->EnableMovingPhotoMirror(isEnabled, isSessionConfiged);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    } else {
        ret = phtOutput->EnableMirror(isEnabled);
        EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);
    }

    isEnabled = false;
    if (phtOutput->IsMirrorSupported()) {
        auto isSessionConfiged = session->IsSessionCommited() || session->IsSessionStarted();
        ret = session->EnableMovingPhotoMirror(isEnabled, isSessionConfiged);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    } else {
        ret = phtOutput->EnableMirror(isEnabled);
        EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);
    }
    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenOfflineNotSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test est photooutput with NotifyOfflinePhotoOutput.
 */
/*
 * Feature: Framework
 * Function: EnableAutoAigcPhoto_ShouldReturnError_WhenOfflineNotSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test est photooutput with NotifyOfflinePhotoOutput.
 */
HWTEST_F(CameraPhotoOutputUnit, NotifyOfflinePhotoOutput_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    int32_t ret = camInput->GetCameraDevice()->Open();
    ASSERT_EQ(ret, CAMERA_OK);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    ASSERT_NE(phtOutput->GetStream().GetRefPtr(), nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    captureMonitorInfo timeStartIter;

    auto it1 = phtOutput->captureIdToCaptureInfoMap_.find(1);
    EXPECT_EQ(it1, phtOutput->captureIdToCaptureInfoMap_.end());

    timeStartIter.timeStart = std::chrono::steady_clock::now() - std::chrono::seconds(2);
    phtOutput->captureIdToCaptureInfoMap_.insert({2, timeStartIter});
    auto it2 = phtOutput->captureIdToCaptureInfoMap_.find(2);
    EXPECT_NE(it2, phtOutput->captureIdToCaptureInfoMap_.end());

    phtOutput->NotifyOfflinePhotoOutput(2);
    EXPECT_EQ(phtOutput->captureIdToCaptureInfoMap_.size(), 0);

    phtOutput->SetSwitchOfflinePhotoOutput(true);
    timeStartIter.timeStart = std::chrono::steady_clock::now();
    phtOutput->captureIdToCaptureInfoMap_.insert({3, timeStartIter});
    phtOutput->NotifyOfflinePhotoOutput(3);
    EXPECT_EQ(phtOutput->captureIdToCaptureInfoMap_.size(), 0);

    phtOutput->captureIdToCaptureInfoMap_.insert({4, timeStartIter});
    phtOutput->captureIdToCaptureInfoMap_.insert({5, timeStartIter});
    phtOutput->NotifyOfflinePhotoOutput(4);
    EXPECT_EQ(phtOutput->captureIdToCaptureInfoMap_.size(), 1);
    auto it5 = phtOutput->captureIdToCaptureInfoMap_.find(5);
    EXPECT_NE(it5, phtOutput->captureIdToCaptureInfoMap_.end());

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: HStreamCaptureCallbackImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamCaptureCallbackImpl
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_029, TestSize.Level0)
{
    PhotoOutput* photoOutput = nullptr;
    std::shared_ptr<HStreamCaptureCallbackImpl> callback = std::make_shared<HStreamCaptureCallbackImpl>(photoOutput);
    int32_t captureId = 1;
    EXPECT_EQ(callback->OnOfflineDeliveryFinished(captureId), 0);
}

/*
 * Feature: Framework
 * Function: ReportCaptureEnhance
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportCaptureEnhance
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_030, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    std::string str = "uttest";
    phtOutput->ReportCaptureEnhanceSupported(str, true);
    phtOutput->ReportCaptureEnhanceEnabled(str, true, 0);
    EXPECT_NE(photoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test photooutput with IsPhotoQualityPrioritizationSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with IsPhotoQualityPrioritizationSupported
 */
HWTEST_F(CameraPhotoOutputUnit, IsPhotoQualityPrioritizationSupported_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsPhotoQualityPrioritizationSupported_001: ENTER");
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetCachedMetadata();
    ASSERT_NE(metadata, nullptr);
    int32_t quality[15] = {0, 0, 1, -1, -1, 1, 0, 1, -1, -1, 2, 0, 1, -1, -1};
    bool status = AddOrUpdateMetadata(metadata, OHOS_ABILITY_PHOTO_QUALITY_PRIORITIZATION, &quality,
        sizeof(quality) / sizeof(quality[0]));
    ASSERT_TRUE(status);
    bool isSupported = false;
    int32_t ret = phtOutput->IsPhotoQualityPrioritizationSupported(
        static_cast<PhotoOutput::PhotoQualityPrioritization>(1), isSupported);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
    MEDIA_INFO_LOG("IsPhotoQualityPrioritizationSupported_001: END");
}

/*
 * Feature: Framework
 * Function: Test photooutput with IsPhotoQualityPrioritizationSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with IsPhotoQualityPrioritizationSupported
 */
HWTEST_F(CameraPhotoOutputUnit, IsPhotoQualityPrioritizationSupported_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsPhotoQualityPrioritizationSupported_002: ENTER");
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetCachedMetadata();
    ASSERT_NE(metadata, nullptr);
    int32_t quality[9] = {0, 0, 1, -1, -1, 1, 0, -1, -1};
    bool status = AddOrUpdateMetadata(metadata, OHOS_ABILITY_PHOTO_QUALITY_PRIORITIZATION, &quality,
        sizeof(quality) / sizeof(quality[0]));
    ASSERT_TRUE(status);
    bool isSupported = false;
    int32_t ret = phtOutput->IsPhotoQualityPrioritizationSupported(
        static_cast<PhotoOutput::PhotoQualityPrioritization>(1), isSupported);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
    MEDIA_INFO_LOG("IsPhotoQualityPrioritizationSupported_002: END");
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetPhotoQualityPrioritization
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetPhotoQualityPrioritization
 */
HWTEST_F(CameraPhotoOutputUnit, SetPhotoQualityPrioritization_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("SetPhotoQualityPrioritization_001: ENTER");
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photoOutput), 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        session->GetInputDevice()->GetCameraDeviceInfo()->GetCachedMetadata();
    ASSERT_NE(metadata, nullptr);
    int32_t quality[15] = {0, 0, 1, -1, -1, 1, 0, 1, -1, -1, 2, 0, 1, -1, -1};
    bool status = AddOrUpdateMetadata(metadata, OHOS_ABILITY_PHOTO_QUALITY_PRIORITIZATION, &quality,
        sizeof(quality) / sizeof(quality[0]));
    ASSERT_TRUE(status);
    int ret = phtOutput->SetPhotoQualityPrioritization(static_cast<PhotoOutput::PhotoQualityPrioritization>(1));

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    camera_metadata_item_t item;
    int32_t res = OHOS::Camera::FindCameraMetadataItem(metadata->get(),
        OHOS_CONTROL_PHOTO_QUALITY_PRIORITIZATION, &item);
    EXPECT_EQ(res, CAM_META_SUCCESS);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
    MEDIA_INFO_LOG("SetPhotoQualityPrioritization_001: END");
}
}
}
