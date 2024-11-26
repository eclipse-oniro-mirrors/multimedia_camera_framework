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

void CameraPhotoOutputUnit::SetUpTestCase(void) {}

void CameraPhotoOutputUnit::TearDownTestCase(void) {}

void CameraPhotoOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
}

void CameraPhotoOutputUnit::TearDown()
{
    NativeAuthorization();
    cameraManager_ = nullptr;
}

void CameraPhotoOutputUnit::NativeAuthorization()
{
    const char *perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    MEDIA_DEBUG_LOG("CameraPhotoOutputUnit::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

sptr<CaptureOutput> CameraPhotoOutputUnit::CreatePhotoOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile, surfaceProducer);
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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photoOutput);
    session->AddInput(input);
    session->CommitConfig();
    session->Start();

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
 * CaseDescription: Test photooutput with SetNativeSurface and SeteCallbackFlag when isEnableDeeferred is oppsite
 *          and session is commit
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photoOutput);
    session->AddInput(input);
    session->CommitConfig();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    bool ret = phtOutput->IsYuvOrHeifPhoto();
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test photooutput with Set and Get AuxiliaryPhotoHandle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with Set and Get AuxiliaryPhotoHandle
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
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
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

    phtOutput->gainmapSurface_ = nullptr;
    phtOutput->deepSurface_ = nullptr;
    phtOutput->exifSurface_ = nullptr;
    phtOutput->debugSurface_ = nullptr;
    phtOutput->rawPhotoSurface_ = nullptr;
    phtOutput->CreateMultiChannel();
    EXPECT_NE(phtOutput->gainmapSurface_, nullptr);
    EXPECT_NE(phtOutput->deepSurface_, nullptr);
    EXPECT_NE(phtOutput->exifSurface_, nullptr);
    EXPECT_NE(phtOutput->debugSurface_, nullptr);

    bool enabled = true;
    EXPECT_EQ(phtOutput->EnableRawDelivery(enabled), CameraErrorCode::SUCCESS);
    EXPECT_NE(phtOutput->rawPhotoSurface_, nullptr);

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
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
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

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

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer("rawImage");
    int32_t ret = phtOutput->SetRawPhotoInfo(surface);
    EXPECT_EQ(ret, CAMERA_OK);

    bool enabled = true;
    ret = phtOutput->EnableRawDelivery(enabled);
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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    phtOutput->thumbnailSurface_ = nullptr;
    sptr<IBufferConsumerListener> listener = new TestIBufferConsumerListener();
    phtOutput->SetThumbnailListener(listener);
    EXPECT_EQ(phtOutput->thumbnailSurface_, nullptr);

    phtOutput->thumbnailSurface_ = Surface::CreateSurfaceAsConsumer("thumbnailSurface");
    phtOutput->SetThumbnailListener(listener);
    EXPECT_NE(phtOutput->thumbnailSurface_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test photooutput with SetThumbnail EnableAutoHighQualityPhoto and EnableMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with SetThumbnail EnableAutoHighQualityPhoto and EnableMirror
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_010, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_011, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_012, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_013, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
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

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_014, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
}

/*
 * Feature: Framework
 * Function: Test photooutput with ProcessSnapshotDurationUpdates
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with ProcessSnapshotDurationUpdates
 */
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_015, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    auto settings = std::make_shared<PhotoCaptureSetting>();
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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_016, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_017, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraPhotoOutputUnit, photo_output_unittest_018, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
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
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(photoOutput);
    session->CommitConfig();
    session->Start();

    int32_t imageRotation = 90;
    int32_t ret = phtOutput->GetPhotoRotation(imageRotation);
    EXPECT_NE(ret, 90);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}
}
}
