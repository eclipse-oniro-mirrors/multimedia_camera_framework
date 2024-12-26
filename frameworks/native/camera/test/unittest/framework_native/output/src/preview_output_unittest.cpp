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

#include "preview_output_unittest.h"

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

void CameraPreviewOutputUnit::SetUpTestCase(void) {}

void CameraPreviewOutputUnit::TearDownTestCase(void) {}

void CameraPreviewOutputUnit::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
}

void CameraPreviewOutputUnit::TearDown()
{
    if (cameraManager_ != nullptr) {
        cameraManager_ = nullptr;
    }
}

void CameraPreviewOutputUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraPreviewOutputUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

sptr<CaptureOutput> CameraPreviewOutputUnit::CreatePreviewOutput()
{
    std::vector<Profile> previewProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    if (!outputCapability) {
        return nullptr;
    }

    previewProfile = outputCapability->GetPreviewProfiles();
    if (previewProfile.empty()) {
        return nullptr;
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreatePreviewOutput(previewProfile[0], surface);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with Start Stop and Release
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with with Start Stop and Release
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    int32_t ret = previewOutput->Start();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);
    ret = previewOutput->Stop();
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    session->Stop();
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with Set and GetPreviewRotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with Set and GetPreviewRotation
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    sptr<CameraDevice> cameraObj = previewOutput->session_->GetInputDevice()->GetCameraDeviceInfo();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_SENSOR_ORIENTATION);
    int32_t value = 90;
    metadata->addEntry(OHOS_SENSOR_ORIENTATION, &value, sizeof(int32_t));
    int32_t imageRotation = 90;
    bool isDisplayLocked = false;
    int32_t ret = previewOutput->SetPreviewRotation(imageRotation, isDisplayLocked);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    ret = previewOutput->GetPreviewRotation(imageRotation);
    EXPECT_EQ(ret, 180);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test previewoutput with GetObserverControlTags
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with GetObserverControlTags
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    std::set<camera_device_metadata_tag_t> tags = { OHOS_CONTROL_ZOOM_RATIO, OHOS_CONTROL_CAMERA_MACRO,
        OHOS_CONTROL_MOON_CAPTURE_BOOST, OHOS_CONTROL_SMOOTH_ZOOM_RATIOS };
    std::set<camera_device_metadata_tag_t> ret = previewOutput->GetObserverControlTags();
    EXPECT_EQ(ret, tags);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with FrameRate SetOutputFormat and SetSize
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with FrameRate SetOutputFormat and SetSize
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    std::vector<int32_t> previewFrameRateRange = {0, 0};
    previewOutput->SetFrameRateRange(previewFrameRateRange[0], previewFrameRateRange[1]);
    EXPECT_EQ(previewOutput->GetFrameRateRange(), previewFrameRateRange);

    previewOutput->SetOutputFormat(static_cast<int32_t>(CAMERA_FORMAT_YUV_420_SP));
    EXPECT_EQ(previewOutput->PreviewFormat_, 1003);

    Size previewSize;
    previewSize.width = 640;
    previewSize.height = 480;
    previewOutput->SetSize(previewSize);
    EXPECT_EQ(previewOutput->PreviewSize_.width, previewSize.width);
    EXPECT_EQ(previewOutput->PreviewSize_.height, previewSize.height);

    int32_t ret = previewOutput->SetFrameRate(0, 0);
    EXPECT_EQ(ret, CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test previewoutput with StartSketch StopSketch EnableSketch AddDeferredSurface and AttachSketchSurface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with StartSketch StopSketch EnableSketch AddDeferredSurface
 *          and AttachSketchSurface
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(previewOutput->AttachSketchSurface(surface), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    Size previewSize;
    previewSize.width = 640;
    previewSize.height = 480;
    auto wrapper = std::make_shared<SketchWrapper>(previewOutput->GetStream(), previewSize);
    wrapper->sketchStream_ = nullptr;
    previewOutput->sketchWrapper_ = wrapper;

    int32_t ret = previewOutput->StartSketch();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    previewOutput->AddDeferredSurface(surface);
    ret = previewOutput->AttachSketchSurface(surface);
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    bool isEnable = true;
    ret = previewOutput->EnableSketch(isEnable);
    EXPECT_EQ(ret, CameraErrorCode::OPERATION_NOT_ALLOWED);

    ret = previewOutput->StopSketch();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    previewOutput->session_ = nullptr;
    float ret_1 = previewOutput->GetSketchRatio();
    EXPECT_EQ(ret_1, -1.0);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test GetHdiFormat From CameraFormat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHdiFormat From CameraFormat
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    CameraFormat format = CAMERA_FORMAT_YCBCR_420_888;
    Size size = {0, 0};
    std::shared_ptr<Profile> previewProfile = std::make_shared<Profile>(format, size);
    previewOutput->previewProfile_ = previewProfile;
    std::shared_ptr<Size> ret = previewOutput->FindSketchSize();
    EXPECT_EQ(ret, nullptr);

    previewOutput->previewProfile_->format_ = CAMERA_FORMAT_YCBCR_P010;
    ret = previewOutput->FindSketchSize();
    EXPECT_EQ(ret, nullptr);

    previewOutput->previewProfile_->format_ = CAMERA_FORMAT_YCRCB_P010;
    ret = previewOutput->FindSketchSize();
    EXPECT_EQ(ret, nullptr);

    previewOutput->previewProfile_->format_ = CAMERA_FORMAT_NV12;
    ret = previewOutput->FindSketchSize();
    EXPECT_EQ(ret, nullptr);

    previewOutput->previewProfile_->format_ = CAMERA_FORMAT_YUV_422_YUYV;
    ret = previewOutput->FindSketchSize();
    EXPECT_EQ(ret, nullptr);

    previewOutput->previewProfile_->format_ = CAMERA_FORMAT_INVALID;
    ret = previewOutput->FindSketchSize();
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: Framework
 * Function: Test PreviewOutputCallbackImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PreviewOutputCallbackImpl
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    previewOutput->appCallback_ = nullptr;
    sptr<PreviewOutputCallbackImpl> callback = new (std::nothrow) PreviewOutputCallbackImpl(previewOutput);
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnFrameStarted(), CAMERA_OK);
    EXPECT_EQ(callback->OnFrameError(0), CAMERA_OK);

    if (callback) {
        callback = nullptr;
    }
}

/*
 * Feature: Framework
 * Function: Test previewoutput with StartSketch StopSketch when sketchWrapper_ is nullptr and not config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with StartSketch StopSketch when sketchWrapper_ is nullptr and not config
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(previewOutput->StartSketch(), SESSION_NOT_CONFIG);
    EXPECT_EQ(previewOutput->StopSketch(), SESSION_NOT_CONFIG);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    previewOutput->sketchWrapper_ = nullptr;
    int32_t ret = previewOutput->StartSketch();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    ret = previewOutput->StopSketch();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with CameraServerDied when appCallback_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with CameraServerDied when appCallback_ is nullptr
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    std::shared_ptr<PreviewStateCallback> appCallback = nullptr;
    Size previewSize;
    previewSize.width = 640;
    previewSize.height = 480;
    EXPECT_EQ(previewOutput->CreateSketchWrapper(previewSize), 0);
    previewOutput->SetCallback(appCallback);

    pid_t pid = 0;
    previewOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with CameraServerDied when appCallback_ is not nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with CameraServerDied when appCallback_ is not nullptr
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_010, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)preview;

    std::shared_ptr<PreviewStateCallback> setCallback =
        std::make_shared<TestPreviewOutputCallback>("PreviewStateCallback");
    previewOutput->SetCallback(setCallback);
    std::shared_ptr<PreviewStateCallback> getCallback = previewOutput->GetApplicationCallback();
    ASSERT_EQ(setCallback, getCallback);

    pid_t pid = 0;
    previewOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged() in OnNativeRegisterCallback,
 *          OnNativeUnregisterCallback, FindSketchSize
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in
 *          OnNativeRegisterCallback, OnNativeUnregisterCallback, FindSketchSize
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_011, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    previewOutput->SetSession(session);
    previewOutput->FindSketchSize();

    std::string eventString = "test";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);
    eventString = "sketchStatusChanged";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);

    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    eventString = "test";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);
    eventString = "sketchStatusChanged";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test previewoutput with OnSketchStatusChanged IsSketchSupported and CreateSketchWrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with OnSketchStatusChanged IsSketchSupported and CreateSketchWrapper
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_012, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    auto previewOutput = (sptr<PreviewOutput>&)preview;
    previewOutput->stream_ = nullptr;
    previewOutput->session_ = nullptr;

    EXPECT_EQ(previewOutput->OnSketchStatusChanged(SketchStatus::STOPED), CAMERA_INVALID_STATE);
    EXPECT_EQ(previewOutput->IsSketchSupported(), false);

    Size previewSize = {};
    previewOutput->stream_ = nullptr;
    EXPECT_EQ(previewOutput->CreateSketchWrapper(previewSize), CameraErrorCode::SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with callback and cameraserverdied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with callback and cameraserverdied
 */
HWTEST_F(CameraPreviewOutputUnit, preview_output_unittest_013, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    auto previewOutput = (sptr<PreviewOutput>&)preview;

    std::string eventString = "sketchStatusChanged";
    previewOutput->sketchWrapper_ = nullptr;
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);

    pid_t pid = 0;
    previewOutput->stream_ = nullptr;
    previewOutput->CameraServerDied(pid);
}
}
}
