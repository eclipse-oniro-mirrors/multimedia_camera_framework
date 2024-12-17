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

#include "camera_framework_input_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraFrameworkInputUnit::SetUpTestCase(void) {}

void CameraFrameworkInputUnit::TearDownTestCase(void) {}

void CameraFrameworkInputUnit::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraFrameworkInputUnit::TearDown()
{
    cameraManager_ = nullptr;
}

void CameraFrameworkInputUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraFrameworkInputUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test CameraFrameworkInput with SetInputUsedAsPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetInputUsedAsPosition for Normal branches
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    CameraPosition usedAsPosition = CAMERA_POSITION_UNSPECIFIED;
    camInput->SetInputUsedAsPosition(usedAsPosition);
    EXPECT_EQ(camInput->cameraObj_->usedAsCameraPosition_, CAMERA_POSITION_UNSPECIFIED);
}

/*
 * Feature: Framework
 * Function: Test CameraFrameworkInput with SetOcclusionDetectCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetOcclusionDetectCallback for cameraOcclusionDetectCallback is nullptr
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::shared_ptr<CameraOcclusionDetectCallback> cameraOcclusionDetectCallback = nullptr;
    camInput->SetOcclusionDetectCallback(cameraOcclusionDetectCallback);
    EXPECT_EQ(camInput->cameraOcclusionDetectCallback_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraFrameworkInput with CameraServerDied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraFrameworkInput with CameraServerDied for abnormal branches
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    pid_t pid = 0;
    camInput->CameraServerDied(pid);
    EXPECT_EQ(camInput->errorCallback_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test result callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test result callback
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::shared_ptr<TestOnResultCallback> setResultCallback =
        std::make_shared<TestOnResultCallback>("OnResultCallback");

    input->SetResultCallback(setResultCallback);
    std::shared_ptr<ResultCallback> getResultCallback = input->GetResultCallback();
    ASSERT_EQ(getResultCallback, setResultCallback);
}

/*
 * Feature: Framework
 * Function: Test input callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test input callback
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::shared_ptr<TestDeviceCallback> setCallback = std::make_shared<TestDeviceCallback>("InputCallback");
    input->SetErrorCallback(setCallback);
    std::shared_ptr<ErrorCallback> getCallback = input->GetErrorCallback();
    ASSERT_EQ(setCallback, getCallback);
}

/*
 * Feature: Framework
 * Function: Test cameraFormat with CAMERA_FORMAT_YUV_420_SP and CAMERA_FORMAT_JPEG
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraFormat with CAMERA_FORMAT_YUV_420_SP and CAMERA_FORMAT_JPEG
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    Size previewSize = {.width = 1440, .height = 1080};
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata = cameras[0]->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    CameraFormat previewFormat = CAMERA_FORMAT_YCBCR_420_888;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;
    EXPECT_EQ(previewOutput->IsSketchSupported(), false);
    auto currentPreviewProfile = previewOutput->GetPreviewProfile();
    currentPreviewProfile->format_ = CAMERA_FORMAT_YUV_420_SP;
    EXPECT_EQ(previewOutput->IsSketchSupported(), false);
    currentPreviewProfile->format_ = CAMERA_FORMAT_JPEG;
    EXPECT_EQ(previewOutput->IsSketchSupported(), false);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test camerainput with deviceObj_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camerainput with deviceObj_ is nullptr
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    pid_t pid = 0;
    std::shared_ptr<TestDeviceCallback> setCallback = std::make_shared<TestDeviceCallback>("InputCallback");
    camInput->deviceObj_ = nullptr;
    camInput->SetErrorCallback(setCallback);
    camInput->CameraServerDied(pid);
}

/*
* Feature: Framework
* Function: Test normal branch that is support secure camera for open camera
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test normal branch for open camera
*/
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        int32_t modeSet = static_cast<int32_t>(PORTRAIT);
        std::shared_ptr<Camera::CameraMetadata> metadata = camDevice->GetMetadata();
        metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);

            uint64_t secureSeqId = 0;
            sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
            ASSERT_NE(deviceObj, nullptr);

            int intResult = camInput->Open(true, &secureSeqId);
            EXPECT_EQ(intResult, 0);
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test anomalous branch that is not support secure camera for open camera
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test anomalous branch for open camera
*/
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        int32_t modeSet = static_cast<int32_t>(PORTRAIT);
        std::shared_ptr<Camera::CameraMetadata> metadata = camDevice->GetMetadata();
        metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) == modes.end()) {
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);

            uint64_t secureSeqId = 0;
            sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
            ASSERT_NE(deviceObj, nullptr);

            int intResult = camInput->Open(true, &secureSeqId);
            EXPECT_EQ(intResult, 0);
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test anomalous branch when open secure camera that seq is null
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test anomalous branch for open camera
*/
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_010, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        int32_t modeSet = static_cast<int32_t>(PORTRAIT);
        std::shared_ptr<Camera::CameraMetadata> metadata = camDevice->GetMetadata();
        metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);

            sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
            ASSERT_NE(deviceObj, nullptr);

            uint64_t* secureSeqId = nullptr;
            int intResult = camInput->Open(true, secureSeqId);
            EXPECT_EQ(intResult, CAMERA_INVALID_ARG);
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test normal branch that is open non-secure camera
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test normal branch that is open non-secure camera
*/
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_011, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        int32_t modeSet = static_cast<int32_t>(PORTRAIT);
        std::shared_ptr<Camera::CameraMetadata> metadata = camDevice->GetMetadata();
        metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) == modes.end()) {
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);

            sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
            ASSERT_NE(deviceObj, nullptr);

            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            EXPECT_EQ(secureSeqId, 0);
            input->Close();
            break;
        }
    }
}
}
}
