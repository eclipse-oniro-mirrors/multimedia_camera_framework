/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "input/camera_service_system_ability_listener.h"
#include "utils/camera_rotation_api_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

class CameraOcclusionDetectCallbackTest : public CameraOcclusionDetectCallback {
public:
    CameraOcclusionDetectCallbackTest() = default;
    ~CameraOcclusionDetectCallbackTest() = default;
    void OnCameraOcclusionDetected(const uint8_t isCameraOcclusion, const uint8_t isCameraLensDirty) const
    {
        MEDIA_INFO_LOG("CameraOcclusionDetectCallbackTest::OnCameraOcclusionDetected called %{public}d %{public}d",
            isCameraOcclusion, isCameraLensDirty);
    }
};

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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_001, TestSize.Level1)
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_002, TestSize.Level1)
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_003, TestSize.Level1)
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_004, TestSize.Level1)
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_005, TestSize.Level1)
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_006, TestSize.Level1)
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
    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata;
    std::string cameraId = cameras[0]->GetID();
    cameraProxy->GetCameraAbility(cameraId, deviceMetadata);
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_007, TestSize.Level1)
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_008, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        camDevice->supportedModes_.clear();
        camDevice->supportedModes_.push_back(PORTRAIT);
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_009, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        camDevice->supportedModes_.clear();
        camDevice->supportedModes_.push_back(PORTRAIT);
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_010, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        camDevice->supportedModes_.clear();
        camDevice->supportedModes_.push_back(PORTRAIT);
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
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_011, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    for (sptr<CameraDevice> camDevice : cameras) {
        camDevice->supportedModes_.clear();
        camDevice->supportedModes_.push_back(PORTRAIT);
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

/*
 * Feature: Framework
 * Function: Test camerainput with SwitchCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camerainput with SwitchCameraDevice
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_012, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<ICameraDeviceService> deviceObj = nullptr;
    int32_t retCode = CameraManager::GetInstance()->CreateCameraDevice(cameras[0]->GetID(), &deviceObj);
    ASSERT_EQ(retCode, CameraErrorCode::SUCCESS);
    camInput->SwitchCameraDevice(deviceObj, cameras[0]);
    EXPECT_EQ(camInput->cameraObj_, cameras[0]);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMetaSetting with existing metaTag.
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_013, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;

    sptr<CameraDevice> cameraObject = camInput->GetCameraDeviceInfo();
    cameraObject->cachedMetadata_ = std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObject->GetMetadata();
    std::vector<int32_t> testStreamInfo = { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 };
    baseMetadata->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS,
        testStreamInfo.data(), testStreamInfo.size());

    std::shared_ptr<camera_metadata_item_t> metadataItem = nullptr;
    metadataItem = camInput->GetMetaSetting(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    ASSERT_NE(metadataItem, nullptr);

    std::vector<vendorTag_t> infos = {};
    camInput->GetCameraAllVendorTags(infos);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<CameraDevice> camdeviceObj = nullptr;
    sptr<CameraInput> camInput_1 = new (std::nothrow) CameraInput(deviceObj, camdeviceObj);
    ASSERT_NE(camInput_1, nullptr);
    metadataItem = camInput_1->GetMetaSetting(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    EXPECT_EQ(metadataItem, nullptr);
    metadataItem = camInput->GetMetaSetting(-1);
    EXPECT_EQ(metadataItem, nullptr);

    if (cameras.size() > 1) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[1]->GetMetadata();
        std::string cameraId = cameras[1]->GetID();
        sptr<CameraDevice> camdeviceObj_2 = new (std::nothrow) CameraDevice(cameraId, metadata);
        ASSERT_NE(camdeviceObj_2, nullptr);
    }
}


/*
 * Feature: Framework
 * Function: Test camera service system ability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camera service system ability
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_014, TestSize.Level1)
{
    auto cameraListener =
        new(std::nothrow) CameraServiceSystemAbilityListener();
    ASSERT_NE(cameraListener, nullptr);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    std::string deviceId = "";
    cameraListener->OnAddSystemAbility(0, deviceId);
    EXPECT_EQ(deviceId, "");

    cameraListener->OnRemoveSystemAbility(0, deviceId);
    EXPECT_EQ(deviceId, "");
    cameraListener = nullptr;
}

/*
 * Feature: Framework
 * Function: Test cameraDevice structure with metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraDevice structure with metadata
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_015, TestSize.Level1)
{
    std::string cameraID = "cam01";
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = nullptr;
    dmDeviceInfo deviceInfo;

    CameraDevice device1(cameraID, metadata);
    EXPECT_EQ(device1.GetMetadata(), nullptr);
    CameraDevice device2(cameraID, metadata, deviceInfo);
    EXPECT_EQ(device2.GetMetadata(), nullptr);

    int32_t itemCount = 1;
    int32_t dataSize = 1024;
    metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    CameraDevice device3(cameraID, metadata);
    EXPECT_NE(device3.GetMetadata(), nullptr);
    CameraDevice device4(cameraID, metadata, deviceInfo);
    EXPECT_NE(device4.GetMetadata(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test cameraDevice structure with GetPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraDevice structure with GetPosition
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_016, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);

    CameraPosition tempPositionType = camera->cameraPosition_;
    CameraFoldScreenType tempFoldType = camera->foldScreenType_;

    camera->cameraPosition_ = CAMERA_POSITION_FRONT;
    camera->foldScreenType_ = CAMERA_FOLDSCREEN_INNER;
    CameraPosition cameraPosition = camera->GetPosition();

    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    if (apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN) {
        EXPECT_EQ(cameraPosition, CAMERA_POSITION_FOLD_INNER);
    } else {
        EXPECT_EQ(cameraPosition, CAMERA_POSITION_FRONT);
    }

    camera->SetCameraDeviceUsedAsPosition(cameraPosition);
    EXPECT_EQ(camera->GetUsedAsPosition(), cameraPosition);

    camera->cameraPosition_ = tempPositionType;
    camera->foldScreenType_ = tempFoldType;
}

/*
 * Feature: Framework
 * Function: Test cameraInput Open and Close with camera device is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput Open and Close with camera device is nullptr
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_017, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<ICameraDeviceService> deviceObj = nullptr;
    input->SetCameraDevice(deviceObj);
    EXPECT_EQ(input->GetCameraDevice(), deviceObj);

    bool isEnableSecureCamera = false;
    uint64_t secureSeqId = 0;
    EXPECT_EQ(input->Open(isEnableSecureCamera, &secureSeqId), SERVICE_FATL_ERROR);
    EXPECT_EQ(input->Close(), SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test cameraInput with camera device service on result when set occlusion detect call back
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput with camera device service on result when set occlusion detect call back
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_018, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::shared_ptr<CameraOcclusionDetectCallback> cameraOcclusionDetectCallback = nullptr;
    input->SetOcclusionDetectCallback(cameraOcclusionDetectCallback);
    EXPECT_EQ(input->GetOcclusionDetectCallback(), nullptr);

    cameraOcclusionDetectCallback = std::make_shared<CameraOcclusionDetectCallbackTest>();
    input->SetOcclusionDetectCallback(cameraOcclusionDetectCallback);
    EXPECT_NE(input->GetOcclusionDetectCallback(), nullptr);

    std::shared_ptr<CameraDeviceServiceCallback> cameraDeviceServiceCallback_test =
        std::make_shared<CameraDeviceServiceCallback>();
    EXPECT_NE(cameraDeviceServiceCallback_test, nullptr);

    std::shared_ptr<CameraDeviceServiceCallback> cameraDeviceServiceCallback =
        std::make_shared<CameraDeviceServiceCallback>(input);
    EXPECT_NE(cameraDeviceServiceCallback, nullptr);
    uint64_t timestamp = 10;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = nullptr;
    EXPECT_EQ(cameraDeviceServiceCallback->OnResult(timestamp, metadata), CAMERA_INVALID_ARG);

    const int32_t DEFAULT_ITEMS = 10;
    const int32_t DEFAULT_DATA_LENGTH = 100;
    int32_t count = 1;
    int32_t isOcclusionDetected = 1;
    int32_t isLensDirtyDetected = 1;
    metadata = std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    ASSERT_TRUE(metadata->addEntry(OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &isOcclusionDetected, count));
    EXPECT_EQ(cameraDeviceServiceCallback->OnResult(timestamp, metadata), CAMERA_OK);

    metadata = std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    ASSERT_TRUE(metadata->addEntry(OHOS_STATUS_CAMERA_LENS_DIRTY_DETECTION, &isLensDirtyDetected, count));
    EXPECT_EQ(cameraDeviceServiceCallback->OnResult(timestamp, metadata), CAMERA_OK);

    metadata = std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    ASSERT_TRUE(metadata->addEntry(OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &isOcclusionDetected, count));
    ASSERT_TRUE(metadata->addEntry(OHOS_STATUS_CAMERA_LENS_DIRTY_DETECTION, &isLensDirtyDetected, count));
    EXPECT_EQ(cameraDeviceServiceCallback->OnResult(timestamp, metadata), CAMERA_OK);

    sptr<ICameraDeviceService> deviceObj = nullptr;
    input->SetCameraDevice(deviceObj);
    EXPECT_EQ(input->GetCameraDevice(), nullptr);
    EXPECT_EQ(cameraDeviceServiceCallback->OnResult(timestamp, metadata), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with set profile when cameraDevice or supported mode is null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager with set profile when cameraDevice or supported mode is null
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_019, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CameraDevice> device1 = cameras[0];
    ASSERT_NE(device1, nullptr);

    std::string cameraID = "cam01";
    int32_t itemCount = 1;
    int32_t dataSize = 1024;
    auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    sptr<CameraDevice> device2 = new CameraDevice(cameraID, metadata);
    ASSERT_NE(device2, nullptr);

    sptr<CameraDevice> device3 = nullptr;

    std::vector<sptr<CameraDevice>> cameraDevices;
    cameraDevices.push_back(device1);
    cameraDevices.push_back(device2);
    cameraDevices.push_back(device3);

    cameraManager_->SetProfile(cameraDevices[0], metadata);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with GetSupportedCamerasWithFoldStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager with GetSupportedCamerasWithFoldStatus
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_020, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::string tempFoldType = cameraManager_->foldScreenType_;
    cameraManager_->foldScreenType_ = "1";
    ASSERT_TRUE(cameraManager_->GetIsFoldable());

    ASSERT_FALSE(cameraManager_->GetSupportedCamerasWithFoldStatus().empty());

    cameraManager_->foldScreenType_ = tempFoldType;
}

/*
 * Feature: Framework
 * Function: Test CameraDevice with GetCameraOrientation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraDevice with GetCameraOrientation for invoke
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_021, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    uint32_t tempCameraOrientation = cameras[0]->cameraOrientation_;

    cameras[0]->cameraOrientation_ = 1;
    EXPECT_EQ(cameras[0]->GetCameraOrientation(), 1);

    cameras[0]->cameraOrientation_ = tempCameraOrientation;
}

/*
 * Feature: Framework
 * Function: Test cameraInput closeDelayed while deviceObj_ is null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput closeDelayed while deviceObj_ is null
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_022, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    int32_t delayTime = 1;
    EXPECT_EQ(input->closeDelayed(delayTime), 0);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with open camera device concurrently
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameradevice with open camera device concurrently
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_023, TestSize.Level1)
{
    cameraManager_->cameraDeviceList_.clear();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::vector<bool> cameraConcurrentType = {};
    std::vector<std::vector<SceneMode>> modes = {};
    std::vector<std::vector<sptr<CameraOutputCapability>>> outputCapabilities = {};
    sptr<CameraDevice> deviceFront = nullptr;
    sptr<CameraDevice> deviceBack = nullptr;
    for (auto iterator : cameras) {
        MEDIA_INFO_LOG("camera_framework_input_unittest_022"
            "device id:%{public}s position: %{public}d, cameraType: %{public}d",
            iterator->GetID().c_str(), iterator->GetPosition(), iterator->GetCameraType());
        if (iterator->GetPosition() == CameraPosition::CAMERA_POSITION_FRONT &&
            iterator->GetCameraType() == CameraType::CAMERA_TYPE_DEFAULT) {
            deviceFront = iterator;
            MEDIA_INFO_LOG("camera_framework_input_unittest_022 deviceFront is not null");
        } else if (iterator->GetPosition() == CameraPosition::CAMERA_POSITION_BACK &&
                   iterator->GetCameraType() == CameraType::CAMERA_TYPE_DEFAULT) {
            MEDIA_INFO_LOG("camera_framework_input_unittest_022 deviceBack is not null");
            deviceBack = iterator;
        }
    }
    if (deviceFront != nullptr && deviceBack != nullptr) {
        MEDIA_INFO_LOG("camera_framework_input_unittest_022 device is not null");
        std::vector<sptr<CameraDevice>> concurrentCameras = {deviceFront, deviceBack};
        bool isSupported = cameraManager_->GetConcurrentType(concurrentCameras, cameraConcurrentType);
        if (isSupported) {
            MEDIA_INFO_LOG("camera_framework_input_unittest_022 can open concurrently");
            cameraManager_->GetCameraConcurrentInfos(
                concurrentCameras, cameraConcurrentType, modes, outputCapabilities);
        }
        if (outputCapabilities.size() != 0 && cameraConcurrentType.size() != 0) {
            MEDIA_INFO_LOG("camera_framework_input_unittest_022 outputCapabilities not empty");
            sptr<CameraInput> inputFront = cameraManager_->CreateCameraInput(deviceFront);
            sptr<CameraInput> inputBack = cameraManager_->CreateCameraInput(deviceFront);
            int32_t ret = inputFront->Open(cameraConcurrentType[0]);
            EXPECT_EQ(ret, 0);
            ret = inputFront->Close();
            EXPECT_EQ(ret, 0);
        }
    }
}

/*
 * Feature: Framework
 * Function: Test cameraInput device retry
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput device retry
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_024, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
 
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->ControlAuxiliary(AuxiliaryType::CONTRACTLENS, AuxiliaryStatus::AUXILIARY_ON);
}

/*
 * Feature: Framework
 * Function: Test cameraInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput of OnResult abnormal branches
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_025, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)input;

    std::shared_ptr<CameraDeviceServiceCallback> cameraDeviceServiceCallback_test =
        std::make_shared<CameraDeviceServiceCallback>();
    EXPECT_NE(cameraDeviceServiceCallback_test, nullptr);
    cameraInput->cameraObj_ = nullptr;
    cameraDeviceServiceCallback_test->camInput_ = cameraInput;
    const std::shared_ptr<OHOS::Camera::CameraMetadata> result;
    auto res = cameraDeviceServiceCallback_test->OnResult(0, result);
    EXPECT_EQ(res, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test cameraInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput of InitCameraInput
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_026, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)input;
    cameraInput->InitCameraInput();
}

/*
 * Feature: Framework
 * Function: Test cameraInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput of closeDelayed
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_027, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)input;
    cameraInput->cameraObj_ = nullptr;
    int32_t delayTime = 1;
    int32_t res = cameraInput->closeDelayed(delayTime);
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test cameraInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput of SetInputUsedAsPosition abnormal branches
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_028, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)input;
    cameraInput->positionMapping = {};
    CameraPosition usedAsPosition = CameraPosition::CAMERA_POSITION_UNSPECIFIED;
    cameraInput->SetInputUsedAsPosition(usedAsPosition);
}

/*
 * Feature: Framework
 * Function: Test cameraInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraInput of SetInputUsedAsPosition abnormal branches
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_029, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)input;
    cameraInput->cameraObj_ = cameras[0];
    cameraInput->RecoveryOldDevice();
}

/*
 * Feature: Framework
 * Function: Test CreateDeferredPhotoProcessingSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDeferredPhotoProcessingSession
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_026, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession =
        CameraManager::GetInstance()->CreateDeferredPhotoProcessingSession(
        userId_, std::make_shared<TestDeferredPhotoProcSessionCallback>());
 
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);
}
 
/*
 * Feature: Framework
 * Function: Test CreateDeferredVideoProcessingSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDeferredVideoProcessingSession
 */
HWTEST_F(CameraFrameworkInputUnit, camera_framework_input_unittest_027, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession =
        CameraManager::GetInstance()->CreateDeferredVideoProcessingSession(
        userId_, std::make_shared<TestDeferredVideoProcSessionCallback>());
 
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);
}
}
}
