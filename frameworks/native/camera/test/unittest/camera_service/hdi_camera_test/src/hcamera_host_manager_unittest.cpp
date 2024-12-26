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
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "output/sketch_wrapper.h"
#include "hcamera_service.h"
#include "hcamera_host_manager_unitest.h"
#include "ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;
using wptr = std::weak_ptr<OHOS::CameraStandard::HCameraHostManager>;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void HCameraHostManagerUnit::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnit::SetUpTestCase started!");
}

void HCameraHostManagerUnit::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnit::TearDownTestCase started!");
}

void HCameraHostManagerUnit::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
    NativeAuthorization();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    ASSERT_NE(cameraHostManager_, nullptr);
    cameraManager_ = CameraManager::GetInstance();
}

void HCameraHostManagerUnit::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    if (cameraManager_ != nullptr) {
        cameraManager_ = nullptr;
    }
    if (cameraHostManager_ != nullptr) {
        cameraHostManager_ = nullptr;
    }
}

void HCameraHostManagerUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraInputUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test DeleteRestoreParam.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeleteRestoreParam, when clientName and cameraId are passed in.
 *  The expected result is that the CaptureInput object remains valid after the deletion operation,
 *  and this operation does not cause any exceptions or errors.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_001, TestSize.Level0)
{
    const std::string svcName;
    cameraHostManager_->RemoveCameraHost(svcName);
    const std::string clientName = "testClientName";
    const std::string cameraId = "132";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    cameraRestoreParam->mRestoreParamType = TRANSIENT_ACTIVE_PARAM_OHOS;
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    cameraHostManager_->SaveRestoreParam(cameraRestoreParam);
    cameraHostManager_->DeleteRestoreParam(clientName, cameraId);
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    cameraHostManager_->UpdateRestoreParamCloseTime(clientName, cameraId);
    EXPECT_NE(cameraHostManager_->persistentParamMap_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch, set the fold status to 1. Pass in cameraId and clientName to
 *  call the Prelaunch method. The expected result is that the Prelaunch method returns 2,
 *  indicating that the pre-launch operation is successful or has reached the expected state.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_002, TestSize.Level0)
{
    int notifyType = 1;
    int deviceState = 2;
    cameraHostManager_->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    const std::string cameraId = "123465";
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    cameraRestoreParam->mRestoreParamType = RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS;
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    cameraRestoreParam->mFoldStatus = 1;
    result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test AddCameraDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddCameraDevice, pass in cameraId and clientName to add them to the cameraDevices_.
 *  The expected result is that the camera device can be successfully
 *  added to the map without causing any exceptions or errors.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    const std::string cameraId = "dadsada";
    const std::string clientName = "testClientName";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager_->cameraDevices_.emplace(cameraId, cameraDevice);
    cameraHostManager_->AddCameraDevice(cameraId, cameraDevice);
    cameraHostManager_->RemoveCameraDevice(cameraId);
    cameraHostManager_->CloseCameraDevice(cameraId);
    EXPECT_EQ(cameraHostManager_->cameraDevices_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test Init.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Init, simulate the service status listener receiving different service states.
 *  The expected result is that throughout the initialization and de-initialization process,
 *  the HCameraHostManager object can correctly respond to service state changes,
 *  and will not cause any exceptions or errors during the operation.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    ASSERT_NE(input, nullptr);

    bool result = cameraHostManager_->Init();
    HDI::ServiceManager::V1_0::ServiceStatus status;

    status.serviceName = "1";
    cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
    status.deviceClass = DEVICE_CLASS_CAMERA;
    status.serviceName = HCameraHostManager::DISTRIBUTED_SERVICE_NAME;
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_START;
    cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
    cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP;
    cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
    status.status = 4;
    cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
    result = cameraHostManager_->Init();
    cameraHostManager_->DeInit();
    input->Close();
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test ~HCameraHostManager.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraHostManager, add a camera device to the cameraDevices_.
 *  The expected result is that throughout the destruction process, the HCameraHostManager
 *  object can correctly handle the camera devices in the map, and will not cause any
 *  exceptions or errors during the operation.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    const std::string cameraId = "dadsada";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager_->cameraDevices_.emplace(cameraId, cameraDevice);
    cameraHostManager_->~HCameraHostManager();

    cameraHostManager_->cameraDevices_.emplace("dddddd", nullptr);
    cameraHostManager_->~HCameraHostManager();
    EXPECT_NE(cameraHostManager_->cameraDevices_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraHostManager with anomalous branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    std::vector<std::string> cameraIds = {};
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    std::string cameraId = cameras[0]->GetID();
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameras(cameraIds), 0);
    cameraHostManager_->RemoveCameraHost( HCameraHostManager::LOCAL_SERVICE_NAME);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameras[0]->GetMetadata();
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameraAbility(cameraId, ability), CAMERA_INVALID_ARG);
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, false), CAMERA_INVALID_ARG);

    cameraId = "HCameraHostManager";

    cameraHostManager_->AddCameraDevice(cameraId, nullptr);
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, true), CAMERA_INVALID_ARG);

    cameraHostManager_->CloseCameraDevice(cameraId);

    ability = cameras[0]->GetMetadata();
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameraAbility(cameraId, ability), CAMERA_INVALID_ARG);

    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetVersionByCamera(cameraId), 0);

    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> pDevice;
    cameraHostManager_->HCameraHostManager::OpenCameraDevice(cameraId, nullptr, pDevice);

    cameraId = cameras[0]->GetID();
    HDI::ServiceManager::V1_0::ServiceStatus status;
    status.deviceClass = DEVICE_CLASS_CAMERA;
    status.serviceName = "distributed_camera_service";
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_START;
    cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, false), CAMERA_INVALID_ARG);
    cameraHostManager_->DeInit();
    input->Close();
}

}
}