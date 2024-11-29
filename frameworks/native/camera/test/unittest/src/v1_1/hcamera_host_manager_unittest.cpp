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
#include "hcamera_host_manager_unittest.h"
#include "ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;
using wptr = std::weak_ptr<OHOS::CameraStandard::HCameraHostManager>;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void HCameraHostManagerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnitTest::SetUpTestCase started!");
}

void HCameraHostManagerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnitTest::TearDownTestCase started!");
}

void HCameraHostManagerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
}

void HCameraHostManagerUnitTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    if (cameraManager_!= nullptr) {
        cameraManager_ = nullptr;
    }
}

void HCameraHostManagerUnitTest::NativeAuthorization()
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
HWTEST_F(HCameraHostManagerUnitTest, hcamera_host_manager_unittest_001, TestSize.Level0)
{
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(cameraHostManager, nullptr);
    
    const std::string svcName;
    cameraHostManager->RemoveCameraHost(svcName);
    const std::string clientName = "testClientName";
    const std::string cameraId = "132";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager->GetRestoreParam(clientName, cameraId);
    cameraHostManager->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    cameraRestoreParam->mRestoreParamType = TRANSIENT_ACTIVE_PARAM_OHOS;
    cameraHostManager->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    cameraHostManager->SaveRestoreParam(cameraRestoreParam);
    cameraHostManager->DeleteRestoreParam(clientName, cameraId);
    cameraHostManager->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    cameraHostManager->UpdateRestoreParamCloseTime(clientName, cameraId);
    EXPECT_NE(cameraHostManager->persistentParamMap_.size(), 0);
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
HWTEST_F(HCameraHostManagerUnitTest, hcamera_host_manager_unittest_002, TestSize.Level0)
{
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(cameraHostManager, nullptr);

    int notifyType = 1;
    int deviceState = 2;
    cameraHostManager->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    const std::string cameraId = "123465";
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager->GetRestoreParam(clientName, cameraId);
    cameraRestoreParam->mRestoreParamType = RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS;
    int32_t result = cameraHostManager->Prelaunch(cameraId, clientName);
    cameraRestoreParam->mFoldStatus = 1;
    result = cameraHostManager->Prelaunch(cameraId, clientName);
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
HWTEST_F(HCameraHostManagerUnitTest, hcamera_host_manager_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    
    const std::string cameraId = "dadsada";
    const std::string clientName = "testClientName";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager->cameraDevices_.emplace(cameraId, cameraDevice);
    cameraHostManager->AddCameraDevice(cameraId, cameraDevice);
    cameraHostManager->RemoveCameraDevice(cameraId);
    cameraHostManager->CloseCameraDevice(cameraId);
    EXPECT_EQ(cameraHostManager->cameraDevices_.size(), 0);
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
HWTEST_F(HCameraHostManagerUnitTest, hcamera_host_manager_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    ASSERT_NE(input, nullptr);

    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    bool result = cameraHostManager->Init();
    HDI::ServiceManager::V1_0::ServiceStatus status;

    status.serviceName = "1";
    cameraHostManager->GetRegisterServStatListener()->OnReceive(status);
    status.deviceClass = DEVICE_CLASS_CAMERA;
    status.serviceName = HCameraHostManager::DISTRIBUTED_SERVICE_NAME;
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_START;
    cameraHostManager->GetRegisterServStatListener()->OnReceive(status);
    cameraHostManager->GetRegisterServStatListener()->OnReceive(status);
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP;
    cameraHostManager->GetRegisterServStatListener()->OnReceive(status);
    status.status = 4;
    cameraHostManager->GetRegisterServStatListener()->OnReceive(status);
    result = cameraHostManager->Init();
    cameraHostManager->DeInit();
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
HWTEST_F(HCameraHostManagerUnitTest, hcamera_host_manager_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    
    const std::string cameraId = "dadsada";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager->cameraDevices_.emplace(cameraId, cameraDevice);
    cameraHostManager->~HCameraHostManager();

    cameraHostManager->cameraDevices_.emplace("dddddd", nullptr);
    cameraHostManager->~HCameraHostManager();
    EXPECT_NE(cameraHostManager->cameraDevices_.size(), 0);
}
}
}
