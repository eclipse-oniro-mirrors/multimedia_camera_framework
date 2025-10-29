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
#include "hcamera_host_manager_unitest.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "output/sketch_wrapper.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;
using wptr = std::weak_ptr<OHOS::CameraStandard::HCameraHostManager>;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void HCameraHostManagerUnit::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnit::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void HCameraHostManagerUnit::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnit::TearDownTestCase started!");
}

void HCameraHostManagerUnit::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_001, TestSize.Level1)
{
    const std::string svcName;
    cameraHostManager_->RemoveCameraHost(svcName);
    const std::string clientName = "testClientName";
    const std::string cameraId = "132";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    cameraRestoreParam->mRestoreParamType = RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS;
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_002, TestSize.Level1)
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->SetMdmCheck(false);
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    const std::string cameraId = "dadsada";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager_->cameraDevices_.emplace(cameraId, cameraDevice);

    cameraHostManager_->cameraDevices_.emplace("dddddd", nullptr);
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    std::vector<std::string> cameraIds = {};
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    std::string cameraId = cameras[0]->GetID();
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameras(cameraIds), 0);
    cameraHostManager_->RemoveCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameraAbility(cameraId, ability), CAMERA_INVALID_ARG);
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, false), CAMERA_UNKNOWN_ERROR);

    cameraId = "HCameraHostManager";

    cameraHostManager_->AddCameraDevice(cameraId, nullptr);
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, true), CAMERA_INVALID_ARG);

    cameraHostManager_->CloseCameraDevice(cameraId);

    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameraAbility(cameraId, ability), CAMERA_INVALID_ARG);

    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetVersionByCamera(cameraId), 0);

    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> pDevice;

    int32_t ret = cameraHostManager_->HCameraHostManager::OpenCameraDevice(cameraId, nullptr, pDevice);

    if (!ret) {
        cameraId = cameras[0]->GetID();
        HDI::ServiceManager::V1_0::ServiceStatus status;
        status.deviceClass = DEVICE_CLASS_CAMERA;
        status.serviceName = "distributed_camera_service";
        status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_START;
        cameraHostManager_->GetRegisterServStatListener()->OnReceive(status);
        EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, false), CAMERA_INVALID_ARG);
    }

    cameraHostManager_->DeInit();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam normal branches.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_007, TestSize.Level1)
{
    const std::string clientName1 = "testClientName1";
    const std::string clientName2 = "testClientName2";
    const std::string clientName3 = "testClientName3";
    const std::string cameraId1 = "123";
    const std::string cameraId2 = "456";
    const std::string cameraId3 = "789";
    sptr<HCameraRestoreParam> cameraRestoreParam1 = cameraHostManager_->GetRestoreParam(clientName1, cameraId1);
    cameraRestoreParam1->mCloseCameraTime = {0, 0};
    sptr<HCameraRestoreParam> cameraRestoreParam2 = cameraHostManager_->GetRestoreParam(clientName2, cameraId2);
    timeval closeTime;
    gettimeofday(&closeTime, nullptr);
    cameraRestoreParam2->mCloseCameraTime = closeTime;
    
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam1);
    cameraHostManager_->persistentParamMap_.emplace(clientName1,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId1, cameraRestoreParam1}});
    cameraHostManager_->persistentParamMap_.emplace(clientName2,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId1, cameraRestoreParam2}});
    EXPECT_EQ(cameraHostManager_->persistentParamMap_.size(), 2);

    cameraHostManager_->DeleteRestoreParam(clientName3, cameraId3);
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam1);
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam2);

    cameraHostManager_->persistentParamMap_.erase(clientName2);
    cameraHostManager_->persistentParamMap_.emplace(clientName2,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId2, cameraRestoreParam2}});
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam2);

    cameraRestoreParam1->mRestoreParamType = RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS;
    cameraHostManager_->SaveRestoreParam(cameraRestoreParam1);
    EXPECT_EQ(cameraHostManager_->persistentParamMap_.size(), 2);
}

/*
 * Feature: Framework
 * Function: Test CheckCameraId.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckCameraId normal branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_010, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    const std::string cameraId = "123465";
    const std::string checkCameraId = "654981";
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    bool result = cameraHostManager_->CheckCameraId(cameraRestoreParam, checkCameraId);
    EXPECT_FALSE(result);
}

/*
 * Feature: Framework
 * Function: Test CheckCameraId.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckCameraId abnormal branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_011, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    const std::string cameraId = "123465";
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    bool result = cameraHostManager_->CheckCameraId(cameraRestoreParam, cameraId);
    EXPECT_TRUE(result);
}

/*
 * Feature: Framework
 * Function: Test AddCameraDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddCameraDevice abnormal branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_012, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    const std::string cameraId = "dadsada";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager_->AddCameraDevice(cameraId, cameraDevice);
    cameraHostManager_->AddCameraDevice(cameraId, cameraDevice);
    cameraHostManager_->RemoveCameraDevice(cameraId);
    cameraHostManager_->CloseCameraDevice(cameraId);
    EXPECT_EQ(cameraHostManager_->cameraDevices_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test RemoveCameraDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveCameraDevice abnormal branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_013, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    const std::string cameraId1 = "dadsada";
    const std::string cameraId2 = "dfdfdss";
    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    cameraHostManager_->AddCameraDevice(cameraId1, cameraDevice);
    cameraHostManager_->RemoveCameraDevice(cameraId2);
    cameraHostManager_->AddCameraDevice(cameraId2, cameraDevice);
    cameraHostManager_->RemoveCameraDevice(cameraId1);
    cameraHostManager_->CloseCameraDevice(cameraId1);
    EXPECT_NE(cameraHostManager_->cameraDevices_.size(), 0);
    cameraHostManager_->RemoveCameraDevice(cameraId2);
    cameraHostManager_->CloseCameraDevice(cameraId2);
}

/*
 * Feature: Framework
 * Function: Test SetTorchLevel.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetTorchLevel abnormal branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_014, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    cameraHostManager_->RemoveCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    EXPECT_NE(cameraHostManager_->HCameraHostManager::SetTorchLevel(0), CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test NotifyDeviceStateChangeInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NotifyDeviceStateChangeInfo normal branch.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_015, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    cameraHostManager_->RemoveCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    cameraHostManager_->NotifyDeviceStateChangeInfo(1, 2);
    cameraHostManager_->AddCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    cameraHostManager_->NotifyDeviceStateChangeInfo(1, 2);
}

} // CameraStandard
} // OHOS