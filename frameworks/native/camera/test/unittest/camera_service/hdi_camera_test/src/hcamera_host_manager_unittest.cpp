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
    if (cameraHostManager_ != nullptr) {
        if (cameraHostManager_->GetRegisterServStatListener() != nullptr) {
            cameraHostManager_->DeInit();
        }
        if (!cameraHostManager_->IsCameraHostInfoAdded(HCameraHostManager::LOCAL_SERVICE_NAME)) {
            cameraHostManager_->AddCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
        }
        cameraHostManager_ = nullptr;
    }
    if (cameraManager_ != nullptr) {
        cameraManager_ = nullptr;
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_001, TestSize.Level0)
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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
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
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    std::vector<std::string> cameraIds = {};
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    std::string cameraId = cameras[0]->GetID();
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameras(cameraIds), 0);
    cameraHostManager_->RemoveCameraHost( HCameraHostManager::LOCAL_SERVICE_NAME);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::GetCameraAbility(cameraId, ability), CAMERA_INVALID_ARG);
    EXPECT_EQ(cameraHostManager_->HCameraHostManager::SetFlashlight(cameraId, false), CAMERA_INVALID_ARG);

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
 * Function: Test EntireCloseDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EntireCloseDevice.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
    std::vector<std::string> cameraIds = {};
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    std::string cameraId = "123465";
    cameraHostManager_->EntireCloseDevice(cameraId);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam normal branches.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_008, TestSize.Level1)
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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

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
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);

    cameraHostManager_->RemoveCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    cameraHostManager_->NotifyDeviceStateChangeInfo(1, 2);
    cameraHostManager_->AddCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    cameraHostManager_->NotifyDeviceStateChangeInfo(1, 2);
}

/*
 * Feature: Framework
 * Function: Test GetRestoreParam with persistent param
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetRestoreParam when persistent param exists.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_016, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    
    sptr<HCameraRestoreParam> result = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetRestoreParam with transitent param
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetRestoreParam when only transitent param exists.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_017, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    
    sptr<HCameraRestoreParam> result = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetTransitentParam with valid clientName and cameraId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTransitentParam when transitent param exists and cameraId matches.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_018, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    
    sptr<HCameraRestoreParam> result = cameraHostManager_->GetTransitentParam(clientName, cameraId);
    ASSERT_NE(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetTransitentParam with non-existent clientName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTransitentParam when transitent param does not exist.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_019, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    
    sptr<HCameraRestoreParam> result = cameraHostManager_->GetTransitentParam(clientName, cameraId);
    ASSERT_NE(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetTransitentParam with mismatched cameraId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTransitentParam when cameraId does not match.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_020, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId1 = "123";
    const std::string cameraId2 = "456";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId1);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    
    sptr<HCameraRestoreParam> result = cameraHostManager_->GetTransitentParam(clientName, cameraId2);
    ASSERT_NE(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam with isSupportExposureSet == true and timeInterval < threshold
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam when exposure is supported and time interval is less than threshold.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_021, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    timeval closeTime;
    gettimeofday(&closeTime, nullptr);
    cameraRestoreParam->SetCloseCameraTime(closeTime);
    cameraRestoreParam->SetStartActiveTime(100);
    
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam);
    ASSERT_NE(cameraRestoreParam, nullptr);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam with isSupportExposureSet == true and timeInterval >= threshold
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam when exposure is supported and time interval is greater than threshold.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_022, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    timeval closeTime;
    gettimeofday(&closeTime, nullptr);
    closeTime.tv_sec -= 200;
    cameraRestoreParam->SetCloseCameraTime(closeTime);
    cameraRestoreParam->SetStartActiveTime(1);
    
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam);
    ASSERT_NE(cameraRestoreParam, nullptr);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam with usec_diff < 0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam when usec_diff is negative.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_023, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    timeval closeTime;
    gettimeofday(&closeTime, nullptr);
    closeTime.tv_sec -= 1;
    closeTime.tv_usec += 1000000;
    cameraRestoreParam->SetCloseCameraTime(closeTime);
    cameraRestoreParam->SetStartActiveTime(100);
    
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam);
    ASSERT_NE(cameraRestoreParam, nullptr);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with muteMode == true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when muteMode is true, which will call UpdateMuteSetting.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_024, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(true);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with muteMode == false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when muteMode is false.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_025, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with setting == nullptr and muteMode == true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when setting is nullptr and muteMode is true, which will test UpdateMuteSetting with nullptr.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_026, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> nullSettings = nullptr;
    cameraRestoreParam->SetSetting(nullSettings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(true);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with opMode == 0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when opMode is 0, which will test IsNeedRestore with opMode == 0.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_027, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetCameraOpMode(0);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with opMode != 0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when opMode is not 0, which will test IsNeedRestore with opMode != 0.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_028, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetCameraOpMode(1);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test GetRestoreParam with empty persistentParamMap and empty transitentParamMap
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetRestoreParam when both persistentParamMap and transitentParamMap are empty.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_029, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    
    sptr<HCameraRestoreParam> result = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam with isSupportExposureSet == false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam when isSupportExposureSet is false.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_030, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId = "123";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    timeval closeTime = {0, 0};
    cameraRestoreParam->SetCloseCameraTime(closeTime);
    
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId, cameraRestoreParam}});
    
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam);
    ASSERT_NE(cameraRestoreParam, nullptr);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreParam with mismatched cameraId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreParam when cameraId does not match.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_031, TestSize.Level1)
{
    const std::string clientName = "testClientName";
    const std::string cameraId1 = "123";
    const std::string cameraId2 = "456";
    sptr<HCameraRestoreParam> cameraRestoreParam1 = cameraHostManager_->GetRestoreParam(clientName, cameraId1);
    ASSERT_NE(cameraRestoreParam1, nullptr);
    sptr<HCameraRestoreParam> cameraRestoreParam2 = cameraHostManager_->GetRestoreParam(clientName, cameraId2);
    ASSERT_NE(cameraRestoreParam2, nullptr);
    
    timeval closeTime;
    gettimeofday(&closeTime, nullptr);
    cameraRestoreParam1->SetCloseCameraTime(closeTime);
    cameraRestoreParam1->SetStartActiveTime(100);
    
    cameraHostManager_->persistentParamMap_.emplace(clientName,
        std::map<std::string, sptr<HCameraRestoreParam>>{{cameraId1, cameraRestoreParam1}});
    
    cameraHostManager_->UpdateRestoreParam(cameraRestoreParam2);
    ASSERT_NE(cameraRestoreParam2, nullptr);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with ret == 0 and PERSISTENT_DEFAULT_PARAM_OHOS
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when ret == 0 and restoreParamType is PERSISTENT_DEFAULT_PARAM_OHOS.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_032, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with ret == 0 and TRANSIENT_ACTIVE_PARAM_OHOS
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when ret == 0 and restoreParamType is TRANSIENT_ACTIVE_PARAM_OHOS.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_033, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with it != transitentParamMap_.end() and CheckCameraId returns true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when transitent param exists and cameraId matches.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_034, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
    EXPECT_NE(cameraHostManager_->transitentParamMap_.find(clientName), cameraHostManager_->transitentParamMap_.end());
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with it == transitentParamMap_.end()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when transitent param does not exist.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_035, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId = cameras[0]->GetID();
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId, clientName);
    EXPECT_TRUE(result >= 0);
}

/*
 * Feature: Framework
 * Function: Test Prelaunch with CheckCameraId returns false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Prelaunch when transitent param exists but cameraId does not match.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_036, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    const std::string cameraId1 = cameras[0]->GetID();
    const std::string cameraId2 = "different_camera_id";
    std::string clientName = "testClientName";
    sptr<HCameraRestoreParam> cameraRestoreParam = cameraHostManager_->GetRestoreParam(clientName, cameraId1);
    ASSERT_NE(cameraRestoreParam, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = 
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    cameraRestoreParam->SetSetting(settings);
    cameraRestoreParam->SetRestoreParamType(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS);
    cameraHostManager_->transitentParamMap_.emplace(clientName, cameraRestoreParam);
    
    cameraHostManager_->SetMuteMode(false);
    int32_t result = cameraHostManager_->Prelaunch(cameraId2, clientName);
    EXPECT_TRUE(result >= 0);
    EXPECT_NE(cameraHostManager_->transitentParamMap_.find(clientName), cameraHostManager_->transitentParamMap_.end());
}

/*
 * Feature: Framework
 * Function: Test NotifyDeviceStateChangeInfo with cameraHostProxyV1_3_ != nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NotifyDeviceStateChangeInfo when cameraHostProxyV1_3_ is not nullptr.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_037, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    cameraHostManager_->NotifyDeviceStateChangeInfo(1, 2);
    ASSERT_NE(cameraHostManager_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test NotifyDeviceStateChangeInfo with cameraHostProxyV1_2_ != nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NotifyDeviceStateChangeInfo when cameraHostProxyV1_2_ is not nullptr.
 */
HWTEST_F(HCameraHostManagerUnit, hcamera_host_manager_unittest_038, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    cameraHostManager_->Init();
    ASSERT_NE(cameraHostManager_, nullptr);
    
    cameraHostManager_->RemoveCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    cameraHostManager_->AddCameraHost(HCameraHostManager::LOCAL_SERVICE_NAME);
    ASSERT_NE(cameraHostManager_, nullptr);
    
    cameraHostManager_->NotifyDeviceStateChangeInfo(1, 2);
    ASSERT_NE(cameraHostManager_, nullptr);
}
} // CameraStandard
} // OHOS