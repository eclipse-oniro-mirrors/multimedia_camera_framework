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

#include "gmock/gmock.h"
#include "hcamera_device_unittest.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "output/sketch_wrapper.h"
#include "test_token.h"
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
#include "res_value.h"
#endif

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

const std::string LOCAL_SERVICE_NAME = "camera_service";

void HCameraDeviceUnit::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnit::SetUpTestCase started!");
    auto tt = TestToken();
    tt.AddPermission("ohos.permission.START_SYSTEM_DIALOG");
    ASSERT_TRUE(tt.GetAllCameraPermission());
}

void HCameraDeviceUnit::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnit::TearDownTestCase started!");
}

void HCameraDeviceUnit::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
    cameraHostManager_ = new HCameraHostManager(nullptr);
    cameraManager_ = CameraManager::GetInstance();
}

void HCameraDeviceUnit::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    cameraHostManager_ = nullptr;
    cameraManager_ = nullptr;
    MEDIA_INFO_LOG("TearDown end");
}

/*
 * Feature: Framework
 * Function: Test GetSecureCameraSeq.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSecureCameraSeq, set the isHasOpenSecure member to true.
 *  The expected result is that the GetSecureCameraSeq method can correctly handle
 *  this situation and return CAMERA_OK, indicating that the secure camera sequence
 *  has been successfully obtained, and no exceptions or errors will occur during the operation.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint64_t secureSeqId = 0;
    camDevice->isHasOpenSecure = true;
    int32_t result = camDevice->GetSecureCameraSeq(&secureSeqId);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test ResetZoomTimer.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ResetZoomTimer, set the inPrepareZoom_ member to true to simulate the
 *  camera preparing to zoom. The expected result is that the ResetZoomTimer method can correctly
 *  reset the zoom timer, ensuring that zoom operations can be restarted when needed, and no exceptions
 *  or errors will occur during the operation.
 * Test HandlePrivacyWhenOpenDeviceFail, Set cameraPrivacy_ to nullptr and set cameraPid_ to 0.
 *  The expected result is that the HandlePrivacyWhenOpenDeviceFail method can correctly handle privacy,
 *  ensuring that when the device open fails, the relevant privacy settings are properly reset or cleared,
 *  and no exceptions or errors will occur during the operation.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    
    camDevice->SetMdmCheck(false);
    camDevice->HandlePrivacyWhenOpenDeviceFail();

    camDevice->cameraPrivacy_ = nullptr;
    camDevice->cameraPid_ = 0;
    camDevice->HandlePrivacyWhenOpenDeviceFail();

    camDevice->inPrepareZoom_ = true;
    camDevice->ResetZoomTimer();
    EXPECT_EQ(camDevice->inPrepareZoom_.load(), true);
}

/*
 * Feature: Framework
 * Function: Test SetCallback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCallback, call the SetCallback method and pass in a nullptr callback object to
 *  simulate setting an empty callback. The expected result is that the SetCallback method can correctly handle
 *  the empty callback situation and return CAMERA_OK, indicating that the operation is successful.
 * Test UpdateDeviceOpenLifeCycleSettings, call the UpdateDeviceOpenLifeCycleSettings method and
 *  pass in an empty shared_ptr as the change settings, set the deviceOpenLifeCycleSettings_ member to nullptr,
 *  the expected result is that the method can correctly handle these situations and will not cause any
 *  exceptions or errors during the operation.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->RegisterFoldStatusListener();
    camDevice->UnregisterFoldStatusListener();

    std::shared_ptr<OHOS::Camera::CameraMetadata> changedSettings;
    camDevice->UpdateDeviceOpenLifeCycleSettings(changedSettings);
    changedSettings = nullptr;
    camDevice->UpdateDeviceOpenLifeCycleSettings(changedSettings);

    sptr<ICameraDeviceServiceCallback> callback = nullptr;
    int32_t result = camDevice->SetCallback(callback);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OperatePermissionCheck, the test includes checking the CAMERA_DEVICE_OPEN
 *  interface code, expecting to return CAMERA_OK; checking the CAMERA_DEVICE_DISABLED_RESULT interface code,
 *  expecting to return 0; and checking an invalid interface code, also expecting to return CAMERA_OK.
 *  The expected result is that the method can correctly perform permission checks based on different
 *  interface codes and will not cause any exceptions or errors during the operation.
 * Test CheckOnResultData, call the CheckOnResultData method and pass in an empty shared_ptr as the
 *  camera result data. Then, obtain the metadata of the first camera and assign it to cameraResult.
 *  The expected result is that the method can handle this correctly and will not cause any
 *  exceptions or errors during the operation.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult;
    camDevice->CheckOnResultData(cameraResult);
    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);
    cameraProxy->GetCameraAbility(cameraId, cameraResult);
    ASSERT_NE(cameraResult, nullptr);
    camDevice->CheckOnResultData(cameraResult);

    uint32_t interfaceCode = 0;
    int32_t result = camDevice->OperatePermissionCheck(interfaceCode);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test GetCameraType.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraType, set the client name clientName_ to "com.example.camera" and
 *  call the GetCameraType method to retrieve the camera type.
 *  The expected result is that the GetCameraType method returns the SYSTEM type.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->clientName_ = "com.huawei.hmos.camera";
    int32_t result = camDevice->GetCameraType();
    EXPECT_EQ(result, SYSTEM);
}

/*
 * Feature: Framework
 * Function: Test DispatchDefaultSettingToHdi.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DispatchDefaultSettingToHdi, set the item_count attribute of the deviceOpenLifeCycleSettings_
 *  member to 1 and call the method. The expected result is that the DispatchDefaultSettingToHdi method returns 10,
 *  indicating that the default settings have been successfully dispatched to the HDI.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->deviceOpenLifeCycleSettings_->get()->item_count = 1;
    int32_t result = camDevice->DispatchDefaultSettingToHdi();
    EXPECT_NE(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CheckPermissionBeforeOpenDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckPermissionBeforeOpenDevice, set the callerToken_ to 1 and
 *  call the CheckPermissionBeforeOpenDevice method to perform the permission check.
 *  The expected result is that the CheckPermissionBeforeOpenDevice method returns 13,
 *  and no exceptions or errors will occur during the operation.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->callerToken_ = 1;
    int32_t result = camDevice->CheckPermissionBeforeOpenDevice();
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test HandlePrivacyBeforeOpenDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HandlePrivacyBeforeOpenDevice, set the callerToken_ to 1 and call the method to
 *  handle privacy permissions. Set the camera process ID cameraPid_ to 100. The expected result is that
 *  in both cases, the HandlePrivacyBeforeOpenDevice method returns false.
 * Test HandlePrivacyAfterCloseDevice, set cameraPrivacy_ to nullptr and set cameraPid_ to 1 to simulate the
 *  privacy state after the device is closed. The expected result is that the HandlePrivacyAfterCloseDevice
 *  method can correctly execute privacy permission processing, ensuring that privacy is properly managed after
 *  the device is closed.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->SetMdmCheck(false);
    camDevice->cameraPrivacy_ = nullptr;
    camDevice->cameraPid_ = 1;
    camDevice->HandlePrivacyAfterCloseDevice();

    camDevice->callerToken_ = 1;
    bool result = camDevice->HandlePrivacyBeforeOpenDevice();
    EXPECT_EQ(result, false);

    camDevice->cameraPid_ = 1;
    result = camDevice->HandlePrivacyBeforeOpenDevice();
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test CloseDevice.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CloseDevice, set the hdiCameraDevice_ member to nullptr and verify
 *  that hdiCameraDevice_ remains nullptr. Set the cameraHostManager_ member to nullptr and
 *  call the method again to verify that the return result is CAMERA_OK.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->hdiCameraDevice_ = nullptr;
    camDevice->CloseDevice();
    EXPECT_EQ(camDevice->hdiCameraDevice_, nullptr);

    camDevice->cameraHostManager_ = nullptr;
    int32_t result = camDevice->CloseDevice();
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice with anomalous branch
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_010, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    auto peerCallback = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(peerCallback, nullptr);
    pid_t pid = 1234;
    HCameraDeviceManager::GetInstance()->peerCallbacks_[pid] = peerCallback;
    camDevice -> SetMdmCheck(false);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);

    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);

    ret = camDevice->HCameraDevice::EnableResult(result);
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::DisableResult(result);
    EXPECT_EQ(ret, 0);

    // sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = camDevice->HCameraDevice::GetStreamOperator();
    // EXPECT_TRUE(streamOperator != nullptr);

    ret = camDevice->HCameraDevice::OnError(REQUEST_TIMEOUT, 0);
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::Close();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice with anomalous branch.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_011, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = nullptr;
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<ICameraDeviceServiceCallback> callback1 = new (std::nothrow) CameraDeviceServiceCallback(input);
    ASSERT_NE(callback1, nullptr);

    camDevice->EnableResult(result);
    camDevice->DisableResult(result);
    camDevice->SetMdmCheck(false);
    int32_t ret = camDevice->Open();
    EXPECT_EQ(ret, 0);
    camDevice->UpdateSetting(nullptr);
    sptr<ICameraDeviceServiceCallback> callback = nullptr;
    camDevice->SetCallback(callback);
    camDevice->GetDeviceAbility();
    camDevice->SetCallback(callback1);
    camDevice->OnError(REQUEST_TIMEOUT, 0) ;
    camDevice->OnError(DEVICE_PREEMPT, 0) ;
    camDevice->OnError(DRIVER_ERROR, 0) ;

    EXPECT_EQ(camDevice->Close(), 0);
    EXPECT_EQ(camDevice->GetEnabledResults(result), 11);
    EXPECT_EQ(camDevice->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_012, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    uint32_t callerToken1 = 3;
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    sptr<HCameraDevice> camDevice1 = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken1);
    ASSERT_NE(camDevice1, nullptr);

    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = nullptr;
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<ICameraDeviceServiceCallback> callback1 = new (std::nothrow) CameraDeviceServiceCallback(input);
    ASSERT_NE(callback1, nullptr);
    camDevice->EnableResult(result);
    camDevice->DisableResult(result);
    camDevice->SetMdmCheck(false);
    int32_t ret = camDevice->Open();
    EXPECT_EQ(ret, 0);
    camDevice->Open();
    camDevice->Close();
    camDevice->GetDeviceAbility();
    EXPECT_EQ(camDevice->Open(), 0);

    camDevice->Close();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when settings is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when settings is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_013, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    EXPECT_EQ(camDevice->UpdateSettingOnce(settings), CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_014, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    cameraProxy->GetCameraAbility(cameraId, settings);
    ASSERT_NE(settings, nullptr);
    EXPECT_EQ(camDevice->UpdateSettingOnce(settings), 0);

    camDevice->RegisterFoldStatusListener();
    camDevice->UnregisterFoldStatusListener();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_015, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    camDevice->UnregisterFoldStatusListener();
    camDevice->RegisterFoldStatusListener();
    camDevice->UnregisterFoldStatusListener();
    camDevice->cameraHostManager_ = nullptr;
    camDevice->RegisterFoldStatusListener();
    camDevice->UnregisterFoldStatusListener();

    std::vector<int32_t> results = {};
    EXPECT_EQ(camDevice->EnableResult(results), CAMERA_INVALID_ARG);
    EXPECT_EQ(camDevice->DisableResult(results), CAMERA_INVALID_ARG);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut;
    EXPECT_EQ(camDevice->GetStatus(metaIn, metaOut), CAMERA_INVALID_ARG);

    camDevice->Close();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when hdiCameraDevice_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when hdiCameraDevice_ is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_016, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    camDevice->hdiCameraDevice_ = nullptr;
    sptr<IStreamOperatorCallback> callbackObj = nullptr;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> hStreamOperator = nullptr;
    EXPECT_EQ(camDevice->GetStreamOperator(callbackObj, hStreamOperator), CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_022, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
    }
    camInput->GetCameraDevice()->Open();

    sptr<HCameraService> cameraService = new (std::nothrow) HCameraService(cameraHostManager_);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = cameraService->SetCameraCallback(callback, true);
    EXPECT_EQ(intResult, 2);

    callback = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);
    intResult = cameraService->SetCameraCallback(callback, true);
    EXPECT_EQ(intResult, 0);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<ICameraMuteServiceCallback> callback_2 = nullptr;
    intResult = cameraService->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 2);

    callback_2 = cameraManager_->GetCameraMuteListenerManager();
    ASSERT_NE(callback_2, nullptr);
    intResult = cameraService->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 0);

    std::string cameraId = camInput->GetCameraId();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraService->cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    ASSERT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraAbility, nullptr);

    OHOS::Camera::DeleteCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_PRELAUNCH_AVAILABLE);
    int activeTime = 0;
    EffectParam effectParam = {0, 0, 0};
    intResult = cameraService->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);

    intResult = cameraService->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS,
    activeTime, effectParam);
    EXPECT_EQ(intResult, 2);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test BuildDeviceProtectionDialogCommand
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test BuildDeviceProtectionDialogCommand
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_023, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    std::string commandStr = camDevice->BuildDeviceProtectionDialogCommand(OHOS_DEVICE_EJECT_BLOCK);
    ASSERT_NE(commandStr, "");
    commandStr = camDevice->BuildDeviceProtectionDialogCommand(OHOS_DEVICE_EXTERNAL_PRESS);
    ASSERT_NE(commandStr, "");
}

/*
 * Feature: Framework
 * Function: Test ShowDeviceProtectionDialog
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ShowDeviceProtectionDialog
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_024, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    bool ret = camDevice->ShowDeviceProtectionDialog(OHOS_DEVICE_EJECT_BLOCK);
    ASSERT_TRUE(ret);
    ret = camDevice->ShowDeviceProtectionDialog(OHOS_DEVICE_EXTERNAL_PRESS);
    ASSERT_TRUE(ret);
}

/*
 * Feature: Framework
 * Function: Test DeviceEjectCallBack
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeviceEjectCallBack
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_025, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    camDevice->DeviceEjectCallBack();
}

/*
 * Feature: Framework
 * Function: Test ReportDeviceProtectionStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportDeviceProtectionStatus
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_026, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint32_t count = 1;
    int32_t status = 2;
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    metadata->addEntry(OHOS_DEVICE_PROTECTION_STATE, &status, count);
    camDevice->clientName_ = "com.huawei.hmos.camera";
    camDevice->ReportDeviceProtectionStatus(metadata);
}

/*
 * Feature: Framework
 * Function: Test RegisterSensor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterSensor
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_027, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    camDevice->RegisterSensorCallback();
    camDevice->UnRegisterSensorCallback();
    Rosen::LoadMotionSensor();
    Rosen::UnloadMotionSensor();
}

/*
 * Feature: Framework
 * Function: Test RegisterSensor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterSensor
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_028, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    OHOS::Rosen::MotionSensorEvent motionData;
    motionData.type = 1;
    motionData.status = 1;
    camDevice->DropDetectionDataCallbackImpl(motionData);
    camDevice->SetDeviceRetryTime();
    camDevice->DropDetectionDataCallbackImpl(motionData);
}

/*
 * Feature: Framework
 * Function: Test UpdateCameraRotateAngleAndZoom without info
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateCameraRotateAngleAndZoom
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_029, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    std::vector<int32_t> fpsRanges;
    camDevice->UpdateCameraRotateAngleAndZoom(fpsRanges);
}

/*
 * Feature: Framework
 * Function: Test UpdateCameraRotateAngleAndZoom with info
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateCameraRotateAngleAndZoom
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_030, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    CameraRotateStrategyInfo strategyInfo = {GetClientNameByToken(callerToken), 0.0f , -1, -1};
    std::vector<CameraRotateStrategyInfo> strategyInfos;
    strategyInfos.push_back(strategyInfo);
    camDevice->SetCameraRotateStrategyInfos(strategyInfos);
    std::vector<int32_t> fpsRanges;
    camDevice->UpdateCameraRotateAngleAndZoom(fpsRanges);
}

/*
 * Feature: Framework
 * Function: Test GetSigleStrategyInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSigleStrategyInfo
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_031, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    CameraRotateStrategyInfo strategyInfo;
    ASSERT_EQ(camDevice->GetSigleStrategyInfo(strategyInfo), false);
}

/*
 * Feature: Framework
 * Function: Test GetCameraConnectType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraConnectType
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_032, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
 
    EXPECT_EQ(camDevice->GetCameraConnectType(), 0);
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t status = 16;
    metadata->addEntry(OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &status, 1);
    auto oldmeta = camDevice->deviceAbility_;
    camDevice->deviceAbility_ = metadata;
    ASSERT_NE(camDevice->GetCameraConnectType(), 0);
    camDevice->deviceAbility_ = oldmeta;
}
 
/*
 * Feature: Framework
 * Function: Test ResetDeviceSettings with deviceMuteMode_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ResetDeviceSettings with deviceMuteMode_
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_033, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
 
    auto oldDeviceMuteMode_ = camDevice->deviceMuteMode_.load();
    camDevice->deviceMuteMode_.store(true);
    EXPECT_EQ(camDevice->ResetDeviceSettings(), 0);
    camDevice->deviceMuteMode_.store(oldDeviceMuteMode_);
}

/*
 * Feature: Framework
 * Function: Test closeDelayed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test closeDelayed
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_034, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    auto peerCallback = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(peerCallback, nullptr);
    pid_t pid = 1234;
    HCameraDeviceManager::GetInstance()->peerCallbacks_[pid] = peerCallback;
    camDevice->SetMdmCheck(false);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::closeDelayed();
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::Close();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test DebugLogTag
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DebugLogTag
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_035, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    string dfxUbStr = "";
    int64_t data = 1;
    metadata->addEntry(OHOS_CAMERA_SENSOR_START, &data, sizeof(int64_t));
    camDevice->DebugLogTag(metadata, OHOS_CAMERA_SENSOR_START, "OHOS_CAMERA_SENSOR_START", dfxUbStr);

    double data2 = 1.0f;
    metadata->addEntry(OHOS_STREAM_JPEG_START, &data2, sizeof(double));
    camDevice->DebugLogTag(
        metadata, OHOS_STREAM_JPEG_START, "OHOS_STREAM_JPEG_START", dfxUbStr);

    camera_rational_t data3 = {
        .denominator = 1,
        .numerator = 1,
    };
    metadata->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &data3, sizeof(camera_rational_t));
    camDevice->DebugLogTag(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, "OHOS_STATUS_SENSOR_EXPOSURE_TIME", dfxUbStr);
}

/*
 * Feature: Framework
 * Function: Test GetClientName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetClientName
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_036, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    auto peerCallback = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(peerCallback, nullptr);
    pid_t pid = 1234;
    HCameraDeviceManager::GetInstance()->peerCallbacks_[pid] = peerCallback;
    camDevice->SetMdmCheck(false);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);
    camDevice->GetClientName();

    ret = camDevice->HCameraDevice::Close();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test DispatchDefaultSettingToHdi.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DispatchDefaultSettingToHdi when IsCameraDebugOn() is true and hdiCameraDevice_ is nullptr.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_037, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    int32_t data = 1;
    SetCameraDebugValue(true);
    camDevice->deviceOpenLifeCycleSettings_->addEntry(OHOS_CONTROL_MUTE_MODE, &data, 1);
    int32_t result = camDevice->DispatchDefaultSettingToHdi();
    camDevice->ResetDeviceOpenLifeCycleSettings();
    SetCameraDebugValue(false);
    EXPECT_EQ(result, CAMERA_INVALID_STATE);
}

#ifdef CAMERA_LIVE_SCENE_RECOGNITION
/*
 * Feature: Framework
 * Function: Test Open and Close when current scene is live scene
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Open and Close when current scene is live scene
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_039, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    camDevice->SetMdmCheck(false);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);
    HCameraDeviceManager::GetInstance()->SetLiveScene(true);
    ret = camDevice->HCameraDevice::Close();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateLiveStreamSceneMetadata with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnReceiveEvent with normal branch
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_040, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->UpdateLiveStreamSceneMetadata(OHOS_CAMERA_APP_HINT_NONE);
}
#endif

/*
 * Feature: Framework
 * Function: Test SetIsHasFitedRotation and GetIsHasFitedRotation when isHasFitedRotation is true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetIsHasFitedRotation and GetIsHasFitedRotation
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_041, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    bool isHasFitedRotation = true;
    camDevice->SetIsHasFitedRotation(isHasFitedRotation);
    EXPECT_EQ(camDevice->GetIsHasFitedRotation(), true);
}

/*
 * Feature: Framework
 * Function: Test SetIsHasFitedRotation and GetIsHasFitedRotation when isHasFitedRotation is false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetIsHasFitedRotation and GetIsHasFitedRotation
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_042, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    bool isHasFitedRotation = false;
    camDevice->SetIsHasFitedRotation(isHasFitedRotation);
    EXPECT_EQ(camDevice->GetIsHasFitedRotation(), false);
}

/*
 * Function: Test UpdateCameraRotateAngle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateCameraRotateAngle
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_043, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    std::vector<int32_t> fpsRanges;
    camDevice->UpdateCameraRotateAngle();
}

/*
 * Function: Test SetFirstCallerTokenID
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFirstCallerTokenID
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_044, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    camDevice->SetFirstCallerTokenID(callerToken);
}

/*
 * Feature: Framework
 * Function: Test UpdateCameraSwitchCameraId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateCameraSwitchCameraId to verify cameraID_ is updated correctly.
 *  Also test with empty string.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_045, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    std::string newCameraId = "test_camera_switch_id";
    camDevice->UpdateCameraSwitchCameraId(newCameraId);
    EXPECT_EQ(camDevice->GetCameraId(), newCameraId);

    std::string emptyId = "";
    camDevice->UpdateCameraSwitchCameraId(emptyId);
    EXPECT_EQ(camDevice->GetCameraId(), emptyId);
}

/*
 * Feature: Framework
 * Function: Test GetSensorOrientation when GetCorrectedCameraOrientation fails
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set deviceAbility_ to valid metadata without the required tag so that
 *  GetCorrectedCameraOrientation returns non-CAM_META_SUCCESS. Expect 0 return value.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_046, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);

    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.camera";
    int32_t result = camDevice->GetSensorOrientation();
    EXPECT_EQ(result, 0);
}

/*
 * Feature: Framework
 * Function: Test GetSensorOrientation success branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set deviceAbility_ via GetCameraAbility to get actual sensor orientation.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_047, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    cameraProxy->GetCameraAbility(cameraId, ability);
    ASSERT_NE(ability, nullptr);

    camDevice->deviceAbility_ = ability;
    camDevice->clientName_ = "com.test.camera";
    camDevice->usePhysicalCameraOrientation_ = false;
    int32_t result = camDevice->GetSensorOrientation();
    EXPECT_GE(result, 0);
}

/*
 * Feature: Framework
 * Function: Test CreateMuteSetting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call CreateMuteSetting and verify the created settings have the mute mode entry
 *  set to OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_048, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    camDevice->CreateMuteSetting(settings);
    ASSERT_NE(settings, nullptr);

    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_MUTE_MODE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(item.data.u8[0], OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK);
}

/*
 * Feature: Framework
 * Function: Test closeDelayedDevice when hdiCameraDevice_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set hdiCameraDevice_ to nullptr to test the early return branch.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_049, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();

    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->hdiCameraDevice_ = nullptr;
    int32_t result = camDevice->closeDelayedDevice();
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test closeDelayedDevice with opened device
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Open the camera first, then call closeDelayedDevice to test the main logic branch.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_050, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    auto peerCallback = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(peerCallback, nullptr);
    pid_t pid = 1234;
    HCameraDeviceManager::GetInstance()->peerCallbacks_[pid] = peerCallback;

    camDevice->SetMdmCheck(false);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);

    ret = camDevice->closeDelayedDevice();
    EXPECT_EQ(ret, CAMERA_OK);

    ret = camDevice->HCameraDevice::Close();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test IsPhysicalCameraOrientationVariable when deviceAbility_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set deviceAbility_ to nullptr to test early return branch.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_051, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->deviceAbility_ = nullptr;
    bool result = camDevice->IsPhysicalCameraOrientationVariable();
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test IsPhysicalCameraOrientationVariable when tag not found
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set deviceAbility_ without OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE tag.
 *  The FindCameraMetadataItem returns non-CAM_META_SUCCESS so return 0 (false).
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_052, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    camDevice->deviceAbility_ = metadata;
    bool result = camDevice->IsPhysicalCameraOrientationVariable();
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test IsPhysicalCameraOrientationVariable with variable = true, naturalDirection = false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Add OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE=1 and set
 *  GetNaturalDirectionCorrect to return false. Expect isVariable=true.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_053, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t isVariable = 1;
    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &isVariable, 1);
    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.variable";

    bool result = camDevice->IsPhysicalCameraOrientationVariable();
    EXPECT_EQ(result, true);
}

/*
 * Feature: Framework
 * Function: Test IsPhysicalCameraOrientationVariable with variable = false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Add OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE=0 entry.
 *  isVariable is computed as item.data.u8[0]=0, so result is false.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_054, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t notVariable = 0;

    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &notVariable, 1);
    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.notvariable";
    bool result = camDevice->IsPhysicalCameraOrientationVariable();
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test GetUseLogicCamera when isLogicCamera_ is false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set isLogicCamera_ to false, expect GetUseLogicCamera returns false.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_055, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = false;
    bool result = camDevice->GetUseLogicCamera(0);
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test GetUseLogicCamera when isLogicCamera_ is true and appConfigure is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set isLogicCamera_ to true and clientName_ to a non-existent bundle,
 *  so CameraApplistManager returns nullptr. Expect GetUseLogicCamera returns true.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_056, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    camDevice->clientName_ = "com.nonexistent.bundle";
    bool result = camDevice->GetUseLogicCamera(0);
    EXPECT_EQ(result, true);
}

/*
 * Feature: Framework
 * Function: Test GetUseLogicCamera when config has entry with second=0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When isLogicCamera is true and appConfigure is valid but displayMode is
 *  not found in useLogicCamera map, expects true.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_057, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    camDevice->clientName_ = "com.test.app";
    bool result = camDevice->GetUseLogicCamera(999);
    EXPECT_EQ(result, true);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleForSpecialBundle with frameRateRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call UpdateRotateAngleForSpecialBundle with isResetDegree=true.
 *  UpdateCameraRotateAngleAndZoom returns CAMERA_INVALID_ARG without configured strategy info.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_058, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    int32_t result = camDevice->UpdateRotateAngleForSpecialBundle(true);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);

    result = camDevice->UpdateRotateAngleForSpecialBundle(false);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge when isLogicCamera_ is false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set isLogicCamera_ to false, expect early return CAMERA_OK.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_059, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = false;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge when isLogicCamera_ is true
 *  but IsPhysicalCameraOrientationVariable returns false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set isLogicCamera_ to true and deviceAbility_ to nullptr so that
 *  IsPhysicalCameraOrientationVariable returns false. First condition
 *  (!isLogicCamera_ || !IsPhysicalCameraOrientationVariable()) is true, returns CAMERA_OK.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_060, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    camDevice->deviceAbility_ = nullptr;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge with foldScreenType_='7' and displayMode not FULL/COORDINATION
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: foldScreenType_[0]='7', displayMode not FULL/COORDINATION.
 *  isResetDegree=true. UpdateCameraRotateAngleAndZoom returns CAMERA_INVALID_ARG.
 *  retCode != CAMERA_OK, isUsed=false (default) -> returns CAMERA_INVALID_ARG.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_061, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t isVariable = 1;

    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &isVariable, 1);
    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.fold7";
    camDevice->foldScreenType_ = "7";
    camDevice->usePhysicalCameraOrientation_ = false;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge with foldScreenType_='6' and displayMode != GLOBAL_FULL
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: foldScreenType_[0]='6', displayMode != GLOBAL_FULL.
 *  isResetDegree=true. UpdateCameraRotateAngleAndZoom returns CAMERA_INVALID_ARG.
 *  retCode != CAMERA_OK, isUsed=false -> returns CAMERA_INVALID_ARG.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_062, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t isVariable = 1;

    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &isVariable, 1);
    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.fold6";
    camDevice->foldScreenType_ = "6";
    camDevice->usePhysicalCameraOrientation_ = false;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge with foldScreenType_='8' and displayMode != GLOBAL_FULL
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: foldScreenType_[0]='8', displayMode != GLOBAL_FULL.
 *  Same logic as '6' branch.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_063, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t isVariable = 1;

    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &isVariable, 1);
    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.fold8";
    camDevice->foldScreenType_ = "8";
    camDevice->usePhysicalCameraOrientation_ = false;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge when isLogicCamera_=true no foldScreen
 *  and not usePhysicalCameraOrientation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: isLogicCamera_=true, foldScreenType_ is empty,
 *  usePhysicalCameraOrientation_=false. Goes to else-if isLogicCamera_ branch,
 *  isUsed=false -> returns CAMERA_INVALID_ARG.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_064, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t isVariable = 1;
    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &isVariable, 1);

    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.logic";
    camDevice->foldScreenType_ = "";
    camDevice->usePhysicalCameraOrientation_ = false;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test UpdateRotateAngleJudge when isLogicCamera_=true no foldScreen
 *  and usePhysicalCameraOrientation=true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: isLogicCamera_=true, foldScreenType_ empty,
 *  usePhysicalCameraOrientation_=true. isUsed=true -> returns CAMERA_OK.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_065, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->isLogicCamera_ = true;
    const uint32_t METADATA_ITEM_SIZE = 10;
    const uint32_t METADATA_DATA_SIZE = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    uint8_t isVariable = 1;
    metadata->addEntry(OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &isVariable, 1);

    camDevice->deviceAbility_ = metadata;
    camDevice->clientName_ = "com.test.logicUse";
    camDevice->foldScreenType_ = "";
    camDevice->usePhysicalCameraOrientation_ = true;
    int32_t result = camDevice->UpdateRotateAngleJudge(0);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test SetUsedAsPosition with normal value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call SetUsedAsPosition with valid position value and verify usedAsPosition_
 *  and GetUsedAsPosition. Since the test app has system permission, should succeed.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_066, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint8_t position = OHOS_CAMERA_POSITION_FRONT;
    int32_t result = camDevice->SetUsedAsPosition(position);
    EXPECT_EQ(result, CAMERA_OK);
    EXPECT_EQ(camDevice->GetUsedAsPosition(), position);
}

/*
 * Feature: Framework
 * Function: Test SetUsedAsPosition with BACK position
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call SetUsedAsPosition with OHOS_CAMERA_POSITION_BACK and verify.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_067, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint8_t position = OHOS_CAMERA_POSITION_BACK;
    camDevice->SetUsedAsPosition(position);
    EXPECT_EQ(camDevice->GetUsedAsPosition(), position);
}

/*
 * Feature: Framework
 * Function: Test SetUsedAsPosition with OTHER position
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call SetUsedAsPosition with OHOS_CAMERA_POSITION_OTHER and verify.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_068, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint8_t position = OHOS_CAMERA_POSITION_OTHER;
    camDevice->SetUsedAsPosition(position);
    EXPECT_EQ(camDevice->GetUsedAsPosition(), position);
}

/*
 * Feature: Framework
 * Function: Test RegisterDisplayModeListener and UnregisterDisplayModeListener
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterDisplayModeListener followed by UnregisterDisplayModeListener.
 *  Covers both success path and listener cleanup.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_069, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->RegisterDisplayModeListener();
    camDevice->UnregisterDisplayModeListener();
}

/*
 * Feature: Framework
 * Function: Test UnregisterDisplayModeListener when listener is already null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call UnregisterDisplayModeListener twice to cover the early return branch
 *  where displayModeListener_ is null.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_070, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->RegisterDisplayModeListener();
    camDevice->UnregisterDisplayModeListener();
    camDevice->UnregisterDisplayModeListener();
}

/*
 * Feature: Framework
 * Function: Test SetSpectrumCallback with nullptr callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call SetSpectrumCallback with nullptr, both spectrumInfoCallback_
 *  and userId_ should remain unchanged (default).
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_071, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->SetSpectrumCallback(0, nullptr);
    EXPECT_EQ(camDevice->GetSpectrumCallback(), nullptr);

    camDevice->SetSpectrumCallback(1, nullptr);
    EXPECT_EQ(camDevice->GetSpectrumCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test SetSpectrumCallback with userId=0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When userId is 0, even if callback is valid, the function should not set values.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_072, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    sptr<CameraSpectrumListenerManager> callback = cameraManager_->GetCameraSpectrumListenerManager();
    ASSERT_NE(callback, nullptr);
    camDevice->SetSpectrumCallback(0, callback);
    EXPECT_EQ(camDevice->GetSpectrumCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test SetSpectrumCallback with valid userId and callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set valid userId and valid callback, verify spectrumInfoCallback_ and
 *  userId_ are stored correctly.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_073, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    sptr<CameraSpectrumListenerManager> callback = cameraManager_->GetCameraSpectrumListenerManager();
    ASSERT_NE(callback, nullptr);
    int32_t userId = 100;
    camDevice->SetSpectrumCallback(userId, callback);
    EXPECT_NE(camDevice->GetSpectrumCallback(), nullptr);

    camDevice->UnsetSpectrumCallback();
    EXPECT_EQ(camDevice->GetSpectrumCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test UnsetSpectrumCallback when callback is valid
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Set a valid callback first, then call UnsetSpectrumCallback.
 *  Verify callback is set to nullptr.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_074, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    sptr<CameraSpectrumListenerManager> callback = cameraManager_->GetCameraSpectrumListenerManager();
    ASSERT_NE(callback, nullptr);

    camDevice->SetSpectrumCallback(200, callback);
    EXPECT_NE(camDevice->GetSpectrumCallback(), nullptr);

    camDevice->UnsetSpectrumCallback();
    EXPECT_EQ(camDevice->GetSpectrumCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test UnsetSpectrumCallback when callback is already null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Call UnsetSpectrumCallback when no callback is set.
 *  The early return branch (spectrumInfoCallback_ == nullptr) is covered.
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_075, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->UnsetSpectrumCallback();
    EXPECT_EQ(camDevice->GetSpectrumCallback(), nullptr);
}
}
}