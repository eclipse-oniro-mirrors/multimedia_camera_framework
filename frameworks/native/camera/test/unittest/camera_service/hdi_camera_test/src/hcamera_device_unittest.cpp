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

#include "gmock/gmock.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "output/sketch_wrapper.h"
#include "hcamera_service.h"
#include "hcamera_device_unittest.h"
#include "ipc_skeleton.h"
#include "test_token.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

const std::string LOCAL_SERVICE_NAME = "camera_service";

void HCameraDeviceUnit::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnit::SetUpTestCase started!");
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_001, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_003, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_004, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_005, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_006, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_007, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_008, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_009, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_010, TestSize.Level1)
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

    HCameraDeviceManager::GetInstance()->peerCallback_ = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(HCameraDeviceManager::GetInstance()->peerCallback_, nullptr);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);

    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);

    ret = camDevice->HCameraDevice::EnableResult(result);
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::DisableResult(result);
    EXPECT_EQ(ret, 0);

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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_011, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_012, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_013, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_014, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_015, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_016, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_022, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraService> cameraService = new (std::nothrow) HCameraService(cameraHostManager_);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = cameraService->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 2);

    callback = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);
    intResult = cameraService->SetCameraCallback(callback);
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_023, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_024, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    bool ret = camDevice->ShowDeviceProtectionDialog(OHOS_DEVICE_EJECT_BLOCK);
    ASSERT_FALSE(ret);
    ret = camDevice->ShowDeviceProtectionDialog(OHOS_DEVICE_EXTERNAL_PRESS);
    ASSERT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test DeviceEjectCallBack
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeviceEjectCallBack
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_025, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_026, TestSize.Level1)
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
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_027, TestSize.Level1)
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
    CameraRotateStrategyInfo strategyInfo = {GetClientNameByToken(callerToken), 0.0f, -1, -1};
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

    HCameraDeviceManager::GetInstance()->peerCallback_ = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(HCameraDeviceManager::GetInstance()->peerCallback_, nullptr);
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
    DFX_UB_NAME dfxUbStr = DFX_UB_NOT_REPORT;
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

    HCameraDeviceManager::GetInstance()->peerCallback_ = new (std::nothrow) ICameraBrokerTest();
    ASSERT_NE(HCameraDeviceManager::GetInstance()->peerCallback_, nullptr);
    int32_t ret = camDevice->HCameraDevice::Open();
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(camDevice->GetClientName(), "native_camera_tdd");

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
}
}