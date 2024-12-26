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

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

const std::string LOCAL_SERVICE_NAME = "camera_service";

void HCameraDeviceUnit::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnit::SetUpTestCase started!");
}

void HCameraDeviceUnit::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnit::TearDownTestCase started!");
}

void HCameraDeviceUnit::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
    NativeAuthorization();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    cameraManager_ = CameraManager::GetInstance();
}

void HCameraDeviceUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraFrameworkUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
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
    camDevice->UnRegisterFoldStatusListener();

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
    cameraResult = cameras[0]->GetMetadata();
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
    EXPECT_NE(result, CAMERA_OK);
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

    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = camDevice->HCameraDevice::GetStreamOperator();
    EXPECT_TRUE(streamOperator != nullptr);

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
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = cameras[0]->GetMetadata();
    EXPECT_EQ(camDevice->UpdateSettingOnce(settings), 0);

    camDevice->RegisterFoldStatusListener();
    camDevice->UnRegisterFoldStatusListener();
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
    camDevice->UnRegisterFoldStatusListener();
    camDevice->RegisterFoldStatusListener();
    camDevice->UnRegisterFoldStatusListener();
    camDevice->cameraHostManager_ = nullptr;
    camDevice->RegisterFoldStatusListener();
    camDevice->UnRegisterFoldStatusListener();

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
    EXPECT_EQ(camDevice->InitStreamOperator(), CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when streamOperator_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when streamOperator_ is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_017, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos = {};
    camDevice->CreateStreams(streamInfos);

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceSettings = cameras[0]->GetMetadata();
    int32_t operationMode = 0;
    camDevice->streamOperator_ = nullptr;
    EXPECT_EQ(camDevice->CommitStreams(deviceSettings, operationMode), CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when streamOperator is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when streamOperator is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_018, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    std::vector<StreamInfo_V1_1> streamInfos = {};
    EXPECT_EQ(camDevice->UpdateStreams(streamInfos), CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when streamOperatorCallback is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when streamOperatorCallback is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_019, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    int32_t captureId = 0;
    const std::vector<int32_t> streamIds = {1, 2};
    EXPECT_EQ(camDevice->OnCaptureStarted(captureId, streamIds), CAMERA_INVALID_STATE);

    HDI::Camera::V1_2::CaptureStartedInfo it1;
    it1.streamId_ = 1;
    it1.exposureTime_ = 1;
    HDI::Camera::V1_2::CaptureStartedInfo it2;
    it2.streamId_ = 2;
    it2.exposureTime_ = 2;
    std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> captureStartedInfo = {};
    captureStartedInfo.push_back(it1);
    captureStartedInfo.push_back(it2);
    EXPECT_EQ(camDevice->OnCaptureStarted_V1_2(captureId, captureStartedInfo), CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when streamOperatorCallback is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when streamOperatorCallback is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_020, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    int32_t captureId = 0;
    const std::vector<int32_t> streamIds = {1, 2};
    EXPECT_EQ(camDevice->OnCaptureStarted(captureId, streamIds), CAMERA_INVALID_STATE);
    const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> captureStartedInfo = {};
    EXPECT_EQ(camDevice->OnCaptureStarted_V1_2(captureId, captureStartedInfo), CAMERA_INVALID_STATE);

    CaptureEndedInfo it1;
    it1.streamId_ = 1;
    it1.frameCount_ = 1;
    CaptureEndedInfo it2;
    it2.streamId_ = 2;
    it2.frameCount_ = 2;
    std::vector<CaptureEndedInfo> captureEndedInfo = {};
    captureEndedInfo.push_back(it1);
    captureEndedInfo.push_back(it2);
    EXPECT_EQ(camDevice->OnCaptureEnded(captureId, captureEndedInfo), CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice when streamOperatorCallback is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice when streamOperatorCallback is nullptr
 */
HWTEST_F(HCameraDeviceUnit, hcamera_device_unittest_021, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);
    int32_t captureId = 0;
    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> captureErrorInfo = {};
    captureErrorInfo.push_back(it1);
    captureErrorInfo.push_back(it2);
    EXPECT_EQ(camDevice->OnCaptureError(captureId, captureErrorInfo), CAMERA_INVALID_STATE);

    const std::vector<int32_t> streamIds = {1, 2};
    uint64_t timestamp = 5;
    EXPECT_EQ(camDevice->OnFrameShutter(captureId, streamIds, timestamp), CAMERA_INVALID_STATE);
    EXPECT_EQ(camDevice->OnFrameShutterEnd(captureId, streamIds, timestamp), CAMERA_INVALID_STATE);
    EXPECT_EQ(camDevice->OnCaptureReady(captureId, streamIds, timestamp), CAMERA_INVALID_STATE);
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
    camInput->GetCameraDevice()->Open();

    sptr<HCameraService> cameraService = new (std::nothrow) HCameraService(cameraHostManager_);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = cameraService->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 2);

    callback = new (std::nothrow) CameraStatusServiceCallback(cameraManager_);
    ASSERT_NE(callback, nullptr);
    intResult = cameraService->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 0);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<ICameraMuteServiceCallback> callback_2 = nullptr;
    intResult = cameraService->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 2);

    callback_2 = new (std::nothrow) CameraMuteServiceCallback(cameraManager_);
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

}
}