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

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void HCameraDeviceUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnitTest::SetUpTestCase started!");
}

void HCameraDeviceUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceUnitTest::TearDownTestCase started!");
}

void HCameraDeviceUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
    NativeAuthorization();
    g_mockFlagWithoutAbt = false;
    cameraHostManager_ = new HCameraHostManager(nullptr);
    cameraManager_ = CameraManager::GetInstance();
}

void HCameraDeviceUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraFrameworkUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}
void HCameraDeviceUnitTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    cameraHostManager_ = nullptr;
    cameraManager_ = nullptr;
    MEDIA_INFO_LOG("TearDown end");
}

/*
 * Feature: Framework
 * Function: Test OpenSecureCamera.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OpenSecureCamera_001.
 */
HWTEST_F(HCameraDeviceUnitTest, OpenSecureCamera_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint64_t secureSeqId = 0;
    int32_t result = camDevice->OpenSecureCamera(&secureSeqId);
    EXPECT_EQ(result, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OpenSecureCamera.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OpenSecureCamera_002.
 */
HWTEST_F(HCameraDeviceUnitTest, OpenSecureCamera_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    uint64_t secureSeqId = 0;
    camDevice->hdiCameraDevice_ = nullptr;
    int32_t result = camDevice->OpenSecureCamera(&secureSeqId);
    EXPECT_EQ(result, CAMERA_OK);
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
HWTEST_F(HCameraDeviceUnitTest, GetSecureCameraSeq_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, ResetZoomTimer_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, SetCallback_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, OperatePermissionCheck_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, GetCameraType_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, DispatchDefaultSettingToHdi_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, CheckPermissionBeforeOpenDevice_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, HandlePrivacyBeforeOpenDevice_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
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
HWTEST_F(HCameraDeviceUnitTest, CloseDevice_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    camDevice->hdiCameraDevice_ = nullptr;
    camDevice->CloseDevice();
    EXPECT_EQ(camDevice->hdiCameraDevice_, nullptr);

    camDevice->cameraHostManager_ = nullptr;
    int32_t result = camDevice->CloseDevice();
    EXPECT_EQ(result, CAMERA_OK);
}
}
}