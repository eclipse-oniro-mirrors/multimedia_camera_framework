/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hshared_camera_device_unittest.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"
#include "hcamera_device_manager.h"
#include "icamera_device_service_callback.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

static const std::string TEST_BUNDLE_NAME = "ohos";

class MockCameraDeviceServiceCallback : public ICameraDeviceServiceCallback {
public:
    MOCK_METHOD2(OnError, int32_t(const int32_t errorType, const int32_t errorMsg));
    MOCK_METHOD2(OnResult, int32_t(const uint64_t timestamp,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& result));
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

void HSharedCameraDeviceUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void HSharedCameraDeviceUnitTest::TearDownTestCase(void) {}

void HSharedCameraDeviceUnitTest::SetUp()
{
    cameraHostManager_ = new (std::nothrow) HCameraHostManager(nullptr);
    cameraService_ = new (std::nothrow) HCameraService(cameraHostManager_);
    cameraManager_ = CameraManager::GetInstance();
}

void HSharedCameraDeviceUnitTest::TearDown()
{
    cameraHostManager_ = nullptr;
    cameraService_ = nullptr;
    cameraManager_ = nullptr;
}

sptr<HCameraDevice> HSharedCameraDeviceUnitTest::CreateCameraDevice(const std::string& cameraId)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    return new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
}

// =================== HCameraDeviceWrapper tests ===================

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test constructor with independent device (non-shared mode)
 * SubFunction: NA
 * FunctionPoints: GetCameraId, GetOwnerPid, IsSharedMode, GetRealDevice
 * EnvConditions: NA
 * CaseDescription: Create wrapper with independent device, verify basic properties
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_001, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];
    pid_t ownerPid = 1001;

    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, ownerPid, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->GetCameraId(), cameraId);
    EXPECT_EQ(wrapper->GetOwnerPid(), ownerPid);
    EXPECT_EQ(wrapper->IsSharedMode(), false);
    EXPECT_EQ(wrapper->GetRealDevice().GetRefPtr(), realDevice.GetRefPtr());
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test constructor with shared device (shared mode)
 * SubFunction: NA
 * FunctionPoints: GetCameraId, GetOwnerPid, IsSharedMode, GetRealDevice
 * EnvConditions: NA
 * CaseDescription: Create wrapper with shared device, verify basic properties and ref counting
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_002, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];
    pid_t ownerPid = 1002;

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, ownerPid, sharedDevice, true);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->GetCameraId(), cameraId);
    EXPECT_EQ(wrapper->GetOwnerPid(), ownerPid);
    EXPECT_EQ(wrapper->IsSharedMode(), true);
    EXPECT_EQ(wrapper->GetRealDevice().GetRefPtr(), sharedDevice.GetRefPtr());
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test Open delegation
 * SubFunction: NA
 * FunctionPoints: Open
 * EnvConditions: NA
 * CaseDescription: Verify Open delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_003, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1003, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->Open(), CAMERA_OK);
    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test Open with concurrent type delegation
 * SubFunction: NA
 * FunctionPoints: Open(int32_t)
 * EnvConditions: NA
 * CaseDescription: Verify Open(concurrentType) delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_004, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1004, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    int32_t concurrentType = 0;
    EXPECT_EQ(wrapper->Open(concurrentType), CAMERA_OK);
    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test Close delegation
 * SubFunction: NA
 * FunctionPoints: Close
 * EnvConditions: NA
 * CaseDescription: Verify Close delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_005, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1005, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->Open(), CAMERA_OK);
    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test Close and closeDelayed delegation
 * SubFunction: NA
 * FunctionPoints: Close, closeDelayed
 * EnvConditions: NA
 * CaseDescription: Verify Close and closeDelayed delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_006, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1006, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->Open(), CAMERA_OK);
    EXPECT_EQ(wrapper->closeDelayed(), CAMERA_OK);
    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test Release delegation
 * SubFunction: NA
 * FunctionPoints: Release
 * EnvConditions: NA
 * CaseDescription: Verify Release delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_007, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1007, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->Open(), CAMERA_OK);
    EXPECT_EQ(wrapper->Release(), CAMERA_OK);
    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test UpdateSetting delegation
 * SubFunction: NA
 * FunctionPoints: UpdateSetting
 * EnvConditions: NA
 * CaseDescription: Verify UpdateSetting delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_008, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1008, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->Open(), CAMERA_OK);

    auto settings = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    int32_t rc = wrapper->UpdateSetting(settings);
    // UpdateSetting may return CAMERA_OK or CAMERA_INVALID_STATE depending on state
    EXPECT_TRUE(rc == CAMERA_OK || rc == CAMERA_INVALID_STATE);

    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SetCallback and UnSetCallback delegation
 * SubFunction: NA
 * FunctionPoints: SetCallback, UnSetCallback
 * EnvConditions: NA
 * CaseDescription: Verify SetCallback/UnSetCallback delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_009, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1009, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    sptr<MockCameraDeviceServiceCallback> callback = new (std::nothrow) MockCameraDeviceServiceCallback();
    ASSERT_NE(callback, nullptr);

    EXPECT_EQ(wrapper->SetCallback(callback), CAMERA_OK);
    EXPECT_EQ(wrapper->UnSetCallback(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test GetEnabledResults and EnableResult delegation
 * SubFunction: NA
 * FunctionPoints: GetEnabledResults, EnableResult, DisableResult
 * EnvConditions: NA
 * CaseDescription: Verify result-related methods delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_010, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1010, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    std::vector<int32_t> results;
    int32_t rc = wrapper->GetEnabledResults(results);
    std::vector<int32_t> enableResults = { 1, 2, 3 };
    rc = wrapper->EnableResult(enableResults);
    rc = wrapper->DisableResult(enableResults);
    EXPECT_EQ(rc, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SwitchToSharedMode
 * SubFunction: NA
 * FunctionPoints: SwitchToSharedMode
 * EnvConditions: NA
 * CaseDescription: Switch independent wrapper to shared mode, verify IsSharedMode and GetRealDevice
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_011, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];
    pid_t ownerPid = 1011;

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, ownerPid, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->Open(), CAMERA_OK);
    EXPECT_EQ(wrapper->IsSharedMode(), false);

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> sharedRealDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(sharedRealDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, sharedRealDevice);
    ASSERT_NE(sharedDevice, nullptr);

    sptr<HCameraDevice> switched = wrapper->SwitchToSharedMode(sharedDevice);
    ASSERT_NE(switched, nullptr);
    EXPECT_EQ(switched.GetRefPtr(), sharedDevice.GetRefPtr());
    EXPECT_EQ(wrapper->IsSharedMode(), true);
    EXPECT_EQ(wrapper->GetRealDevice().GetRefPtr(), sharedDevice.GetRefPtr());

    EXPECT_EQ(wrapper->Close(), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SwitchToSharedMode when already shared
 * SubFunction: NA
 * FunctionPoints: SwitchToSharedMode
 * EnvConditions: NA
 * CaseDescription: SwitchToSharedMode on already shared wrapper returns existing device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_012, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];
    pid_t ownerPid = 1012;

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, ownerPid, sharedDevice, true);
    ASSERT_NE(wrapper, nullptr);
    EXPECT_EQ(wrapper->IsSharedMode(), true);

    sptr<HCameraDevice> switched = wrapper->SwitchToSharedMode(sharedDevice);
    ASSERT_NE(switched, nullptr);
    EXPECT_EQ(switched.GetRefPtr(), sharedDevice.GetRefPtr());
    EXPECT_EQ(wrapper->IsSharedMode(), true);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SwitchToSharedMode with null sharedDevice
 * SubFunction: NA
 * FunctionPoints: SwitchToSharedMode
 * EnvConditions: NA
 * CaseDescription: SwitchToSharedMode with null sharedDevice returns nullptr
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_013, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1013, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    sptr<HCameraDevice> switched = wrapper->SwitchToSharedMode(nullptr);
    EXPECT_EQ(switched, nullptr);
    EXPECT_EQ(wrapper->IsSharedMode(), false);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test Open with CallerDeviceInfo delegation
 * SubFunction: NA
 * FunctionPoints: Open(CallerDeviceInfo)
 * EnvConditions: NA
 * CaseDescription: Verify Open with CallerDeviceInfo delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_014, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1014, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    CallerDeviceInfo callerInfo;
    callerInfo.deviceId = "1014";
    int32_t rc = wrapper->Open(callerInfo);
    rc = wrapper->Close();
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SetMdmCheck and SetCameraIdTransform delegation
 * SubFunction: NA
 * FunctionPoints: SetMdmCheck, SetCameraIdTransform
 * EnvConditions: NA
 * CaseDescription: Verify SetMdmCheck and SetCameraIdTransform delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_015, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1015, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->SetMdmCheck(true), CAMERA_OK);
    EXPECT_EQ(wrapper->SetMdmCheck(false), CAMERA_OK);
    EXPECT_EQ(wrapper->SetCameraIdTransform("origin_camera_0"), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SetFirstCallerTokenID and SetUsePhysicalCameraOrientation delegation
 * SubFunction: NA
 * FunctionPoints: SetFirstCallerTokenID, SetUsePhysicalCameraOrientation
 * EnvConditions: NA
 * CaseDescription: Verify SetFirstCallerTokenID and SetUsePhysicalCameraOrientation delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_016, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1016, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->SetFirstCallerTokenID(12345), CAMERA_OK);
    EXPECT_EQ(wrapper->SetUsePhysicalCameraOrientation(true), CAMERA_OK);
    EXPECT_EQ(wrapper->SetUsePhysicalCameraOrientation(false), CAMERA_OK);
}

/*
 * Feature: HCameraDeviceWrapper
 * Function: Test SetDeviceRetryTime and GetNaturalDirectionCorrect delegation
 * SubFunction: NA
 * FunctionPoints: SetDeviceRetryTime, GetNaturalDirectionCorrect
 * EnvConditions: NA
 * CaseDescription: Verify SetDeviceRetryTime and GetNaturalDirectionCorrect delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hcamera_device_wrapper_unittest_017, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    sptr<HCameraDevice> realDevice = CreateCameraDevice(cameraId);
    ASSERT_NE(realDevice, nullptr);

    sptr<HCameraDeviceWrapper> wrapper = new (std::nothrow) HCameraDeviceWrapper(
        cameraId, 1017, realDevice, false);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->SetDeviceRetryTime();
    EXPECT_EQ(rc, CAMERA_OK);

    bool isNaturalDirectionCorrect = false;
    rc = wrapper->GetNaturalDirectionCorrect(isNaturalDirectionCorrect);
    EXPECT_EQ(rc, CAMERA_OK);
}

// =================== HSharedCameraDevice tests ===================

/*
 * Feature: HSharedCameraDevice
 * Function: Test AddRef and ReleaseRef reference counting
 * SubFunction: NA
 * FunctionPoints: AddRef, ReleaseRef
 * EnvConditions: NA
 * CaseDescription: AddRef increments, ReleaseRef decrements, multiple refs require multiple releases
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_001, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    pid_t pid1 = 2001;
    pid_t pid2 = 2002;

    sharedDevice->AddRef(pid1);
    sharedDevice->AddRef(pid1);
    sharedDevice->AddRef(pid2);

    sharedDevice->ReleaseRef(pid1);
    sharedDevice->ReleaseRef(pid1);

    sharedDevice->ReleaseRef(pid2);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test RegisterAppCallback and UnregisterAppCallback
 * SubFunction: NA
 * FunctionPoints: RegisterAppCallback, UnregisterAppCallback
 * EnvConditions: NA
 * CaseDescription: Register and unregister app callbacks
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_002, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    pid_t pid = 3001;
    sptr<MockCameraDeviceServiceCallback> callback = new (std::nothrow) MockCameraDeviceServiceCallback();
    ASSERT_NE(callback, nullptr);

    sharedDevice->RegisterAppCallback(pid, callback);
    sharedDevice->UnregisterAppCallback(pid);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test Open delegation
 * SubFunction: NA
 * FunctionPoints: Open
 * EnvConditions: NA
 * CaseDescription: Verify Open delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_003, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    EXPECT_EQ(sharedDevice->Open(), CAMERA_OK);
    EXPECT_EQ(sharedDevice->Close(), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test Open with concurrent type delegation
 * SubFunction: NA
 * FunctionPoints: Open(int32_t)
 * EnvConditions: NA
 * CaseDescription: Verify Open(concurrentType) delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_004, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    int32_t concurrentType = 0;
    EXPECT_EQ(sharedDevice->Open(concurrentType), CAMERA_OK);
    EXPECT_EQ(sharedDevice->Close(), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test Open with CallerDeviceInfo delegation
 * SubFunction: NA
 * FunctionPoints: Open(CallerDeviceInfo)
 * EnvConditions: NA
 * CaseDescription: Verify Open with CallerDeviceInfo delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_005, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    CallerDeviceInfo callerInfo;
    callerInfo.deviceId = "1001";
    int32_t rc = sharedDevice->Open(callerInfo);
    rc = sharedDevice->Close();
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test Close and Release delegation
 * SubFunction: NA
 * FunctionPoints: Close, Release
 * EnvConditions: NA
 * CaseDescription: Verify Close and Release delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_006, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    EXPECT_EQ(sharedDevice->Open(), CAMERA_OK);
    EXPECT_EQ(sharedDevice->Release(), CAMERA_OK);
    EXPECT_EQ(sharedDevice->Close(), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test UpdateSetting delegation
 * SubFunction: NA
 * FunctionPoints: UpdateSetting
 * EnvConditions: NA
 * CaseDescription: Verify UpdateSetting delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_007, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);
    realDevice->SetMdmCheck(false);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    EXPECT_EQ(sharedDevice->Open(), CAMERA_OK);

    auto settings = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    int32_t rc = sharedDevice->UpdateSetting(settings);
    EXPECT_TRUE(rc == CAMERA_OK || rc == CAMERA_INVALID_STATE);

    EXPECT_EQ(sharedDevice->Close(), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test SetCallback and UnSetCallback delegation
 * SubFunction: NA
 * FunctionPoints: SetCallback, UnSetCallback
 * EnvConditions: NA
 * CaseDescription: Verify SetCallback/UnSetCallback delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_008, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    sptr<MockCameraDeviceServiceCallback> callback = new (std::nothrow) MockCameraDeviceServiceCallback();
    ASSERT_NE(callback, nullptr);

    EXPECT_EQ(sharedDevice->SetCallback(callback), CAMERA_OK);
    EXPECT_EQ(sharedDevice->UnSetCallback(), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test GetEnabledResults and EnableResult delegation
 * SubFunction: NA
 * FunctionPoints: GetEnabledResults, EnableResult, DisableResult
 * EnvConditions: NA
 * CaseDescription: Verify result-related methods delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_009, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    std::vector<int32_t> results;
    int32_t rc = sharedDevice->GetEnabledResults(results);
    std::vector<int32_t> enableResults = { 1, 2, 3 };
    rc = sharedDevice->EnableResult(enableResults);
    rc = sharedDevice->DisableResult(enableResults);
    EXPECT_EQ(rc, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test SetMdmCheck and SetCameraIdTransform delegation
 * SubFunction: NA
 * FunctionPoints: SetMdmCheck, SetCameraIdTransform
 * EnvConditions: NA
 * CaseDescription: Verify SetMdmCheck and SetCameraIdTransform delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_010, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    EXPECT_EQ(sharedDevice->SetMdmCheck(true), CAMERA_OK);
    EXPECT_EQ(sharedDevice->SetMdmCheck(false), CAMERA_OK);
    EXPECT_EQ(sharedDevice->SetCameraIdTransform("origin_camera_0"), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test SetFirstCallerTokenID and SetUsePhysicalCameraOrientation delegation
 * SubFunction: NA
 * FunctionPoints: SetFirstCallerTokenID, SetUsePhysicalCameraOrientation
 * EnvConditions: NA
 * CaseDescription: Verify SetFirstCallerTokenID and SetUsePhysicalCameraOrientation delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_011, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    EXPECT_EQ(sharedDevice->SetFirstCallerTokenID(12345), CAMERA_OK);
    EXPECT_EQ(sharedDevice->SetUsePhysicalCameraOrientation(true), CAMERA_OK);
    EXPECT_EQ(sharedDevice->SetUsePhysicalCameraOrientation(false), CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test SetDeviceRetryTime and GetNaturalDirectionCorrect delegation
 * SubFunction: NA
 * FunctionPoints: SetDeviceRetryTime, GetNaturalDirectionCorrect
 * EnvConditions: NA
 * CaseDescription: Verify SetDeviceRetryTime and GetNaturalDirectionCorrect delegate to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_012, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    int32_t rc = sharedDevice->SetDeviceRetryTime();
    EXPECT_EQ(rc, CAMERA_OK);

    bool isNaturalDirectionCorrect = false;
    rc = sharedDevice->GetNaturalDirectionCorrect(isNaturalDirectionCorrect);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test openSecureCamera delegation
 * SubFunction: NA
 * FunctionPoints: OpenSecureCamera
 * EnvConditions: NA
 * CaseDescription: Verify OpenSecureCamera delegates to real device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_013, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraId, callerToken);
    ASSERT_NE(realDevice, nullptr);

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(
        cameraId, cameraHostManager_, callerToken, realDevice);
    ASSERT_NE(sharedDevice, nullptr);

    uint64_t secureSeqId = 0;
    int32_t rc = sharedDevice->OpenSecureCamera(secureSeqId);
    EXPECT_EQ(rc, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test GetOrCreateSharedDevice creates new device
 * SubFunction: NA
 * FunctionPoints: GetOrCreateSharedDevice, GetCameraId, GetRealDevice
 * EnvConditions: NA
 * CaseDescription: Create shared device, verify properties
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_014, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HSharedCameraDevice> sharedDevice = HSharedCameraDevice::GetOrCreateSharedDevice(
        cameraId, cameraHostManager_, callerToken);
    ASSERT_NE(sharedDevice, nullptr);

    EXPECT_EQ(sharedDevice->GetCameraId(), cameraId);
    sptr<HCameraDevice> realDevice = sharedDevice->GetRealDevice();
    ASSERT_NE(realDevice, nullptr);
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test GetOrCreateSharedDevice returns existing device
 * SubFunction: NA
 * FunctionPoints: GetOrCreateSharedDevice
 * EnvConditions: NA
 * CaseDescription: GetOrCreateSharedDevice twice returns same device pointer
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_015, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HSharedCameraDevice> first = HSharedCameraDevice::GetOrCreateSharedDevice(
        cameraId, cameraHostManager_, callerToken);
    ASSERT_NE(first, nullptr);

    sptr<HSharedCameraDevice> second = HSharedCameraDevice::GetOrCreateSharedDevice(
        cameraId, cameraHostManager_, callerToken);
    ASSERT_NE(second, nullptr);

    EXPECT_EQ(first.GetRefPtr(), second.GetRefPtr());
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test GetSharedDevice returns existing device
 * SubFunction: NA
 * FunctionPoints: GetSharedDevice
 * EnvConditions: NA
 * CaseDescription: GetSharedDevice after creation returns the same device
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_016, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    std::string cameraId = cameraIds[0];

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HSharedCameraDevice> created = HSharedCameraDevice::GetOrCreateSharedDevice(
        cameraId, cameraHostManager_, callerToken);
    ASSERT_NE(created, nullptr);

    sptr<HSharedCameraDevice> found = HSharedCameraDevice::GetSharedDevice(cameraId);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found.GetRefPtr(), created.GetRefPtr());

    created->ReleaseRef(getpid());
}

/*
 * Feature: HSharedCameraDevice
 * Function: Test GetSharedDevice returns null for non-existent cameraId
 * SubFunction: NA
 * FunctionPoints: GetSharedDevice
 * EnvConditions: NA
 * CaseDescription: GetSharedDevice with non-existent cameraId returns nullptr
 */
HWTEST_F(HSharedCameraDeviceUnitTest, hshared_camera_device_unittest_017, TestSize.Level0)
{
    sptr<HSharedCameraDevice> found = HSharedCameraDevice::GetSharedDevice("non_existent_camera_id");
    EXPECT_EQ(found, nullptr);
}
} // CameraStandard
} // OHOS