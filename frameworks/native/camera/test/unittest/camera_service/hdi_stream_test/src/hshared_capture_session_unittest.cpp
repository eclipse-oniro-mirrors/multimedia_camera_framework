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

#include "hshared_capture_session_unittest.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_session_callback_stub.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"
#include "hcamera_device.h"
#include "hstream_repeat.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

constexpr static int32_t DEFAULT_WIDTH = 1280;
constexpr static int32_t DEFAULT_HEIGHT = 960;
constexpr static int32_t DEFAULT_FORMAT = 4;

class MockHCaptureSessionCallbackStub : public CaptureSessionCallbackStub {
public:
    MOCK_METHOD1(OnError, int32_t(int32_t errorCode));
    ~MockHCaptureSessionCallbackStub() {}
};

class MockHPressureStatusCallbackStub : public PressureStatusCallbackStub {
public:
    MOCK_METHOD1(OnPressureStatusChanged, int32_t(PressureStatus status));
    ~MockHPressureStatusCallbackStub() {}
};

void HSharedCaptureSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void HSharedCaptureSessionUnitTest::TearDownTestCase(void) {}

void HSharedCaptureSessionUnitTest::SetUp()
{
    cameraHostManager_ = new (std::nothrow) HCameraHostManager(nullptr);
    cameraService_ = new (std::nothrow) HCameraService(cameraHostManager_);
    cameraManager_ = CameraManager::GetInstance();
}

void HSharedCaptureSessionUnitTest::TearDown()
{
    cameraHostManager_ = nullptr;
    cameraService_ = nullptr;
    cameraManager_ = nullptr;
}

// =================== HCaptureSessionWrapper tests ===================

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test constructor with independent session (non-privileged)
 * SubFunction: NA
 * FunctionPoints: GetOwnerPid, GetRealSession, IsSharedMode
 * EnvConditions: NA
 * CaseDescription: Create wrapper with independent session, verify basic properties
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_001, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1001;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->GetOwnerPid(), ownerPid);
    EXPECT_EQ(wrapper->IsSharedMode(), false);
    EXPECT_EQ(wrapper->GetRealSession().GetRefPtr(), realSession.GetRefPtr());
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test constructor with privileged app
 * SubFunction: NA
 * FunctionPoints: GetOwnerPid, IsSharedMode
 * EnvConditions: NA
 * CaseDescription: Create wrapper with privileged app flag, verify properties
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_002, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1002;

    CamServiceError err;
    sptr<HSharedCaptureSession> sharedSession = nullptr;
    err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, true, sharedSession);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->GetOwnerPid(), ownerPid);
    EXPECT_EQ(wrapper->IsSharedMode(), true);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test AddInput and RemoveInput delegation
 * SubFunction: NA
 * FunctionPoints: AddInput, RemoveInput
 * EnvConditions: NA
 * CaseDescription: Verify AddInput and RemoveInput delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_003, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->SetMdmCheck(false);
    EXPECT_EQ(device->Open(), CAMERA_OK);

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1003;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    EXPECT_EQ(wrapper->BeginConfig(), CAMERA_OK);
    bool result = false;
    int32_t rc = wrapper->CanAddInput(device, result);
    EXPECT_EQ(rc, CAMERA_OK);
    rc = wrapper->AddInput(device);
    rc = wrapper->AddOutput(StreamType::REPEAT, streamRepeat);
    EXPECT_EQ(rc, CAMERA_OK);

    EXPECT_EQ(wrapper->CommitConfig(), CAMERA_OK);
    rc = wrapper->RemoveInput(device);
    rc = wrapper->RemoveOutput(StreamType::REPEAT, streamRepeat);
    EXPECT_EQ(rc, CAMERA_INVALID_STATE);

    EXPECT_EQ(device->Close(), CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test Start and Stop delegation
 * SubFunction: NA
 * FunctionPoints: Start, Stop
 * EnvConditions: NA
 * CaseDescription: Verify Start and Stop delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_004, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1004;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->Start();
    rc = wrapper->Stop();
    EXPECT_EQ(rc, CAMERA_INVALID_STATE);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test Release in independent mode
 * SubFunction: NA
 * FunctionPoints: Release
 * EnvConditions: NA
 * CaseDescription: Verify Release delegates to real session in independent mode
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_005, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1005;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->Release();
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test Release idempotence (already released)
 * SubFunction: NA
 * FunctionPoints: Release
 * EnvConditions: NA
 * CaseDescription: Release twice should return CAMERA_OK on second call
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_006, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1006;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc1 = wrapper->Release();
    EXPECT_EQ(rc1, CAMERA_OK);

    int32_t rc2 = wrapper->Release();
    EXPECT_EQ(rc2, CAMERA_INVALID_STATE);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetCallback and UnSetCallback delegation
 * SubFunction: NA
 * FunctionPoints: SetCallback, UnSetCallback
 * EnvConditions: NA
 * CaseDescription: Verify SetCallback and UnSetCallback delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_007, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1007;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    sptr<MockHCaptureSessionCallbackStub> callback = new (std::nothrow) MockHCaptureSessionCallbackStub();
    ASSERT_NE(callback, nullptr);

    EXPECT_EQ(wrapper->SetCallback(callback), CAMERA_OK);
    EXPECT_EQ(wrapper->UnSetCallback(), CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetPressureCallback and UnSetPressureCallback delegation
 * SubFunction: NA
 * FunctionPoints: SetPressureCallback, UnSetPressureCallback
 * EnvConditions: NA
 * CaseDescription: Verify SetPressureCallback and UnSetPressureCallback delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_008, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1008;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    sptr<MockHPressureStatusCallbackStub> callback = new (std::nothrow) MockHPressureStatusCallbackStub();
    ASSERT_NE(callback, nullptr);

    EXPECT_EQ(wrapper->SetPressureCallback(callback), CAMERA_OK);
    EXPECT_EQ(wrapper->UnSetPressureCallback(), CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test GetSessionState delegation
 * SubFunction: NA
 * FunctionPoints: GetSessionState
 * EnvConditions: NA
 * CaseDescription: Verify GetSessionState delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_009, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1009;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    CaptureSessionState sessionState = CaptureSessionState::SESSION_INIT;
    int32_t rc = wrapper->GetSessionState(sessionState);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetSmoothZoom delegation
 * SubFunction: NA
 * FunctionPoints: SetSmoothZoom
 * EnvConditions: NA
 * CaseDescription: Verify SetSmoothZoom delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_010, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1010;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    float duration = 0.0f;
    int32_t rc = wrapper->SetSmoothZoom(0, 0, 2.0f, duration);
    EXPECT_EQ(rc, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetFeatureMode delegation
 * SubFunction: NA
 * FunctionPoints: SetFeatureMode
 * EnvConditions: NA
 * CaseDescription: Verify SetFeatureMode delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_011, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1011;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->SetFeatureMode(0);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetColorSpace and GetActiveColorSpace delegation
 * SubFunction: NA
 * FunctionPoints: SetColorSpace, GetActiveColorSpace
 * EnvConditions: NA
 * CaseDescription: Verify SetColorSpace and GetActiveColorSpace delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_012, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1012;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t curColorSpace = 0;
    int32_t rc = wrapper->GetActiveColorSpace(curColorSpace);
    EXPECT_EQ(rc, CAMERA_OK);

    rc = wrapper->SetColorSpace(0, false);
    EXPECT_EQ(rc, CAMERA_INVALID_STATE);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test EnableMovingPhoto and EnableMovingPhotoMirror delegation
 * SubFunction: NA
 * FunctionPoints: EnableMovingPhoto, EnableMovingPhotoMirror
 * EnvConditions: NA
 * CaseDescription: Verify EnableMovingPhoto and EnableMovingPhotoMirror delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_013, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1013;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->EnableMovingPhoto(true);
    EXPECT_EQ(rc, CAMERA_OK);

    rc = wrapper->EnableMovingPhoto(false);
    EXPECT_EQ(rc, CAMERA_OK);

    rc = wrapper->EnableMovingPhotoMirror(true, false);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetPreviewRotation and SetCommitConfigFlag delegation
 * SubFunction: NA
 * FunctionPoints: SetPreviewRotation, SetCommitConfigFlag
 * EnvConditions: NA
 * CaseDescription: Verify SetPreviewRotation and SetCommitConfigFlag delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_014, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1014;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->SetPreviewRotation("test_device");
    EXPECT_EQ(rc, CAMERA_OK);

    rc = wrapper->SetCommitConfigFlag(false);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetHasFitedRotation delegation
 * SubFunction: NA
 * FunctionPoints: SetHasFitedRotation
 * EnvConditions: NA
 * CaseDescription: Verify SetHasFitedRotation delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_015, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1015;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    int32_t rc = wrapper->SetHasFitedRotation(true);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SetSharedSessionReadyCallback
 * SubFunction: NA
 * FunctionPoints: SetSharedSessionReadyCallback
 * EnvConditions: NA
 * CaseDescription: Set a callback and verify it can be set without errors
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_016, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1016;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    bool callbackCalled = false;
    HCaptureSessionWrapper::SharedSessionReadyCallback callback =
        [&callbackCalled](const std::string& cameraId, const sptr<HSharedCameraDevice>& sharedDevice,
            const sptr<HSharedCaptureSession>& sharedSession, pid_t pid) {
            callbackCalled = true;
        };

    wrapper->SetSharedSessionReadyCallback(callback);
    EXPECT_EQ(wrapper->GetOwnerPid(), ownerPid);
    EXPECT_EQ(wrapper->IsSharedMode(), false);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SwitchShareSession from independent mode
 * SubFunction: NA
 * FunctionPoints: SwitchShareSession, IsSharedMode
 * EnvConditions: NA
 * CaseDescription: Switch independent wrapper to shared mode, verify IsSharedMode and GetRealSession
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_017, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1017;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);
    EXPECT_EQ(wrapper->IsSharedMode(), false);

    CamServiceError err;
    sptr<HSharedCaptureSession> sharedSession = nullptr;
    err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    wrapper->SwitchShareSession(sharedSession);
    EXPECT_EQ(wrapper->IsSharedMode(), true);
    EXPECT_EQ(wrapper->GetRealSession().GetRefPtr(), sharedSession.GetRefPtr());
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SwitchShareSession when already shared
 * SubFunction: NA
 * FunctionPoints: SwitchShareSession
 * EnvConditions: NA
 * CaseDescription: SwitchShareSession on already shared wrapper returns existing session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_018, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1018;

    CamServiceError err;
    sptr<HSharedCaptureSession> sharedSession = nullptr;
    err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    CamServiceError err2;
    sptr<HSharedCaptureSession> sharedSession2 = nullptr;
    err2 = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession2);
    EXPECT_EQ(err2, CAMERA_OK);
    ASSERT_NE(sharedSession2, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, sharedSession);
    ASSERT_NE(wrapper, nullptr);

    wrapper->SwitchShareSession(sharedSession);
    EXPECT_EQ(wrapper->IsSharedMode(), true);

    wrapper->SwitchShareSession(sharedSession2);
    EXPECT_EQ(wrapper->IsSharedMode(), true);
    EXPECT_EQ(wrapper->GetRealSession().GetRefPtr(), sharedSession2.GetRefPtr());
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test Release in shared mode
 * SubFunction: NA
 * FunctionPoints: Release
 * EnvConditions: NA
 * CaseDescription: Release in shared mode calls ReleaseRef on shared session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_019, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1019;

    CamServiceError err;
    sptr<HSharedCaptureSession> sharedSession = nullptr;
    err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, sharedSession);
    ASSERT_NE(wrapper, nullptr);

    wrapper->SwitchShareSession(sharedSession);
    EXPECT_EQ(wrapper->IsSharedMode(), true);

    int32_t rc = wrapper->Release();
    EXPECT_EQ(rc, CAMERA_OK);

    rc = wrapper->Release();
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HCaptureSessionWrapper
 * Function: Test SwitchShareSession with output restoration
 * SubFunction: NA
 * FunctionPoints: SwitchShareSession, AddOutput
 * EnvConditions: NA
 * CaseDescription: Add outputs before switching, verify outputs are restored after switch
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hcapture_session_wrapper_unittest_020, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->SetMdmCheck(false);
    EXPECT_EQ(device->Open(), CAMERA_OK);

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;
    pid_t ownerPid = 1020;

    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    ASSERT_NE(realSession, nullptr);

    sptr<HCaptureSessionWrapper> wrapper = new (std::nothrow) HCaptureSessionWrapper(
        opMode, ownerPid, false, realSession);
    ASSERT_NE(wrapper, nullptr);

    EXPECT_EQ(wrapper->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(wrapper->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(wrapper->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);

    CamServiceError err;
    sptr<HSharedCaptureSession> sharedSession = nullptr;
    err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    wrapper->SwitchShareSession(sharedSession);
    EXPECT_EQ(wrapper->IsSharedMode(), true);
    EXPECT_EQ(wrapper->GetRealSession().GetRefPtr(), sharedSession.GetRefPtr());

    EXPECT_EQ(device->Close(), CAMERA_OK);
}

// =================== HSharedCaptureSession tests ===================

/*
 * Feature: HSharedCaptureSession
 * Function: Test NewInstance creates a new session
 * SubFunction: NA
 * FunctionPoints: NewInstance
 * EnvConditions: NA
 * CaseDescription: Create shared capture session via NewInstance, verify it's not null
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_001, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);
    int32_t rc = sharedSession->SetHasFitedRotation(true);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test GetExistingSession returns null for non-existent cameraId
 * SubFunction: NA
 * FunctionPoints: GetExistingSession
 * EnvConditions: NA
 * CaseDescription: GetExistingSession with non-existent cameraId returns nullptr
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_002, TestSize.Level0)
{
    sptr<HSharedCaptureSession> found = HSharedCaptureSession::GetExistingSession("non_existent_camera");
    EXPECT_EQ(found, nullptr);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test RegisterToMap and UnregisterFromMap
 * SubFunction: NA
 * FunctionPoints: RegisterToMap, UnregisterFromMap, GetExistingSession
 * EnvConditions: NA
 * CaseDescription: Register to map, verify it can be retrieved, then unregister
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_003, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    std::string testCameraId = "test_camera_001";
    sharedSession->RegisterToMap(testCameraId);

    sptr<HSharedCaptureSession> found = HSharedCaptureSession::GetExistingSession(testCameraId);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found.GetRefPtr(), sharedSession.GetRefPtr());

    sharedSession->UnregisterFromMap();

    sptr<HSharedCaptureSession> notFound = HSharedCaptureSession::GetExistingSession(testCameraId);
    EXPECT_EQ(notFound, nullptr);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test AddRef and ReleaseRef reference counting
 * SubFunction: NA
 * FunctionPoints: AddRef, ReleaseRef
 * EnvConditions: NA
 * CaseDescription: AddRef increments, ReleaseRef decrements, multiple refs require multiple releases
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_004, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    pid_t pid1 = 3001;
    pid_t pid2 = 3002;

    sharedSession->AddRef(pid1);
    sharedSession->AddRef(pid1);
    sharedSession->AddRef(pid2);

    sharedSession->ReleaseRef(pid1);
    sharedSession->ReleaseRef(pid1);

    sharedSession->ReleaseRef(pid2);

    EXPECT_EQ(sharedSession->BeginConfig(), CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test AddInput and RemoveInput delegation
 * SubFunction: NA
 * FunctionPoints: AddInput, RemoveInput
 * EnvConditions: NA
 * CaseDescription: Verify AddInput and RemoveInput delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_005, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> hDevice = new (std::nothrow) HCameraDevice(
        cameraHostManager_, cameraIds[0], callerToken);
    ASSERT_NE(hDevice, nullptr);
    sptr<ICameraDeviceService> device = hDevice;
    device->SetMdmCheck(false);
    EXPECT_EQ(device->Open(), CAMERA_OK);

    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);

    bool result = false;
    EXPECT_EQ(sharedSession->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(sharedSession->CanAddInput(device, result), CAMERA_OK);
    ASSERT_TRUE(result);
    EXPECT_EQ(sharedSession->AddInput(device), CAMERA_OK);

    EXPECT_EQ(sharedSession->CanAddInput(device, result), CAMERA_INVALID_SESSION_CFG);
    ASSERT_TRUE(!result);
    EXPECT_EQ(sharedSession->AddInput(device), CAMERA_INVALID_SESSION_CFG);
    EXPECT_EQ(sharedSession->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test AddOutput and RemoveOutput delegation
 * SubFunction: NA
 * FunctionPoints: AddOutput, RemoveOutput
 * EnvConditions: NA
 * CaseDescription: Verify AddOutput and RemoveOutput delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_006, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(sharedSession->BeginConfig(), CAMERA_OK);
    int32_t rc = sharedSession->AddOutput(StreamType::REPEAT, streamRepeat);
    EXPECT_EQ(rc, CAMERA_OK);

    rc = sharedSession->RemoveOutput(StreamType::REPEAT, streamRepeat);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test Start and Stop delegation
 * SubFunction: NA
 * FunctionPoints: Start, Stop
 * EnvConditions: NA
 * CaseDescription: Verify Start and Stop delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_007, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t rc = sharedSession->Start();
    rc = sharedSession->Stop();
    EXPECT_EQ(rc, CAMERA_INVALID_STATE);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test Release delegation
 * SubFunction: NA
 * FunctionPoints: Release
 * EnvConditions: NA
 * CaseDescription: Verify Release delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_008, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t rc = sharedSession->Release();
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test SetCallback and UnSetCallback delegation
 * SubFunction: NA
 * FunctionPoints: SetCallback, UnSetCallback
 * EnvConditions: NA
 * CaseDescription: Verify SetCallback and UnSetCallback delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_009, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    sptr<MockHCaptureSessionCallbackStub> callback = new (std::nothrow) MockHCaptureSessionCallbackStub();
    ASSERT_NE(callback, nullptr);

    EXPECT_EQ(sharedSession->SetCallback(callback), CAMERA_OK);
    EXPECT_EQ(sharedSession->UnSetCallback(), CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test GetSessionState delegation
 * SubFunction: NA
 * FunctionPoints: GetSessionState
 * EnvConditions: NA
 * CaseDescription: Verify GetSessionState delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_010, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    CaptureSessionState sessionState = CaptureSessionState::SESSION_INIT;
    int32_t rc = sharedSession->GetSessionState(sessionState);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test SetSmoothZoom delegation
 * SubFunction: NA
 * FunctionPoints: SetSmoothZoom
 * EnvConditions: NA
 * CaseDescription: Verify SetSmoothZoom delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_011, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    float duration = 0.0f;
    int32_t rc = sharedSession->SetSmoothZoom(0, 0, 2.0f, duration);
    EXPECT_EQ(rc, CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test SetFeatureMode delegation
 * SubFunction: NA
 * FunctionPoints: SetFeatureMode
 * EnvConditions: NA
 * CaseDescription: Verify SetFeatureMode delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_012, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t rc = sharedSession->SetFeatureMode(0);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test SetColorSpace and GetActiveColorSpace delegation
 * SubFunction: NA
 * FunctionPoints: SetColorSpace, GetActiveColorSpace
 * EnvConditions: NA
 * CaseDescription: Verify SetColorSpace and GetActiveColorSpace delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_013, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t curColorSpace = 0;
    int32_t rc = sharedSession->GetActiveColorSpace(curColorSpace);
    EXPECT_EQ(rc, CAMERA_OK);
    rc = sharedSession->SetColorSpace(0, false);
    EXPECT_EQ(rc, CAMERA_INVALID_STATE);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test EnableMovingPhoto and EnableMovingPhotoMirror delegation
 * SubFunction: NA
 * FunctionPoints: EnableMovingPhoto, EnableMovingPhotoMirror
 * EnvConditions: NA
 * CaseDescription: Verify EnableMovingPhoto and EnableMovingPhotoMirror delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_014, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t rc = sharedSession->EnableMovingPhoto(true);
    EXPECT_EQ(rc, CAMERA_OK);

    rc = sharedSession->EnableMovingPhoto(false);
    EXPECT_EQ(rc, CAMERA_OK);

    rc = sharedSession->EnableMovingPhotoMirror(true, false);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test SetPreviewRotation and SetCommitConfigFlag delegation
 * SubFunction: NA
 * FunctionPoints: SetPreviewRotation, SetCommitConfigFlag
 * EnvConditions: NA
 * CaseDescription: Verify SetPreviewRotation and SetCommitConfigFlag delegate to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_015, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t rc = sharedSession->SetPreviewRotation("test_device");
    EXPECT_EQ(rc, CAMERA_OK);

    rc = sharedSession->SetCommitConfigFlag(false);
    EXPECT_EQ(rc, CAMERA_OK);
}

/*
 * Feature: HSharedCaptureSession
 * Function: Test SetHasFitedRotation delegation
 * SubFunction: NA
 * FunctionPoints: SetHasFitedRotation
 * EnvConditions: NA
 * CaseDescription: Verify SetHasFitedRotation delegates to real session
 */
HWTEST_F(HSharedCaptureSessionUnitTest, hshared_capture_session_unittest_016, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = SceneMode::NORMAL;

    sptr<HSharedCaptureSession> sharedSession = nullptr;
    CamServiceError err = HSharedCaptureSession::NewInstance(callerToken, opMode, sharedSession);
    EXPECT_EQ(err, CAMERA_OK);
    ASSERT_NE(sharedSession, nullptr);

    int32_t rc = sharedSession->SetHasFitedRotation(true);
    EXPECT_EQ(rc, CAMERA_OK);
}
} // CameraStandard
} // OHOS