/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mech_session_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "hcapture_session.h"
#include "hcamera_service.h"
#include "session/video_session.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
static const int32_t PREVIEW_WIDTH = 1920;
static const int32_t PREVIEW_HEIGHT = 1080;
void MechSessionUnitTest::SetUpTestCase(void) {}

void MechSessionUnitTest::TearDownTestCase(void) {}

void MechSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void MechSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    captureSession_ = nullptr;
    camInput_ = nullptr;
    MEDIA_DEBUG_LOG("MechSessionUnitTest TearDown");
}

void MechSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("MechSessionUnitTest::NativeAuthorization uid_:%{public}d, userId_:%{public}d", uid_, userId_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void MechSessionUnitTest::CommitConfig()
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput_ = (sptr<CameraInput> &)input;
    ASSERT_NE(camInput_, nullptr);
    std::string cameraSettings = camInput_->GetCameraSettings();
    camInput_->SetCameraSettings(cameraSettings);
    camInput_->GetCameraDevice()->Open();
    captureSession_ = cameraManager_->CreateCaptureSession(SceneMode::NORMAL);
    ASSERT_NE(captureSession_, nullptr);

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = PREVIEW_WIDTH;
    previewSize.height = PREVIEW_HEIGHT;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
    ASSERT_NE(previewOutput, nullptr);

    int32_t retCode = captureSession_->BeginConfig();
    EXPECT_EQ(retCode, 0);

    retCode = captureSession_->AddInput(input);
    EXPECT_EQ(retCode, 0);

    sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
    retCode = captureSession_->AddOutput(previewOutputCaptureUpper);
    EXPECT_EQ(retCode, 0);

    retCode = captureSession_->CommitConfig();
    EXPECT_EQ(retCode, 0);
}

void MechSessionUnitTest::StartSession()
{
    ASSERT_NE(captureSession_, nullptr);
    captureSession_->Start();
}

void MechSessionUnitTest::StopSession()
{
    ASSERT_NE(captureSession_, nullptr);
    captureSession_->Stop();
}

void MechSessionUnitTest::ReleaseSession()
{
    if (captureSession_ != nullptr) {
        captureSession_->Release();
    }
    if (camInput_ != nullptr) {
        camInput_->Close();
    }
}

/*
 * Feature: Framework
 * Function: Test IsMechSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMechSupported
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_001, TestSize.Level0)
{
    bool isSupported = cameraManager_->IsMechSupported();
    MEDIA_INFO_LOG("MechSessionUnitTest::IsMechSupported :%{public}d", isSupported);
}

/*
 * Feature: Framework
 * Function: Test CreateMechSession with errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMechSession with errorCode
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_002, TestSize.Level0)
{
    sptr<MechSession> mechSession = nullptr;
    int32_t retCode = cameraManager_->CreateMechSession(userId_, &mechSession);
    EXPECT_EQ(retCode, 0);
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test CreateMechSession twice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMechSession twice
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_003, TestSize.Level0)
{
    sptr<MechSession> mechSession = nullptr;
    int32_t retCode = cameraManager_->CreateMechSession(userId_, &mechSession);
    EXPECT_EQ(retCode, 0);
    ASSERT_NE(mechSession, nullptr);
    retCode = cameraManager_->CreateMechSession(userId_, &mechSession);
    EXPECT_EQ(retCode, 0);
    ASSERT_NE(mechSession, nullptr);
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test CreateMechSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMechSession
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_004, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test release mechSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test release mechSession
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_005, TestSize.Level0)
{
    sptr<MechSession> mechSession = nullptr;
    int32_t retCode = cameraManager_->CreateMechSession(userId_, &mechSession);
    EXPECT_EQ(retCode, 0);
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);

    retCode = cameraManager_->CreateMechSession(userId_, &mechSession);
    EXPECT_EQ(retCode, 0);
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test EnableMechDelivery before session start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableMechDelivery before session start
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_006, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);

    CommitConfig();
    StartSession();
    StopSession();
    ReleaseSession();

    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test EnableMechDelivery after session start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableMechDelivery after session start
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_007, TestSize.Level0)
{
    CommitConfig();
    StartSession();

    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);

    StopSession();
    ReleaseSession();

    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test MechSession SetCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MechSession SetCallback
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_008, TestSize.Level0)
{
    CommitConfig();
    StartSession();

    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);
    auto mechSessionCallback = std::make_shared<AppMechSessionCallback>();
    mechSession->SetCallback(mechSessionCallback);

    StopSession();
    ReleaseSession();

    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test MechSession callback when session start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MechSession callback when session star
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_009, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);

    auto mechSessionCallback = std::make_shared<AppMechSessionCallback>();
    mechSession->SetCallback(mechSessionCallback);

    CommitConfig();
    StartSession();

    std::vector<CameraAppInfo> cameraAppInfos = mechSessionCallback->GetCameraAppInfos();
    int size = cameraAppInfos.size();
    EXPECT_NE(size, 0);
    for (int i = 0; i < size; i++) {
        auto appInfo = cameraAppInfos[i];
        EXPECT_EQ(appInfo.width, PREVIEW_WIDTH);
        EXPECT_EQ(appInfo.height, PREVIEW_HEIGHT);
        EXPECT_EQ(appInfo.videoStatus, true);
    }
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);

    StopSession();
    ReleaseSession();
}

/*
 * Feature: Framework
 * Function: Test MechSession callback when session stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MechSession callback when session stop
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_010, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);

    CommitConfig();
    StartSession();

    auto mechSessionCallback = std::make_shared<AppMechSessionCallback>();
    mechSession->SetCallback(mechSessionCallback);
    StopSession();
    std::vector<CameraAppInfo> cameraAppInfos = mechSessionCallback->GetCameraAppInfos();
    int size = cameraAppInfos.size();
    EXPECT_NE(size, 0);
    for (int i = 0; i < size; i++) {
        auto appInfo = cameraAppInfos[i];
        EXPECT_EQ(appInfo.width, PREVIEW_WIDTH);
        EXPECT_EQ(appInfo.height, PREVIEW_HEIGHT);
        EXPECT_EQ(appInfo.videoStatus, false);
    }
    ReleaseSession();
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test MechSession SetCallback when session setZoomRatio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MechSession SetCallback when session setZoomRatio
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_011, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    auto mechSessionCallback = std::make_shared<AppMechSessionCallback>();
    mechSession->SetCallback(mechSessionCallback);
    EXPECT_EQ(retCode, 0);
    CommitConfig();
    StartSession();

    std::vector<float> zoomRatioRange = captureSession_->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        for (int i = 0; i < zoomRatioRange.size(); i++) {
            float zoomRatio = zoomRatioRange[i];
            captureSession_->LockForControl();
            captureSession_->SetZoomRatio(zoomRatio);
            captureSession_->UnlockForControl();
        }
    }

    void StopSession();
    void ReleaseSession();

    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}
}
}
