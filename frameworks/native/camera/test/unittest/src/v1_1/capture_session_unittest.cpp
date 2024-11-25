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

#include "capture_session_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

class AppSessionCallback : public SessionCallback {
public:
    void OnError(int32_t errorCode)
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
        return;
    }
};

sptr<CaptureOutput> CaptureSessionUnitTest::CreatePreviewOutput(int32_t width, int32_t height)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    Profile previewProfile = Profile(previewFormat, previewSize);
    return cameraManager_->CreatePreviewOutput(previewProfile, surface);
}

void CaptureSessionUnitTest::SetUpTestCase(void) {}

void CaptureSessionUnitTest::TearDownTestCase(void) {}

void CaptureSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
}

void CaptureSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
}

void CaptureSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CaptureSessionUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSessionFunctions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSessionFunctions for inputDevice is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_001, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    std::vector<Profile> previewProfiles = {};
    std::vector<Profile> photoProfiles = {};
    std::vector<VideoProfile> videoProfiles = {};
    bool isForApp = true;
    EXPECT_EQ(session->GetInputDevice(), nullptr);
    auto innerInputDevice = session->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles, isForApp);
    EXPECT_EQ(innerInputDevice.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test captureSession with CheckFrameRateRangeWithCurrentFps
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckFrameRateRangeWithCurrentFps for (minFps % curMinFps == 0 || curMinFps % minFps == 0)
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_002, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session, nullptr);
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(20, 20, 40, 40));
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(40, 40, 20, 20));
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetMaxSizePhotoProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMaxSizePhotoProfile for SceneMode is NORMAL
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_003, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session, nullptr);
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    EXPECT_NE(input->GetCameraDeviceInfo(), nullptr);
    input->GetCameraDeviceInfo()->cameraType_ = CAMERA_TYPE_DEFAULT;
    session->SetInputDevice(input);
    ProfileSizeRatio sizeRatio = UNSPECIFIED;
    session->currentMode_ = SceneMode::NORMAL;
    EXPECT_EQ(session->guessMode_, SceneMode::NORMAL);
    EXPECT_EQ(session->GetMaxSizePhotoProfile(sizeRatio), nullptr);
}

/*
 * Feature: Framework
 * Function: Test captureSession with CreateMediaLibrary
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMediaLibrary for captureSession is nullptr and not nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_005, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_NE(session->GetCaptureSession(), nullptr);
    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);

    session->SetCaptureSession(nullptr);
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetPreviewRotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPreviewRotation for captureSession is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_006, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::string deviceClass;
    session->SetCaptureSession(nullptr);
    EXPECT_EQ(session->SetPreviewRotation(deviceClass), CAMERA_OK);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetGuessMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetGuessMode for switch of default
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_008, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    SceneMode mode = SceneMode::PORTRAIT;
    session->currentMode_ = SceneMode::NORMAL;
    session->SetGuessMode(mode);
    EXPECT_NE(session->guessMode_, SceneMode::PORTRAIT);

    EXPECT_EQ(session->Release(), 0);
}
}
}