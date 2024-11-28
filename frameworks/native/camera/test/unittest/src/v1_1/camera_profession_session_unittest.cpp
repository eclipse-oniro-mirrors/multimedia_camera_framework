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

#include "camera_profession_session_unittest.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "test_common.h"
#include "token_setproc.h"

#define METERING_MODE_UNDEFINE (-1)
int32_t g_videoFd = -1;
int32_t g_previewFd = -1;

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;

class ExposureInfoCallbackMock : public ExposureInfoCallback {
public:
    void OnExposureInfoChanged(ExposureInfo info) override {}
};

class IsoInfoCallbackMock : public IsoInfoCallback {
public:
    void OnIsoInfoChanged(IsoInfo info) override {}
};

class ApertureInfoCallbackMock : public ApertureInfoCallback {
public:
    void OnApertureInfoChanged(ApertureInfo info) override {}
};

class LuminationInfoCallbackMock : public LuminationInfoCallback {
public:
    void OnLuminationInfoChanged(LuminationInfo info) override {}
};

void ProfessionSessionUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredProcUnitTest::SetUpTestCase started!");
}

void ProfessionSessionUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredProcUnitTest::TearDownTestCase started!");
}

void ProfessionSessionUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp testName:%{public}s",
        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    NativeAuthorization();
    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    cameras_ = manager_->GetSupportedCameras();
    ASSERT_TRUE(cameras_.size() != 0);
    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    sceneMode_ = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSupportMode(sceneMode_)) {
        return;
    }
    g_videoFd = -1;
    g_previewFd = -1;
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode_);
    ASSERT_NE(modeAbility, nullptr);

    sptr<CaptureSession> captureSession = cameraManagerObj->CreateCaptureSession(sceneMode_);
    ASSERT_NE(captureSession, nullptr);
    session_ = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session_, nullptr);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);
    intResult = input_->Open();
    EXPECT_EQ(intResult, 0);
    Profile previewProfile;
    VideoProfile videoProfile;
    auto previewProfiles = modeAbility->GetPreviewProfiles();
    auto videoProfiles = modeAbility->GetVideoProfiles();
    for (const auto &vProfile : videoProfiles) {
        for (const auto &pProfile : previewProfiles) {
            if (vProfile.size_.width == pProfile.size_.width) {
                previewProfile = pProfile;
                videoProfile = vProfile;
                break;
            }
        }
    }
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);
}

void ProfessionSessionUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("DeferredProcUnitTest::TearDown started!");
    cameras_.clear();
    manager_ = nullptr;
    session_ = nullptr;
    input_ = nullptr;
}

void ProfessionSessionUnitTest::NativeAuthorization()
{
    uint64_t tokenId;
    const char* perms[2];
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
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

bool ProfessionSessionUnitTest::IsSupportMode(SceneMode mode)
{
    std::vector<SceneMode> modes = manager_->GetSupportedModes(cameras_[0]);
    if (modes.size() == 0) {
        MEDIA_ERR_LOG("IsSupportMode: modes.size is null");
        return false;
    }
    bool supportMode = false;
    for (auto &it : modes) {
        if (it == mode) {
            supportMode = true;
            break;
        }
    }
    return supportMode;
}

sptr<CaptureOutput> ProfessionSessionUnitTest::CreatePreviewOutput(Profile& profile)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    Size previewSize = profile.GetSize();
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(profile, pSurface);
    return previewOutput;
}

sptr<CaptureOutput> ProfessionSessionUnitTest::CreateVideoOutput(VideoProfile& videoProfile)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    sptr<CaptureOutput> videoOutput = nullptr;
    videoOutput = manager_->CreateVideoOutput(videoProfile, videoSurface);
    return videoOutput;
}

/*
 * Feature: Framework
 * Function: Testing multiple calls to set interface function returns normal.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Testing multiple calls to set interface function returns normal.
 */
HWTEST_F(ProfessionSessionUnitTest, camera_profession_session_unittest_001, TestSize.Level0)
{
    if (IsSupportMode(sceneMode_)) {
        bool isSupported = true;
        MeteringMode meteringMode = static_cast<MeteringMode>(METERING_MODE_UNDEFINE);
        session_->IsMeteringModeSupported(meteringMode, isSupported);
        EXPECT_TRUE(!isSupported);

        FocusMode focusMode = static_cast<FocusMode>(METERING_MODE_UNDEFINE);
        isSupported = true;
        session_->IsFocusModeSupported(focusMode, isSupported);
        EXPECT_TRUE(!isSupported);

        FocusAssistFlashMode mode = static_cast<FocusAssistFlashMode>(METERING_MODE_UNDEFINE);
        session_->IsFocusAssistFlashModeSupported(mode, isSupported);
        EXPECT_TRUE(!isSupported);

        FlashMode flashMode = static_cast<FlashMode>(METERING_MODE_UNDEFINE);
        session_->IsFlashModeSupported(flashMode, isSupported);
        EXPECT_TRUE(!isSupported);

        session_->LockForControl();
        int ret = session_->SetMeteringMode(meteringMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        meteringMode = METERING_MODE_SPOT;
        ret = session_->SetMeteringMode(meteringMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetFocusMode(focusMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetFocusMode(focusMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ExposureHintMode hintMode = static_cast<ExposureHintMode>(METERING_MODE_UNDEFINE);
        ret = session_->SetExposureHintMode(hintMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetExposureHintMode(hintMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetFocusAssistFlashMode(mode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetFocusAssistFlashMode(mode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetFlashMode(flashMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetFlashMode(flashMode);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ColorEffect colorEffect = static_cast<ColorEffect>(METERING_MODE_UNDEFINE);
        ret = session_->SetColorEffect(colorEffect);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        ret = session_->SetColorEffect(colorEffect);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

        session_->UnlockForControl();
    }
}

/*
 * Feature: Framework
 * Function: Test setting callback interface returns normal.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting callback interface returns normal.
 */
HWTEST_F(ProfessionSessionUnitTest, camera_profession_session_unittest_002, TestSize.Level0)
{
    if (IsSupportMode(sceneMode_)) {
        session_->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
        EXPECT_NE(session_->exposureInfoCallback_, nullptr);

        session_->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
        EXPECT_NE(session_->isoInfoCallback_, nullptr);

        session_->SetApertureInfoCallback(make_shared<ApertureInfoCallbackMock>());
        EXPECT_NE(session_->apertureInfoCallback_, nullptr);

        session_->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
        EXPECT_NE(session_->luminationInfoCallback_, nullptr);
    }
}
}
}