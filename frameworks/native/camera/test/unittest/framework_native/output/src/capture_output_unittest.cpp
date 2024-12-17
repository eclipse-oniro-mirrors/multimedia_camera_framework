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

#include "capture_output_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void CameraCaptureOutputUnit::SetUpTestCase(void) {}

void CameraCaptureOutputUnit::TearDownTestCase(void) {}

void CameraCaptureOutputUnit::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraCaptureOutputUnit::TearDown()
{
    if (cameraManager_) {
        cameraManager_ = nullptr;
    }
}

void CameraCaptureOutputUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraCaptureOutputUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

sptr<CaptureOutput> CameraCaptureOutputUnit::CreatePhotoOutput(int32_t width, int32_t height)
{
    std::vector<Profile> photoProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    if (!outputCapability) {
        return nullptr;
    }

    photoProfile = outputCapability->GetPhotoProfiles();
    if (photoProfile.empty()) {
        return nullptr;
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile[0], surfaceProducer);
}

/*
 * Feature: Framework
 * Function: Test captureoutput with RegisterStreamBinderDied and UnregisterStreamBinderDied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureoutput with RegisterStreamBinderDied and UnregisterStreamBinderDied
 *        for abnormal branches
 */
HWTEST_F(CameraCaptureOutputUnit, capture_output_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> captureOutput = CreatePhotoOutput();
    ASSERT_NE(captureOutput, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();

    session->AddInput(input);
    session->AddOutput(captureOutput);

    session->CommitConfig();
    session->Start();

    pid_t pid = 0;
    sptr<CameraDeathRecipient> deathRecipient = new CameraDeathRecipient(pid);
    captureOutput->deathRecipient_ = deathRecipient;
    captureOutput->RegisterStreamBinderDied();
    EXPECT_NE(captureOutput->deathRecipient_, nullptr);

    captureOutput->stream_ = nullptr;
    captureOutput->UnregisterStreamBinderDied();
    EXPECT_EQ(captureOutput->stream_, nullptr);

    if (deathRecipient) {
        deathRecipient = nullptr;
    }
    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

}
}
