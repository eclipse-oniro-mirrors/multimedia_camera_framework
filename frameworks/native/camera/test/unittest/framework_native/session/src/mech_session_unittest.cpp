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
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "camera_util.h"
#include "surface.h"
#include "test_common.h"
#include "hcapture_session.h"
#include "test_token.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
static const int32_t PREVIEW_WIDTH = 1920;
static const int32_t PREVIEW_HEIGHT = 1080;
void MechSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void MechSessionUnitTest::TearDownTestCase(void) {}

void MechSessionUnitTest::SetUp()
{
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

void MechSessionUnitTest::CommitConfig()
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput_ = (sptr<CameraInput> &)input;
    ASSERT_NE(camInput_, nullptr);
    std::string cameraSettings = camInput_->GetCameraSettings();
    camInput_->SetCameraSettings(cameraSettings);
    if (camInput_->GetCameraDevice()) {
        camInput_->GetCameraDevice()->SetMdmCheck(false);
        camInput_->GetCameraDevice()->Open();
    }
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

void MechSessionUnitTest::SetFocusPoint(float x, float y)
{
    ASSERT_NE(captureSession_, nullptr);
    Point point;
    point.x = x;
    point.y = y;
    captureSession_->SetFocusPoint(point);
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
 * Function: Test OnCaptureSessionConfiged when session start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureSessionConfiged when session start
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_008, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);

    auto mechSessionCallback = std::make_shared<AppMechSessionCallback>();
    mechSession->SetCallback(mechSessionCallback);

    CommitConfig();
    StartSession();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CaptureSessionInfo sessionInfo = mechSessionCallback->GetSessionInfo();
    auto outputInfos = sessionInfo.outputInfos;
    int size = outputInfos.size();
    EXPECT_NE(size, 0);
    for (int i = 0; i < size; i++) {
        auto outputInfo = outputInfos[i];
        EXPECT_EQ(outputInfo.width, PREVIEW_WIDTH);
        EXPECT_EQ(outputInfo.height, PREVIEW_HEIGHT);
    }

    StopSession();
    ReleaseSession();
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test OnSessionStatusChange when session start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MechSession OnSessionStatusChange when session start
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
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(mechSessionCallback->GetSessionStatus(), true);
    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);

    StopSession();
    ReleaseSession();
}

/*
 * Feature: Framework
 * Function: Test OnSessionStatusChange when session stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MechSession OnSessionStatusChange when session stop
 */
HWTEST_F(MechSessionUnitTest, mech_session_unittest_010, TestSize.Level0)
{
    sptr<MechSession> mechSession = cameraManager_->CreateMechSession(userId_);
    ASSERT_NE(mechSession, nullptr);
    int32_t retCode = mechSession->EnableMechDelivery(true);
    EXPECT_EQ(retCode, 0);

    auto mechSessionCallback = std::make_shared<AppMechSessionCallback>();
    mechSession->SetCallback(mechSessionCallback);

    CommitConfig();
    StartSession();

    StopSession();
    ReleaseSession();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(mechSessionCallback->GetSessionStatus(), false);

    retCode = mechSession->Release();
    EXPECT_EQ(retCode, 0);
}
}
}