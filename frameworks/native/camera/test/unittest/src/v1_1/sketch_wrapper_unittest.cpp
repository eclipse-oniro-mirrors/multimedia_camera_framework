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

#include "sketch_wrapper_unittest.h"

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

void CameraSketchWrapperOutputUnit::SetUpTestCase(void) {}

void CameraSketchWrapperOutputUnit::TearDownTestCase(void) {}

void CameraSketchWrapperOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
}

void CameraSketchWrapperOutputUnit::TearDown()
{
    NativeAuthorization();
    cameraManager_ = nullptr;
}

void CameraSketchWrapperOutputUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraSketchWrapperOutputUnit::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper with OnSketchStatusChanged and SetPreviewStateCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper with OnSketchStatusChanged and SetPreviewStateCallback
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput>&)input;

    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = 1440;
    previewSize.height = 1080;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    SketchWrapper *sketchWrapper = new (std::nothrow)
        SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    sketchWrapper->AutoStream();

    std::shared_ptr<PreviewStateCallback> previewStateCallback =
        std::make_shared<TestPreviewOutputCallback>("PreviewStateCallback");
    EXPECT_NE(previewStateCallback, nullptr);
    sketchWrapper->SetPreviewStateCallback(previewStateCallback);
    EXPECT_NE(sketchWrapper->previewStateCallback_.lock(), nullptr);

    SketchStatus sketchStatus = SketchStatus::STARTING;
    std::shared_ptr<SceneFeaturesMode> sceneFeaturesMode = std::make_shared<SceneFeaturesMode>();
    EXPECT_NE(sceneFeaturesMode, nullptr);
    sketchWrapper->OnSketchStatusChanged(sketchStatus, *sceneFeaturesMode);
    sketchWrapper->AutoStream();

    if (sketchWrapper) {
        sketchWrapper = nullptr;
    }
    EXPECT_EQ(previewOutput->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test Destroy StartSketchStream StopSketchStream while sketchStream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Destroy StartSketchStream StopSketchStream while sketchStream_ is nullptr
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput>&)input;

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        cameraInput->GetCameraDeviceInfo()->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);

    int32_t width = 1440;
    int32_t height = 1080;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    SketchWrapper *sketchWrapper = new (std::nothrow)
        SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    sketchWrapper->sketchStream_ = nullptr;
    int32_t ret = sketchWrapper->Destroy();
    EXPECT_EQ(ret, CAMERA_OK);
    ret = sketchWrapper->StartSketchStream();
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);
    ret = sketchWrapper->StopSketchStream();
    EXPECT_EQ(ret, CAMERA_UNKNOWN_ERROR);

    if (sketchWrapper) {
        sketchWrapper = nullptr;
    }
    EXPECT_EQ(previewOutput->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test AutoStream while currentZoomRatio_ < 0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AutoStream while currentZoomRatio_ < 0
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput>&)input;

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        cameraInput->GetCameraDeviceInfo()->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);

    int32_t width = 1440;
    int32_t height = 1080;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    SketchWrapper *sketchWrapper = new (std::nothrow)
    SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    sketchWrapper->currentZoomRatio_ = -1.0f;
    sketchWrapper->AutoStream();
    if (sketchWrapper) {
        sketchWrapper = nullptr;
    }
    EXPECT_EQ(previewOutput->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test OnSketchStatusChanged while status != sketchStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnSketchStatusChanged while status != sketchStatus
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput>&)input;

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        cameraInput->GetCameraDeviceInfo()->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);

    int32_t width = 1440;
    int32_t height = 1080;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    SketchWrapper *sketchWrapper = new (std::nothrow)
        SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    sketchWrapper->currentSketchStatusData_.status = SketchStatus::STARTED;
    sketchWrapper->currentSketchStatusData_.sketchRatio = 1.0f;
    SketchStatus sketchStatus = SketchStatus::STOPED;
    SceneFeaturesMode sceneFeaturesMode {};
    sketchWrapper->OnSketchStatusChanged(sketchStatus, sceneFeaturesMode);
    sketchStatus = SketchStatus::STARTED;
    sketchWrapper->OnSketchStatusChanged(sketchStatus, sceneFeaturesMode);

    if (sketchWrapper) {
        sketchWrapper = nullptr;
    }
    EXPECT_EQ(previewOutput->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
}

}
}
