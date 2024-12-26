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
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
}

void CameraSketchWrapperOutputUnit::TearDown()
{
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
    MEDIA_DEBUG_LOG("CameraSketchWrapperOutputUnit::NativeAuthorization uid:%{public}d", uid_);
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

/*
 * Feature: Framework
 * Function: Test GetSketchReferenceFovRatio, UpdateSketchReferenceFovRatio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSketchReferenceFovRatio, UpdateSketchReferenceFovRatio
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    Size previewSize = { .width = 1440, .height = 1080 };
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    camInput->SetCameraSettings(camInput->GetCameraSettings());
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata = cameras[0]->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);
    session->GetFeaturesMode();
    Profile previewProfile = Profile(CAMERA_FORMAT_YCBCR_420_888, previewSize);
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    SketchWrapper* sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), previewSize);
    ASSERT_NE(sketchWrapper, nullptr);
    std::shared_ptr<PreviewStateCallback> setCallback =
        std::make_shared<TestPreviewOutputCallback>("PreviewStateCallback");
    ASSERT_NE(setCallback, nullptr);
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);

    auto sketchReferenceFovRangeVec = std::vector<SketchReferenceFovRange>(5);
    SketchReferenceFovRange sketchReferenceFovRange = { .zoomMin = -1.0f, .zoomMax = -1.0f, .referenceValue = -1.0f };
    sketchReferenceFovRangeVec[0] = sketchReferenceFovRange;
    sketchReferenceFovRange = { .zoomMin = -1.0f, .zoomMax = 100.0f, .referenceValue = -1.0f };
    SceneFeaturesMode illegalFeaturesMode(static_cast<SceneMode>(-1), {});
    SketchWrapper::g_sketchReferenceFovRatioMap_[illegalFeaturesMode] = sketchReferenceFovRangeVec;
    EXPECT_EQ(sketchWrapper->GetSketchReferenceFovRatio(illegalFeaturesMode, -1.0f), -1.0f);
    sketchReferenceFovRangeVec[1] = sketchReferenceFovRange;
    sketchReferenceFovRange = { .zoomMin = 100.0f, .zoomMax = 1.0f, .referenceValue = -1.0f };
    sketchReferenceFovRangeVec[2] = sketchReferenceFovRange;
    sketchReferenceFovRange = { .zoomMin = 100.0f, .zoomMax = 100.0f, .referenceValue = -1.0f };
    sketchReferenceFovRangeVec[3] = sketchReferenceFovRange;
    sketchReferenceFovRange = { .zoomMin = 100.0f, .zoomMax = 200.0f, .referenceValue = -1.0f };
    sketchReferenceFovRangeVec[4] = sketchReferenceFovRange;

    SceneFeaturesMode illegalFeaturesMode2(static_cast<SceneMode>(100), {});
    SketchWrapper::g_sketchReferenceFovRatioMap_[illegalFeaturesMode2] = sketchReferenceFovRangeVec;
    EXPECT_EQ(sketchWrapper->GetSketchReferenceFovRatio(illegalFeaturesMode2, -1.0f), -1.0f);
    EXPECT_EQ(sketchWrapper->GetSketchReferenceFovRatio(illegalFeaturesMode2, 200.0f), -1.0f);
    EXPECT_EQ(sketchWrapper->GetSketchReferenceFovRatio(illegalFeaturesMode2, 100.0f), -1.0f);
    sketchWrapper->UpdateSketchReferenceFovRatio(item);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> cameraInput = (sptr<CameraInput>&)input;

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata = cameraInput->GetCameraDeviceInfo()->GetMetadata();
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

    SketchWrapper* sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto modeName = session->GetFeaturesMode();
    int ret = sketchWrapper->Init(deviceMetadata, modeName);
    EXPECT_EQ(ret, CAMERA_OK);

    sketchWrapper->sketchStream_ = nullptr;
    ret = sketchWrapper->AttachSketchSurface(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
    EXPECT_EQ(sketchWrapper->StartSketchStream(), CAMERA_UNKNOWN_ERROR);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    sketchWrapper->UpdateSketchEnableRatio(metadata);
    sketchWrapper->UpdateSketchReferenceFovRatio(metadata);
    sketchWrapper->UpdateSketchConfigFromMoonCaptureBoostConfig(metadata);
    EXPECT_EQ(sketchWrapper->StopSketchStream(), CAMERA_UNKNOWN_ERROR);
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
    sptr<CaptureOutput> previewOutput =
        cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    SketchWrapper *sketchWrapper = new (std::nothrow)
        SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);

    auto modeName = session->GetFeaturesMode();
    int ret = sketchWrapper->Init(deviceMetadata, modeName);
    EXPECT_EQ(ret, CAMERA_OK);
    sketchWrapper->AutoStream();

    float sketchRatio = sketchWrapper->GetSketchEnableRatio(session->GetFeaturesMode());
    EXPECT_EQ(sketchRatio, -1.0);
    sketchWrapper->hostStream_ = nullptr;
    EXPECT_EQ(sketchWrapper->UpdateSketchRatio(sketchRatio), CAMERA_INVALID_STATE);
    EXPECT_EQ(sketchWrapper->Destroy(), CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper with different tag
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper with different tag
 */
HWTEST_F(CameraSketchWrapperOutputUnit, sketch_wrapper_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    SketchWrapper *sketchWrapper = new (std::nothrow)
        SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);

    auto modeName = session->GetFeaturesMode();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    std::vector<int32_t> testStreamInfo = { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 };
    metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, testStreamInfo.data(), testStreamInfo.size());
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(
        metadata->get(), OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    std::cout<<"META:"<<(ret == CAM_META_SUCCESS)<<std::endl;
    const camera_device_metadata_tag_t tag1 = OHOS_CONTROL_ZOOM_RATIO;
    EXPECT_EQ(sketchWrapper->OnMetadataDispatch(modeName, tag1, item), 0);
    const camera_device_metadata_tag_t tag2 = OHOS_CONTROL_CAMERA_MACRO;
    EXPECT_EQ(sketchWrapper->OnMetadataDispatch(modeName, tag2, item), CAM_META_SUCCESS);
}
}
}
