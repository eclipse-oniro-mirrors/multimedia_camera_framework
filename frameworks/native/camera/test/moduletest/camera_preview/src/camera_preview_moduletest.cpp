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

#include "camera_preview_moduletest.h"

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "token_setproc.h"
#include "camera_log.h"
#include "test_token.h"


using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static std::mutex g_mutex;

void CameraPreviewModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPreviewModuleTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPreviewModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPreviewModuleTest::TearDownTestCase started!");
}

void CameraPreviewModuleTest::SetUp()
{
    MEDIA_INFO_LOG("CameraPreviewModuleTest::SetUp start!");

    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    cameras_ = manager_->GetSupportedCameras();
    ASSERT_FALSE(cameras_.empty());
    session_ = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session_, nullptr);
    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    auto device = input_->GetCameraDevice();
    ASSERT_NE(device, nullptr);
    device->SetMdmCheck(false);

    EXPECT_EQ(input_->Open(), SUCCESS);
    UpdateCameraOutputCapability();
    MEDIA_INFO_LOG("CameraPreviewModuleTest::SetUp end!");
}

void CameraPreviewModuleTest::TearDown()
{
    MEDIA_INFO_LOG("CameraPreviewModuleTest::TearDown start!");

    cameras_.clear();
    previewProfile_.clear();

    previewOutput_->Release();

    manager_ = nullptr;

    if (input_) {
        auto device = input_->GetCameraDevice();
        if (device) {
            device->SetMdmCheck(true);
        }
        input_->Release();
    }
    session_->Release();
    previewSurface_ = nullptr;
    MEDIA_INFO_LOG("CameraPreviewModuleTest::TearDown end!");
}

void CameraPreviewModuleTest::UpdateCameraOutputCapability(int32_t modeName)
{
    if (!manager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());
}

int32_t CameraPreviewModuleTest::CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput)
{
    previewSurface_ = Surface::CreateSurfaceAsConsumer();
    if (previewSurface_ == nullptr) {
        MEDIA_ERR_LOG("Failed to get previewOutput surface");
        return INVALID_ARGUMENT;
    }
    previewSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewListener_ = nullptr;
    previewListener_ = new (std::nothrow) TestPreviewConsumer(previewSurface_);
    SurfaceError ret = previewSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)previewListener_);
    EXPECT_EQ(ret, SURFACE_ERROR_OK);
    int32_t retCode = manager_->CreatePreviewOutput(profile, previewSurface_, &previewOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return SERVICE_FATL_ERROR;
    }
    return SUCCESS;
}

int32_t CameraPreviewModuleTest::CreateYuvPreviewOutput()
{
    Profile yuvProfile;
    std::cout << "photo yuv profle format:" << yuvPhotoProfile_.GetCameraFormat()
              << " width:" << yuvPhotoProfile_.GetSize().width << " height:" << yuvPhotoProfile_.GetSize().height
              << std::endl;
    for (Profile &profile : previewProfile_) {
        float ratio1 = static_cast<float>(yuvPhotoProfile_.GetSize().width) / yuvPhotoProfile_.GetSize().height;
        float ratio2 = static_cast<float>(profile.GetSize().width) / profile.GetSize().height;
        std::cout << "ratio1:" << ratio1 << " ratio2:" << ratio2 << std::endl;
        if (profile.GetCameraFormat() == CAMERA_FORMAT_YUV_420_SP && ratio1 == ratio2) {
            yuvProfile = profile;
            std::cout << "get profle:" << profile.GetCameraFormat() << " width:" << profile.GetSize().width
                      << " height:" << profile.GetSize().height << std::endl;
            break;
        } else {
            std::cout << "skip profle:" << profile.GetCameraFormat() << " width:" << profile.GetSize().width
                      << " height:" << profile.GetSize().height << std::endl;
        }
    }

    int32_t retCode = CreatePreviewOutput(yuvProfile, previewOutput_);
    CHECK_RETURN_RET_ELOG((retCode != CameraErrorCode::SUCCESS || previewOutput_ == nullptr),
        SERVICE_FATL_ERROR,
        "Create preview output failed");

    return SUCCESS;
}

TestPreviewConsumer::TestPreviewConsumer(wptr<Surface> surface) : surface_(surface)
{
    MEDIA_INFO_LOG("TestPreviewConsumer new E");
}

TestPreviewConsumer::~TestPreviewConsumer()
{
    MEDIA_INFO_LOG("TestPreviewConsumer ~ E");
}

void TestPreviewConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("TestPreviewConsumer OnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<Surface> surface = surface_.promote();
    CHECK_RETURN_ELOG(surface == nullptr, "surface is null");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = surface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire surface buffer");
    surfaceRet = surface_->ReleaseBuffer(surfaceBuffer, -1);
    MEDIA_INFO_LOG("TestPreviewConsumer OnBufferAvailable X");
}

/*
 * Feature: Framework
 * Function: Test is band width compression
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test is band width compression
 */
HWTEST_F(CameraPreviewModuleTest, camera_preview_moduletest_001, TestSize.Level0)
{
    EXPECT_EQ(CreatePreviewOutput(previewProfile_[0], previewOutput_), SUCCESS);
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    bool isSupport = previewOutput_->IsBandwidthCompressionSupported();
    int32_t res = -1; 
    if (isSupport) {
        res = previewOutput_->EnableBandwidthCompression(true);
        EXPECT_EQ(res, SUCCESS);
    }
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);
    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(session_->Stop(), SUCCESS);
}
}  // namespace CameraStandard
}  // namespace OHOS