/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include "composition_feature_unittest.h"
#include "camera_error_code.h"
#include "capture_session.h"
#include "camera_metadata.h"
#include "surface_buffer.h"
#include "pixel_map.h"
#include "test_token.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
static constexpr CameraFormat PREVIEW_FORMAT = CAMERA_FORMAT_YUV_420_SP;
static constexpr Size PREVIEW_SIZE { .width = 1920, .height = 1440 };
void CompositionFeatureUnitTest::SetUpTestCase() {}

void CompositionFeatureUnitTest::TearDownTestCase() {}

void CompositionFeatureUnitTest::SetUp()
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
    auto cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    auto camDevice = cameras.front();
    auto camInput = cameraManager->CreateCameraInput(camDevice);
    ASSERT_NE(camInput, nullptr);
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    captureSession_ = cameraManager->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(captureSession_, nullptr);

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
    auto previewOutput = cameraManager->CreatePreviewOutput(previewProfile, previewSurface);
    ASSERT_NE(previewOutput, nullptr);

    int32_t intResult = captureSession_->BeginConfig();
    ASSERT_EQ(intResult, 0);

    intResult = captureSession_->AddInput((sptr<CaptureInput>&)camInput);
    ASSERT_EQ(intResult, 0);

    intResult = captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput);
    ASSERT_EQ(intResult, 0);

    intResult = captureSession_->CommitConfig();
    ASSERT_EQ(intResult, 0);
    captureSession_->Start();
    if (!captureSession_->IsCompositionSuggestionSupported()) {
        GTEST_SKIP();
    }
    intResult = captureSession_->EnableCompositionSuggestion(true);
    ASSERT_EQ(intResult, 0);
    bool isSupported = false;
    captureSession_->IsCompositionEffectPreviewSupported(isSupported);
    if (!isSupported) {
        GTEST_SKIP();
    }
}

void CompositionFeatureUnitTest::TearDown()
{
    if (captureSession_) {
        captureSession_->Stop();
        captureSession_->Release();
    }
}

/**
 * @tc.name  : Test IsCompositionEffectPreviewSupported API
 * @tc.number: IsCompositionEffectPreviewSupported_001
 * @tc.desc  : Test IsCompositionEffectPreviewSupported API
 */
HWTEST_F(CompositionFeatureUnitTest, IsCompositionEffectPreviewSupported_001, TestSize.Level0)
{
    bool isSupported = false;
    int32_t ret = captureSession_->IsCompositionEffectPreviewSupported(isSupported);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/**
 * @tc.name  : Test EnableCompositionEffectPreview API
 * @tc.number: EnableCompositionEffectPreview_001
 * @tc.desc  : Test EnableCompositionEffectPreview API
 */
HWTEST_F(CompositionFeatureUnitTest, EnableCompositionEffectPreview_001, TestSize.Level0)
{
    bool isSupported = false;
    int32_t ret = captureSession_->IsCompositionEffectPreviewSupported(isSupported);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    ret = captureSession_->EnableCompositionEffectPreview(true);
    EXPECT_EQ(ret, isSupported ? CameraErrorCode::SUCCESS : CameraErrorCode::OPERATION_NOT_ALLOWED);
    ret = captureSession_->EnableCompositionEffectPreview(false);
    EXPECT_EQ(ret, isSupported ? CameraErrorCode::SUCCESS : CameraErrorCode::OPERATION_NOT_ALLOWED);
}

/**
 * @tc.name  : Test GetSupportedRecommendedInfoLanguage API
 * @tc.number: GetSupportedRecommendedInfoLanguage_001
 * @tc.desc  : Test GetSupportedRecommendedInfoLanguage API
 */
HWTEST_F(CompositionFeatureUnitTest, GetSupportedRecommendedInfoLanguage_001, TestSize.Level0)
{
    std::vector<std::string> supportedLanguages;
    int32_t ret = captureSession_->GetSupportedRecommendedInfoLanguage(supportedLanguages);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/**
 * @tc.name  : Test SetRecommendedInfoLanguage API
 * @tc.number: SetRecommendedInfoLanguage_001
 * @tc.desc  : Test SetRecommendedInfoLanguage API, when input is valid
 */
HWTEST_F(CompositionFeatureUnitTest, SetRecommendedInfoLanguage_001, TestSize.Level0)
{
    std::vector<std::string> supportedLanguages;
    int32_t ret = captureSession_->GetSupportedRecommendedInfoLanguage(supportedLanguages);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    if (supportedLanguages.empty()) {
        GTEST_SKIP();
    }
    for (auto& language : supportedLanguages) {
        ret = captureSession_->SetRecommendedInfoLanguage(language);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    }
}

/**
 * @tc.name  : Test SetRecommendedInfoLanguage API
 * @tc.number: SetRecommendedInfoLanguage_002
 * @tc.desc  : Test SetRecommendedInfoLanguage API, when input is invalid
 */
HWTEST_F(CompositionFeatureUnitTest, SetRecommendedInfoLanguage_002, TestSize.Level1)
{
    std::vector<std::string> supportedLanguages;
    int32_t ret = captureSession_->GetSupportedRecommendedInfoLanguage(supportedLanguages);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    const std::string INVALID_LANGUAGE = "INVALID_LANG";
    ASSERT_TRUE(
        std::find(supportedLanguages.begin(), supportedLanguages.end(), INVALID_LANGUAGE) == supportedLanguages.end());

    ret = captureSession_->SetRecommendedInfoLanguage(INVALID_LANGUAGE);
    EXPECT_EQ(ret, CameraErrorCode::OPERATION_NOT_ALLOWED);
}

/**
 * @tc.name  : Test SetCompositionEffectReceiveCallback API
 * @tc.number: SetCompositionEffectReceiveCallback_001
 * @tc.desc  : Test SetCompositionEffectReceiveCallback API, when callback is valid
 */
HWTEST_F(CompositionFeatureUnitTest, SetCompositionEffectReceiveCallback_001, TestSize.Level0)
{
    auto callback = std::make_shared<MockCompositionEffectInfoCallback>();
    ASSERT_NE(callback, nullptr);
    int32_t ret = captureSession_->SetCompositionEffectReceiveCallback(callback);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    EXPECT_EQ(compositionFeat->compositionEffectReceiveCallback_, callback);
    CompositionEffectInfo info;
    compositionFeat->compositionEffectReceiveCallback_->OnInfoChanged(info);
    EXPECT_TRUE(callback->isCalled_);
}

/**
 * @tc.name  : Test SetCompositionEffectReceiveCallback API
 * @tc.number: SetCompositionEffectReceiveCallback_002
 * @tc.desc  : Test SetCompositionEffectReceiveCallback API, when callback is nullptr
 */
HWTEST_F(CompositionFeatureUnitTest, SetCompositionEffectReceiveCallback_002, TestSize.Level0)
{
    int32_t ret = captureSession_->SetCompositionEffectReceiveCallback(nullptr);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    EXPECT_EQ(compositionFeat->compositionEffectReceiveCallback_, nullptr);
}

/**
 * @tc.name  : Test UnSetCompositionEffectReceiveCallback API
 * @tc.number: UnSetCompositionEffectReceiveCallback_001
 * @tc.desc  : Test UnSetCompositionEffectReceiveCallback API, when callback has been set
 */
HWTEST_F(CompositionFeatureUnitTest, UnSetCompositionEffectReceiveCallback_001, TestSize.Level0)
{
    auto callback = std::make_shared<MockCompositionEffectInfoCallback>();
    ASSERT_NE(callback, nullptr);
    int32_t ret = captureSession_->SetCompositionEffectReceiveCallback(callback);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    EXPECT_EQ(compositionFeat->compositionEffectReceiveCallback_, callback);
    ret = captureSession_->UnSetCompositionEffectReceiveCallback();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    EXPECT_EQ(compositionFeat->compositionEffectReceiveCallback_, nullptr);
}

/**
 * @tc.name  : Test UnSetCompositionEffectReceiveCallback API
 * @tc.number: UnSetCompositionEffectReceiveCallback_002
 * @tc.desc  : Test UnSetCompositionEffectReceiveCallback API, when callback has not been set
 */
HWTEST_F(CompositionFeatureUnitTest, UnSetCompositionEffectReceiveCallback_002, TestSize.Level1)
{
    auto ret = captureSession_->UnSetCompositionEffectReceiveCallback();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    EXPECT_EQ(compositionFeat->compositionEffectReceiveCallback_, nullptr);
}

/**
 * @tc.name  : Test StartCompositionStream/StopCompositionStream API
 * @tc.number: StartAndStopCompositionStream_001
 * @tc.desc  : Test StartCompositionStream/StopCompositionStream API
 */
HWTEST_F(CompositionFeatureUnitTest, StartAndStopCompositionStream_001, TestSize.Level0)
{
    bool isSupported = false;
    int32_t ret = captureSession_->IsCompositionEffectPreviewSupported(isSupported);
    if (!isSupported) {
        GTEST_SKIP();
    }
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    ret = compositionFeat->StartCompositionStream();
    EXPECT_EQ(ret, SUCCESS);
    ret = compositionFeat->StopCompositionStream();
    EXPECT_EQ(ret, SUCCESS);
    ret = compositionFeat->StartCompositionStream();
    EXPECT_EQ(ret, SUCCESS);
    ret = compositionFeat->StopCompositionStream();
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name  : Test CheckMode API
 * @tc.number: CheckMode_001
 * @tc.desc  : Test CheckMode API, when mode is valid
 */
HWTEST_F(CompositionFeatureUnitTest, CheckMode_001, TestSize.Level0)
{
    ASSERT_EQ(captureSession_->GetMode(), SceneMode::CAPTURE);
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    int32_t ret = compositionFeat->CheckMode();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/**
 * @tc.name  : Test CheckMode API
 * @tc.number: CheckMode_002
 * @tc.desc  : Test CheckMode API, when mode is invalid
 */
HWTEST_F(CompositionFeatureUnitTest, CheckMode_002, TestSize.Level1)
{
    captureSession_->currentMode_ = SceneMode::VIDEO;
    auto compositionFeat = captureSession_->compositionFeature_;
    ASSERT_NE(compositionFeat, nullptr);
    int32_t ret = compositionFeat->CheckMode();
    EXPECT_EQ(ret, CameraErrorCode::OPERATION_NOT_ALLOWED);
}

/**
 * @tc.name  : Test Buffer2PixelMap API
 * @tc.number: Buffer2PixelMap_001
 * @tc.desc  : Test Buffer2PixelMap API, when buffer is valid
 */
HWTEST_F(CompositionEffectListenerTest, Buffer2PixelMap_001, TestSize.Level0)
{
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = PREVIEW_SIZE.width,
        .height = PREVIEW_SIZE.height,
        .strideAlignment = 0x8,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCRCB_420_SP,
        .usage = BUFFER_USAGE_CAMERA_WRITE | BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA |
            BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError allocErrorCode = buffer->Alloc(requestConfig);
    ASSERT_EQ(allocErrorCode, GSError::GSERROR_OK);
    ASSERT_NE(buffer, nullptr);
    std::unique_ptr<Media::PixelMap> pixelMap = CompositionEffectListener::Buffer2PixelMap(buffer);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name  : Test Buffer2PixelMap API
 * @tc.number: Buffer2PixelMap_002
 * @tc.desc  : Test Buffer2PixelMap API, when buffer is nullptr
 */
HWTEST_F(CompositionEffectListenerTest, Buffer2PixelMap_002, TestSize.Level0)
{
    std::unique_ptr<Media::PixelMap> pixelMap = CompositionEffectListener::Buffer2PixelMap(nullptr);
    EXPECT_EQ(pixelMap, nullptr);
}
} // namespace CameraStandard
} // namespace OHOS