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

#ifndef CAMERA_PHOTO_MODULETEST_H
#define CAMERA_PHOTO_MODULETEST_H

#include <vector>

#include "gtest/gtest.h"
#include "input/camera_manager.h"
#include "native_image.h"
#include "photo_output_callback.h"

namespace OHOS {
namespace CameraStandard {
const int32_t WAIT_TIME_AFTER_CAPTURE = 5;
const int32_t WAIT_TIME_AFTER_START = 1;
const int32_t WAIT_TIME_CALLBACK = 2;
bool photoFlag_ = false;
bool photoAssetFlag_ = false;
bool thumbnailFlag_ = false;

class TestCaptureCallback : public PhotoAvailableCallback,
                            public PhotoAssetAvailableCallback,
                            public ThumbnailCallback {
public:
    TestCaptureCallback() = default;
    ~TestCaptureCallback() = default;

    void OnPhotoAvailable(
        const std::shared_ptr<Media::NativeImage> nativeImage, const bool isRaw = false) const override;
    void OnPhotoAssetAvailable(const int32_t captureId, const std::string &uri, const int32_t cameraShotType,
        const std::string &burstKey) const override;
    void OnThumbnailAvailable(const WatermarkInfo &info, std::unique_ptr<Media::PixelMap> pixelMap) const override;

private:
};

class CameraPhotoModuleTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

protected:
    void UpdateCameraOutputCapability(int32_t modeName = 0);
    int32_t CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput);
    int32_t CreatePhotoOutputWithoutSurface(Profile &profile, sptr<PhotoOutput> &photoOutput);
    int32_t CreateYuvPhotoOutput();
    int32_t CreateYuvPreviewOutput();

    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;

    uint8_t callbackFlag_ = 0;

    sptr<CameraInput> input_;
    std::vector<sptr<CameraDevice>> cameras_;
    sptr<CameraManager> manager_;
    sptr<CaptureSession> session_;

    sptr<PreviewOutput> previewOutput_;
    sptr<PhotoOutput> photoOutput_;
    std::vector<Profile> previewProfile_ = {};
    std::vector<Profile> photoProfile_ = {};
    Profile yuvPhotoProfile_;
    sptr<IBufferConsumerListener> previewListener_ = nullptr;
    sptr<Surface> previewSurface_ = nullptr;
};

class TestPreviewConsumer : public IBufferConsumerListener {
public:
    TestPreviewConsumer(wptr<Surface> surface);
    ~TestPreviewConsumer() override;

    void OnBufferAvailable() override;
private:
    wptr<Surface> surface_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PHOTO_MODULETEST_H