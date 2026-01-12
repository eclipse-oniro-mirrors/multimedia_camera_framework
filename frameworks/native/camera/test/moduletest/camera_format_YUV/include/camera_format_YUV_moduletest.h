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

#ifndef CAMERA_FORMAT_YUV_MODULETEST_H
#define CAMERA_FORMAT_YUV_MODULETEST_H

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <memory>
#include <vector>
#include <thread>

#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#ifdef CAMERA_CAPTURE_YUV
#include "photo_output_callback.h"
#endif

namespace OHOS {
namespace CameraStandard {

const int32_t WAIT_TIME_AFTER_CAPTURE = 1;
const int32_t WAIT_TIME_AFTER_START = 2;
#ifdef CAMERA_CAPTURE_YUV
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
    void OnPhotoAvailable(const std::shared_ptr<Media::Picture> picture) const override;
    void OnPhotoAssetAvailable(const int32_t captureId, const std::string &uri, const int32_t cameraShotType,
        const std::string &burstKey) const override;
    void OnThumbnailAvailable(
        int32_t captureId, int64_t timestamp, std::unique_ptr<Media::PixelMap> pixelMap) const override;
};
#endif

class AppAbilityCallback : public AbilityCallback {
public:
    void OnAbilityChange() override {}
};

class AppSessionCallback : public SessionCallback {
public:
    void OnError(int32_t errorCode)
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
        return;
    }
};

class CameraformatYUVModuleTest : public testing::Test {
public:
    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<CameraManager> cameraManager_ = nullptr;
    sptr<CaptureInput> input_;
    sptr<CaptureOutput> preview_;
    sptr<CaptureSession> session_;
    std::vector<sptr<CameraDevice>> cameras_;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUpInit();
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    void UpdateCameraOutputCapability(int32_t modeName = 0);

    void UpdateCameraOutputCapabilitySrc(int32_t modeName = 0);

protected:
    std::vector<Profile> previewProfile_ = {};
    std::vector<Profile> photoProfile_ = {};
#ifdef CAMERA_CAPTURE_YUV
    sptr<PreviewOutput> previewOutput_;
    sptr<PhotoOutput> photoOutput_;
    Profile yuvPhotoProfile_;
    sptr<IBufferConsumerListener> previewListener_ = nullptr;
    sptr<Surface> previewSurface_ = nullptr;
    uint8_t callbackFlag_ = 0;
    void UpdateCameraFullOutputCapability(int32_t modeName = 0);
    void CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput);
    void CreateYuvPhotoOutput();
#endif
};

#ifdef CAMERA_CAPTURE_YUV
class TestPreviewConsumer : public IBufferConsumerListener {
public:
    TestPreviewConsumer(wptr<Surface> surface);
    ~TestPreviewConsumer() override;

    void OnBufferAvailable() override;
private:
    wptr<Surface> surface_ = nullptr;
};
#endif
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_FORMAT_YUV_MODULETEST_H