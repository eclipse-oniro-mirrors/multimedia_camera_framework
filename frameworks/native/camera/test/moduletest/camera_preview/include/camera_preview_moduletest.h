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

#ifndef CAMERA_PREVIEW_MODULETEST_H
#define CAMERA_PREVIEW_MODULETEST_H

#include <vector>

#include "gtest/gtest.h"
#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {
const int32_t WAIT_TIME_AFTER_START = 1;

class CameraPreviewModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    void NativeAuthorization();

protected:
    void UpdateCameraOutputCapability(int32_t modeName = 0);
    int32_t CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput);
    int32_t CreateYuvPreviewOutput();

    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;

    sptr<CameraInput> input_;
    std::vector<sptr<CameraDevice>> cameras_;
    sptr<CameraManager> manager_;
    sptr<CaptureSession> session_;

    sptr<PreviewOutput> previewOutput_;
    std::vector<Profile> previewProfile_ = {};
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

#endif // CAMERA_PREVIEW_MODULETEST_H