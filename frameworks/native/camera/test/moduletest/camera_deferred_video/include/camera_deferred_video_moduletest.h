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

#ifndef CAMERA_DEFERRED_VIDEO_MODULETEST_H
#define CAMERA_DEFERRED_VIDEO_MODULETEST_H

#include "gtest/gtest.h"
#include "input/camera_device.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/capture_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include "session/capture_session.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
const int32_t PRVIEW_WIDTH_176 = 176;
const int32_t PRVIEW_HEIGHT_144 = 144;
const int32_t PRVIEW_WIDTH_480 = 480;
const int32_t PRVIEW_HEIGHT_480 = 480;
const int32_t PRVIEW_WIDTH_640 = 640;
const int32_t PRVIEW_HEIGHT_640 = 640;
const int32_t PRVIEW_WIDTH_4096 = 4096;
const int32_t PRVIEW_HEIGHT_3072 = 3072;
const int32_t PRVIEW_WIDTH_4160 = 4160;
const int32_t PRVIEW_HEIGHT_3120 = 3120;
const int32_t PRVIEW_WIDTH_8192 = 8192;
const int32_t PRVIEW_HEIGHT_6144 = 6144;

class ModuleTestVideoStateCallback : public VideoStateCallback {
public:
    ModuleTestVideoStateCallback() = default;
    ~ModuleTestVideoStateCallback() = default;
    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const override;
};

class CameraDeferredVideoModuleTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    static void SetNativeToken();
    std::vector<SceneMode> GetSupportedSceneModes(sptr<CameraDevice>& camera);
    sptr<PreviewOutput> CreatePreviewOutput(Profile& profile);
    sptr<VideoOutput> CreateVideoOutput(VideoProfile& videoProfile);
    void FilterPreviewProfiles(std::vector<Profile>& previewProfiles);
    void RegisterVideoStateCallback();

    sptr<CameraManager> cameraManager_ = nullptr;
    std::vector<sptr<CameraDevice>> cameras_ = {};
    sptr<CameraOutputCapability> outputCapability_ = nullptr;
    std::vector<Profile> previewProfiles_ = {};
    std::vector<VideoProfile> videoProfiles_ = {};
    sptr<PreviewOutput> previewOutput_ = nullptr;
    sptr<VideoOutput> videoOutput_ = nullptr;
    sptr<CaptureInput> cameraInput_ = nullptr;
    sptr<CaptureSession> captureSession_ = nullptr;
    std::shared_ptr<ModuleTestVideoStateCallback> videoStateCallback_ = nullptr;
};
} // CameraStandard
} // OHOS
#endif // CAMERA_DEFERRED_VIDEO_MODULETEST_H