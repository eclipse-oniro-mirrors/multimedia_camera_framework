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

#ifndef CAMERA_BASE_FUNCTION_MODULETEST_H
#define CAMERA_BASE_FUNCTION_MODULETEST_H

#include <vector>

#include "gtest/gtest.h"
#include "input/camera_manager.h"
#include "input/camera_manager_for_sys.h"
#include "photo_output_callback.h"
#include "session/capture_session.h"
#include "session/capture_session_for_sys.h"

namespace OHOS {
namespace CameraStandard {
// camera manager
class TestCameraMuteListener : public CameraMuteListener {
public:
    TestCameraMuteListener() = default;
    virtual ~TestCameraMuteListener() = default;
    void OnCameraMute(bool muteMode) const override;
};
class TestTorchListener : public TorchListener {
public:
    TestTorchListener() = default;
    virtual ~TestTorchListener() = default;
    void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const override;
};
class TestFoldListener : public FoldListener {
public:
    TestFoldListener() = default;
    virtual ~TestFoldListener() = default;
    void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const override;
};
// capture session
class TestSessionCallback : public SessionCallback {
public:
    TestSessionCallback() = default;
    virtual ~TestSessionCallback() = default;
    void OnError(int32_t errorCode) override;
};
class TestExposureCallback : public ExposureCallback {
public:
    TestExposureCallback() = default;
    virtual ~TestExposureCallback() = default;
    void OnExposureState(ExposureState state) override;
};
class TestFocusCallback : public FocusCallback {
public:
    TestFocusCallback() = default;
    virtual ~TestFocusCallback() = default;
    void OnFocusState(FocusState state) override;
};
class TestMacroStatusCallback : public MacroStatusCallback {
public:
    TestMacroStatusCallback() = default;
    virtual ~TestMacroStatusCallback() = default;
    void OnMacroStatusChanged(MacroStatus status) override;
};
class TestMoonCaptureBoostStatusCallback : public MoonCaptureBoostStatusCallback {
public:
    TestMoonCaptureBoostStatusCallback() = default;
    virtual ~TestMoonCaptureBoostStatusCallback() = default;
    void OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status) override;
};
class TestFeatureDetectionStatusCallback : public FeatureDetectionStatusCallback {
public:
    TestFeatureDetectionStatusCallback() = default;
    virtual ~TestFeatureDetectionStatusCallback() = default;
    void OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status) override;
    bool IsFeatureSubscribed(SceneFeature feature) override;
};
class TestSmoothZoomCallback : public SmoothZoomCallback {
public:
    TestSmoothZoomCallback() = default;
    virtual ~TestSmoothZoomCallback() = default;
    void OnSmoothZoom(int32_t duration) override;
};
class TestARCallback : public ARCallback {
public:
    TestARCallback() = default;
    virtual ~TestARCallback() = default;
    void OnResult(const ARStatusInfo &arStatusInfo) const override;
};
class TestEffectSuggestionCallback : public EffectSuggestionCallback {
public:
    TestEffectSuggestionCallback() = default;
    virtual ~TestEffectSuggestionCallback() = default;
    void OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType) override;
};
class TestLcdFlashStatusCallback : public LcdFlashStatusCallback {
public:
    TestLcdFlashStatusCallback() = default;
    virtual ~TestLcdFlashStatusCallback() = default;
    void OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo) override;
};
class TestAutoDeviceSwitchCallback : public AutoDeviceSwitchCallback {
public:
    TestAutoDeviceSwitchCallback() = default;
    virtual ~TestAutoDeviceSwitchCallback() = default;
    void OnAutoDeviceSwitchStatusChange(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const override;
};
class TestMetadataStateCallback : public MetadataStateCallback {
public:
    TestMetadataStateCallback() = default;
    virtual ~TestMetadataStateCallback() = default;
    void OnError(int32_t errorCode) const override;
};

class TestThumbnailCallback : public ThumbnailCallback {
public:
    TestThumbnailCallback() = default;
    virtual ~TestThumbnailCallback() = default;
    void OnThumbnailAvailable(
        const int32_t captureId, const int64_t timestamp, unique_ptr<Media::PixelMap> pixelMap) const override;
};

// ms
static const int32_t DURATION_AFTER_SESSION_START = 200;
static const int32_t DURATION_BEFORE_SESSION_STOP = 200;
static const int32_t DURATION_AFTER_CAPTURE = 200;
static const int32_t DURATION_DURING_RECORDING = 500;
static const int32_t DURATION_AFTER_RECORDING = 200;
static const int32_t DURATION_AFTER_DEVICE_CLOSE = 200;
static const int32_t DURATION_WAIT_CALLBACK = 200;

static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
static const int32_t PREVIEW_DEFAULT_WIDTH = 1280;
static const int32_t PREVIEW_DEFAULT_HEIGHT = 720;
static const int32_t VIDEO_DEFAULT_WIDTH = 1280;
static const int32_t VIDEO_DEFAULT_HEIGHT = 720;

static const int32_t PRVIEW_WIDTH_176 = 176;
static const int32_t PRVIEW_HEIGHT_144 = 144;
static const int32_t PRVIEW_WIDTH_480 = 480;
static const int32_t PRVIEW_HEIGHT_480 = 480;
static const int32_t PRVIEW_WIDTH_640 = 640;
static const int32_t PRVIEW_HEIGHT_640 = 640;
static const int32_t PRVIEW_WIDTH_4096 = 4096;
static const int32_t PRVIEW_HEIGHT_3072 = 3072;
static const int32_t PRVIEW_WIDTH_4160 = 4160;
static const int32_t PRVIEW_HEIGHT_3120 = 3120;
static const int32_t PRVIEW_WIDTH_8192 = 8192;
static const int32_t PRVIEW_HEIGHT_6144 = 6144;

class CameraBaseFunctionModuleTest : public testing::Test {
public:
    static const int32_t deviceBackIndex = 0;
    static const int32_t deviceFrontIndex = 1;

    /* SetUpTestCase: The preset action of the test suite is executed before the first test case */
    static void SetUpTestCase(void);

    /* TearDownTestCase: The cleanup action of the test suite is executed after the last test case */
    static void TearDownTestCase(void);

    /* SetUp: Execute before each test case */
    void SetUp();

    /* TearDown: Execute after each test case */
    void TearDown();

    void UpdateCameraOutputCapability(int32_t index = 0, int32_t modeName = 0);
    void UpdateCameraOutputCapabilityForSys(int32_t index = 0, int32_t modeName = 0);
    void FilterPreviewProfiles(std::vector<Profile>& previewProfiles);

    sptr<PreviewOutput> CreatePreviewOutput(Profile &previewProfile);
    sptr<PhotoOutput> CreatePhotoOutput(Profile &photoProfile);
    sptr<VideoOutput> CreateVideoOutput(VideoProfile &videoProfile);

    void CreateAndConfigureDefaultCaptureOutput(sptr<PhotoOutput> &photoOutput, sptr<VideoOutput> &videoOutput);
    void CreateAndConfigureDefaultCaptureOutputForSys(sptr<PhotoOutput> &photoOutput, sptr<VideoOutput> &videoOutput);
    void CreateAndConfigureDefaultCaptureOutput(sptr<PhotoOutput> &photoOutput);
    void StartDefaultCaptureOutput(sptr<PhotoOutput> photoOutput, sptr<VideoOutput> videoOutput);
    void StartDefaultCaptureOutputForSys(sptr<PhotoOutput> photoOutput, sptr<VideoOutput> videoOutput);
    void StartDefaultCaptureOutput(sptr<PhotoOutput> photoOutput);

    void CreateNormalSession();
    void CreateSystemSession();

protected:
    int32_t previewFd_ = -1;
    int32_t videoFd_ = -1;
    int32_t sketchFd_ = -1;

    sptr<CameraInput> cameraInput_ = nullptr;
    sptr<CameraManager> cameraManager_ = nullptr;
    sptr<CameraManagerForSys> cameraManagerForSys_ = nullptr;
    sptr<CaptureSession> captureSession_ = nullptr;
    sptr<CaptureSessionForSys> captureSessionForSys_ = nullptr;
    std::vector<sptr<CameraDevice>> cameraDevices_ = {};

    std::vector<Profile> photoProfiles_ = {};
    std::vector<Profile> previewProfiles_ = {};
    std::vector<VideoProfile> videoProfiles_ = {};
    std::vector<Profile> photoProfilesForSys_ = {};
    std::vector<Profile> previewProfilesForSys_ = {};
    std::vector<VideoProfile> videoProfilesForSys_ = {};
    std::vector<DepthProfile> depthProfiles_ = {};
    std::vector<MetadataObjectType> metadataObjectTypes_ = {};
};
} // CameraStandard
} // OHOS
#endif // CAMERA_BASE_FUNCTION_MODULETEST_H