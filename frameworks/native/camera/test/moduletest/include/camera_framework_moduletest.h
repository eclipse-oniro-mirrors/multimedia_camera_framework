/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_FRAMEWORK_MODULETEST_H
#define CAMERA_FRAMEWORK_MODULETEST_H

#include "gtest/gtest.h"
#include "input/camera_device.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "session/capture_session.h"
#include "session/portrait_session.h"
#include "hcamera_service_callback_proxy.h"
#include "hstream_repeat_proxy.h"
#include "hstream_capture_callback_proxy.h"
#include "hstream_repeat_callback_proxy.h"
#include "hcapture_session_callback_proxy.h"

namespace OHOS {
namespace CameraStandard {
typedef struct {
    Profile preview;
    Profile photo;
    VideoProfile video;
} SelectProfiles;

class CameraFrameworkModuleTest : public testing::Test {
public:
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    static const int32_t VIDEO_DEFAULT_WIDTH = 640;
    static const int32_t VIDEO_DEFAULT_HEIGHT = 360;
    CameraFormat previewFormat_;
    CameraFormat photoFormat_;
    CameraFormat videoFormat_;
    int32_t previewWidth_;
    int32_t previewHeight_;
    int32_t photoWidth_;
    int32_t photoHeight_;
    int32_t videoWidth_;
    int32_t videoHeight_;
    sptr<CameraManager> manager_;
    sptr<PortraitSession> portraitSession_;
    sptr<CaptureSession> session_;
    sptr<CaptureSession> scanSession_;
    sptr<CaptureSession> highResSession_;
    sptr<CaptureSession> videoSession_;
    sptr<CaptureInput> input_;
    std::vector<sptr<CameraDevice>> cameras_;
    std::vector<CameraFormat> previewFormats_;
    std::vector<CameraFormat> photoFormats_;
    std::vector<CameraFormat> videoFormats_;
    std::vector<Size> previewSizes_;
    std::vector<Size> photoSizes_;
    std::vector<Size> videoSizes_;
    std::vector<int32_t> videoFrameRates_;

    std::vector<Profile> previewProfiles;
    std::vector<Profile> photoProfiles;
    std::vector<VideoProfile> videoProfiles;
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUpInit();
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    sptr<CaptureOutput> CreatePreviewOutput(Profile& profile);
    sptr<CaptureOutput> CreatePreviewOutput(int32_t width, int32_t height);
    sptr<CaptureOutput> CreatePreviewOutput();
    sptr<Surface> CreateSketchSurface(CameraFormat cameraFormat);
    sptr<CaptureOutput> CreatePhotoOutput(int32_t width, int32_t height);
    sptr<CaptureOutput> CreatePhotoOutput();
    sptr<CaptureOutput> CreateVideoOutput(int32_t width, int32_t height);
    sptr<CaptureOutput> CreateVideoOutput();
    sptr<CaptureOutput> CreateVideoOutput(VideoProfile& profile);
    sptr<CaptureOutput> CreatePhotoOutput(Profile profile);
    void GetSupportedOutputCapability();
    Profile SelectProfileByRatioAndFormat(sptr<CameraOutputCapability>& modeAbility,
                                          float ratio, CameraFormat format);
    SelectProfiles SelectWantedProfiles(sptr<CameraOutputCapability>& modeAbility, const SelectProfiles wanted);
    void ConfigScanSession(sptr<CaptureOutput> &previewOutput_1, sptr<CaptureOutput> &previewOutput_2);
    void ConfigHighResSession(sptr<CaptureOutput> &previewOutput_1, sptr<CaptureOutput> &previewOutput_2);
    void CreateHighResPhotoOutput(sptr<CaptureOutput> &previewOutput, sptr<CaptureOutput> &photoOutput,
                                  Profile previewProfile, Profile photoProfile);
    void ConfigVideoSession(sptr<CaptureOutput> &previewOutput, sptr<CaptureOutput> &videoOutput);
    void ReleaseInput();

    void SetCameraParameters(sptr<CaptureSession> &session, bool video);
    void TestCallbacksSession(sptr<CaptureOutput> photoOutput,
		    sptr<CaptureOutput> videoOutput);
    void TestCallbacks(sptr<CameraDevice> &cameraInfo, bool video);
    void TestSupportedResolution(int32_t previewWidth, int32_t previewHeight, int32_t photoWidth,
                                 int32_t photoHeight, int32_t videoWidth, int32_t videoHeight);
    void TestUnSupportedResolution(int32_t previewWidth, int32_t previewHeight, int32_t photoWidth,
                                   int32_t photoHeight, int32_t videoWidth, int32_t videoHeight);
    bool IsSupportNow();
    bool IsSupportMode(SceneMode mode);

    std::shared_ptr<Profile> GetSketchPreviewProfile();

private:
    void RegisterErrorCallback();
    void SetNativeToken();
    void ProcessPreviewProfiles(sptr<CameraOutputCapability>& outputcapability);
    void ProcessSize();
    void ProcessPortraitSession(sptr<PortraitSession>& portraitSession, sptr<CaptureOutput>& previewOutput);
};
} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_MODULETEST_H
