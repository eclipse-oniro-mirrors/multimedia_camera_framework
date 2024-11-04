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
#include "session/slow_motion_session.h"
#include "hcamera_service_callback_proxy.h"
#include "hstream_repeat_proxy.h"
#include "hstream_capture_callback_proxy.h"
#include "hstream_repeat_callback_proxy.h"
#include "hcapture_session_callback_proxy.h"

#include "accesstoken_kit.h"
#include "aperture_video_session.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "hcamera_device.h"
#include "hcamera_device_callback_proxy.h"
#include "hcamera_device_proxy.h"
#include "hcamera_service.h"
#include "hcamera_service_stub.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "light_painting_session.h"
#include "nativetoken_kit.h"
#include "night_session.h"
#include "parameter.h"
#include "quick_shot_photo_session.h"
#include "scan_session.h"
#include "session/panorama_session.h"
#include "session/photo_session.h"
#include "session/profession_session.h"
#include "session/photo_session.h"
#include "session/video_session.h"
#include "session/portrait_session.h"
#include "session/secure_camera_session.h"
#include "session/time_lapse_photo_session.h"
#include "session/slow_motion_session.h"
#include "surface.h"
#include "system_ability_definition.h"
#include "test_common.h"
#include "token_setproc.h"
#include "video_session.h"

namespace OHOS {
namespace CameraStandard {
typedef struct {
    Profile preview;
    Profile photo;
    VideoProfile video;
} SelectProfiles;

enum class CAM_PHOTO_EVENTS {
    CAM_PHOTO_CAPTURE_START = 0,
    CAM_PHOTO_CAPTURE_END,
    CAM_PHOTO_CAPTURE_ERR,
    CAM_PHOTO_FRAME_SHUTTER,
    CAM_PHOTO_MAX_EVENT,
    CAM_PHOTO_FRAME_SHUTTER_END,
    CAM_PHOTO_CAPTURE_READY,
    CAM_PHOTO_ESTIMATED_CAPTURE_DURATION
};

enum class CAM_PREVIEW_EVENTS {
    CAM_PREVIEW_FRAME_START = 0,
    CAM_PREVIEW_FRAME_END,
    CAM_PREVIEW_FRAME_ERR,
    CAM_PREVIEW_SKETCH_STATUS_CHANGED,
    CAM_PREVIEW_MAX_EVENT
};

enum class CAM_VIDEO_EVENTS {
    CAM_VIDEO_FRAME_START = 0,
    CAM_VIDEO_FRAME_END,
    CAM_VIDEO_FRAME_ERR,
    CAM_VIDEO_MAX_EVENT
};

enum class CAM_MACRO_DETECT_EVENTS {
    CAM_MACRO_EVENT_IDLE = 0,
    CAM_MACRO_EVENT_ACTIVE,
    CAM_MACRO_EVENT_MAX_EVENT
};

enum class CAM_MOON_CAPTURE_BOOST_EVENTS {
    CAM_MOON_CAPTURE_BOOST_EVENT_IDLE = 0,
    CAM_MOON_CAPTURE_BOOST_EVENT_ACTIVE,
    CAM_MOON_CAPTURE_BOOST_EVENT_MAX_EVENT
};

const int32_t WAIT_TIME_AFTER_CAPTURE = 1;
const int32_t WAIT_TIME_AFTER_DEFERRED_CAPTURE = 2;
const int32_t WAIT_TIME_AFTER_RECORDING = 3;
const int32_t WAIT_TIME_AFTER_START = 2;
const int32_t WAIT_TIME_BEFORE_STOP = 1;
const int32_t WAIT_TIME_AFTER_CLOSE = 1;
const int32_t WAIT_TIME_CALLBACK = 1;
const int32_t CAMERA_NUMBER = 2;
const int32_t MIN_FRAME_RATE = 15;
const int32_t MAX_FRAME_RATE = 30;
const int32_t SKETCH_PREVIEW_MIN_HEIGHT = 720;
const int32_t SKETCH_PREVIEW_MAX_WIDTH = 3000;
const int32_t SKETCH_DEFAULT_WIDTH = 640;
const int32_t SKETCH_DEFAULT_HEIGHT = 480;
const int32_t PRVIEW_WIDTH_176 = 176;
const int32_t PRVIEW_HEIGHT_144 = 144;
const int32_t PRVIEW_WIDTH_640 = 640;
const int32_t PRVIEW_WIDTH_4096 = 4096;
const int32_t PRVIEW_HEIGHT_3072 = 3072;
const int32_t PRVIEW_WIDTH_4160 = 4160;
const int32_t PRVIEW_HEIGHT_3120 = 3120;
const int32_t PRVIEW_WIDTH_8192 = 8192;
const int32_t PRVIEW_HEIGHT_6144 = 6144;

extern bool g_camInputOnError;
extern bool g_sessionclosed;
extern bool g_brightnessStatusChanged;
extern bool g_slowMotionStatusChanged;
extern std::shared_ptr<OHOS::Camera::CameraMetadata> g_metaResult;
extern int32_t g_videoFd;
extern int32_t g_previewFd;
extern int32_t g_sketchFd;
extern std::bitset<static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_MAX_EVENT)> g_photoEvents;
extern std::bitset<static_cast<unsigned int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_MAX_EVENT)> g_previewEvents;
extern std::bitset<static_cast<unsigned int>(CAM_VIDEO_EVENTS::CAM_VIDEO_MAX_EVENT)> g_videoEvents;
extern std::bitset<static_cast<unsigned int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_MAX_EVENT)> g_macroEvents;
extern std::bitset<static_cast<unsigned int>(CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_MAX_EVENT)>
    g_moonCaptureBoostEvents;
extern std::list<int32_t> g_sketchStatus;
extern std::unordered_map<std::string, int> g_camStatusMap;
extern std::unordered_map<std::string, bool> g_camFlashMap;
extern TorchStatusInfo g_torchInfo;

class AppCallback : public CameraManagerCallback,
                    public TorchListener,
                    public ErrorCallback,
                    public PhotoStateCallback,
                    public PreviewStateCallback,
                    public ResultCallback,
                    public SlowMotionStateCallback,
                    public MacroStatusCallback,
                    public FeatureDetectionStatusCallback,
                    public FoldListener,
                    public LcdFlashStatusCallback,
                    public BrightnessStatusCallback {
public:
    void OnCameraStatusChanged(const CameraStatusInfo& cameraDeviceInfo) const override;

    void OnFlashlightStatusChanged(const std::string& cameraID, const FlashStatus flashStatus) const override;

    void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const override;

    void OnError(const int32_t errorType, const int32_t errorMsg) const override;

    void OnResult(const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) const override;

    void OnCaptureStarted(const int32_t captureId) const override;

    void OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const override;

    void OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const override;

    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override;

    void OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const override;

    void OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const override;

    void OnEstimatedCaptureDuration(const int32_t duration) const override;

    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override;

    void OnFrameStarted() const override;

    void OnFrameEnded(const int32_t frameCount) const override;

    void OnError(const int32_t errorCode) const override;

    void OnSketchStatusDataChanged(const SketchStatusData& statusData) const override;

    void OnMacroStatusChanged(MacroStatus status) override;

    void OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status) override;

    bool IsFeatureSubscribed(SceneFeature feature) override;

    void OnBrightnessStatusChanged(bool state) override;

    void OnSlowMotionState(const SlowMotionState state) override;

    void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const override;

    void OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo) override;
};

class AppVideoCallback : public VideoStateCallback {
public:
    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const override;
};

class AppMetadataCallback : public MetadataObjectCallback, public MetadataStateCallback {
public:
    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const;

    void OnError(int32_t errorCode) const;
};

class AppSessionCallback : public SessionCallback {
public:
    void OnError(int32_t errorCode);
};

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
    sptr<SlowMotionSession> slowMotionSession_;
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
                                          camera_rational_t ratio, CameraFormat format);
    SelectProfiles SelectWantedProfiles(sptr<CameraOutputCapability>& modeAbility, const SelectProfiles wanted);
    void ConfigScanSession(sptr<CaptureOutput> &previewOutput_1, sptr<CaptureOutput> &previewOutput_2);
    void ConfigHighResSession(sptr<CaptureOutput> &previewOutput_1, sptr<CaptureOutput> &previewOutput_2);
    void ConfigSlowMotionSession(sptr<CaptureOutput> &previewOutput, sptr<CaptureOutput> &videoOutput);
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
    static void SetNativeToken();
    void SetHapToken();
    void ProcessPreviewProfiles(sptr<CameraOutputCapability>& outputcapability);
    void ProcessSize();
    void ProcessPortraitSession(sptr<PortraitSession>& portraitSession, sptr<CaptureOutput>& previewOutput);
    sptr<CameraDevice> ChooseCamerasByPositionAndType(CameraPosition, CameraType);
};
} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_MODULETEST_H
