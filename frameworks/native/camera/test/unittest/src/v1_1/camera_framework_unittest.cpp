/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "camera_framework_unittest.h"
#include "camera_util.h"
#include "camera_log.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "surface.h"
#include "test_common.h"

#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

bool g_mockFlagWithoutAbt = false;
bool g_getCameraAbilityerror = false;
bool g_openCameraDevicerror = false;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
constexpr static int32_t ARRAY_IDX = 2;
class MockStreamOperator : public OHOS::HDI::Camera::V1_1::IStreamOperator {
public:
    MockStreamOperator()
    {
        ON_CALL(*this, CreateStreams(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CreateStreams_V1_1(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, ReleaseStreams(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CommitStreams(_, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CommitStreams_V1_1(_, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, Capture(_, _, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CancelCapture(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported(_, _, A<const std::shared_ptr<StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported(_, _, A<const std::vector<StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported_V1_1(_, _, A<const std::shared_ptr<StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported_V1_1(_, _, A<const std::vector<StreamInfo_V1_1> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, GetStreamAttributes(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, AttachBufferQueue(_, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, DetachBufferQueue(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, ChangeToOfflineStream(_, _, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
    }
    ~MockStreamOperator() {}
    MOCK_METHOD1(CreateStreams, int32_t(
        const std::vector<StreamInfo>& streamInfos));
    MOCK_METHOD1(CreateStreams_V1_1, int32_t(
        const std::vector<StreamInfo_V1_1>& streamInfos));
    MOCK_METHOD1(ReleaseStreams, int32_t(const std::vector<int32_t>& streamIds));
    MOCK_METHOD1(CancelCapture, int32_t(int32_t captureId));
    MOCK_METHOD1(GetStreamAttributes, int32_t(
        std::vector<StreamAttribute>& attributes));
    MOCK_METHOD1(DetachBufferQueue, int32_t(int32_t streamId));
    MOCK_METHOD2(CommitStreams, int32_t(OperationMode mode, const std::vector<uint8_t>& modeSetting));
    MOCK_METHOD2(CommitStreams_V1_1, int32_t(OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode,
        const std::vector<uint8_t>& modeSetting));
    MOCK_METHOD2(AttachBufferQueue, int32_t(int32_t streamId,
        const sptr<BufferProducerSequenceable>& bufferProducer));
    MOCK_METHOD3(Capture, int32_t(int32_t captureId, const CaptureInfo& info, bool isStreaming));
    MOCK_METHOD3(ChangeToOfflineStream, int32_t(const std::vector<int32_t>& streamIds,
                                            const sptr<HDI::Camera::V1_0::IStreamOperatorCallback>& callbackObj,
                                            sptr<HDI::Camera::V1_0::IOfflineStreamOperator>& offlineOperator));
    MOCK_METHOD4(IsStreamsSupported, int32_t(OperationMode mode,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &modeSetting,
        const std::shared_ptr<StreamInfo> &info, StreamSupportType &type));
    MOCK_METHOD4(IsStreamsSupported, int32_t(OperationMode mode, const std::vector<uint8_t>& modeSetting,
        const std::vector<StreamInfo>& infos, StreamSupportType& type));
    MOCK_METHOD4(IsStreamsSupported_V1_1, int32_t(OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &modeSetting,
        const std::shared_ptr<StreamInfo> &info, StreamSupportType &type));
    MOCK_METHOD4(IsStreamsSupported_V1_1, int32_t(OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode,
        const std::vector<uint8_t>& modeSetting,
        const std::vector<StreamInfo_V1_1>& infos, StreamSupportType& type));
};

class MockCameraDevice : public OHOS::HDI::Camera::V1_1::ICameraDevice {
public:
    MockCameraDevice()
    {
        streamOperator = new MockStreamOperator();
        ON_CALL(*this, GetStreamOperator_V1_1).WillByDefault([this](
            const OHOS::sptr<HDI::Camera::V1_0::IStreamOperatorCallback> &callback,
            sptr<OHOS::HDI::Camera::V1_1::IStreamOperator>& pStreamOperator) {
            pStreamOperator = streamOperator;
            return HDI::Camera::V1_0::NO_ERROR;
        });
        ON_CALL(*this, GetStreamOperator).WillByDefault([this](
            const OHOS::sptr<HDI::Camera::V1_0::IStreamOperatorCallback> &callback,
            sptr<OHOS::HDI::Camera::V1_0::IStreamOperator>& pStreamOperator) {
            pStreamOperator = streamOperator;
            return HDI::Camera::V1_0::NO_ERROR;
        });
        ON_CALL(*this, UpdateSettings(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, SetResultMode(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, GetEnabledResults(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, EnableResult(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, DisableResult(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, Open()).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, Close()).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, GetDefaultSettings(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
    }
    ~MockCameraDevice() {}
    MOCK_METHOD0(Open, int32_t());
    MOCK_METHOD0(Close, int32_t());
    MOCK_METHOD1(GetDefaultSettings, int32_t(std::vector<uint8_t> &settings));
    MOCK_METHOD1(UpdateSettings, int32_t(const std::vector<uint8_t>& settings));
    MOCK_METHOD1(SetResultMode, int32_t(ResultCallbackMode mode));
    MOCK_METHOD1(GetEnabledResults, int32_t(std::vector<int32_t>& results));
    MOCK_METHOD1(EnableResult, int32_t(const std::vector<int32_t>& results));
    MOCK_METHOD1(DisableResult, int32_t(const std::vector<int32_t>& results));
    MOCK_METHOD2(GetStreamOperator, int32_t(const sptr<HDI::Camera::V1_0::IStreamOperatorCallback>& callbackObj,
                                        sptr<OHOS::HDI::Camera::V1_0::IStreamOperator>& streamOperator));
    MOCK_METHOD2(GetStreamOperator_V1_1, int32_t(const sptr<HDI::Camera::V1_0::IStreamOperatorCallback>& callbackObj,
                                             sptr<OHOS::HDI::Camera::V1_1::IStreamOperator>& streamOperator));
    sptr<MockStreamOperator> streamOperator;
};

class MockHCameraHostManager : public HCameraHostManager {
public:
    int32_t streams[82] = {
        CameraFrameworkUnitTest::DEFAULT_MODE, CameraFrameworkUnitTest::PREVIEW_STREAM,
        OHOS_CAMERA_FORMAT_YCRCB_420_SP, CameraFrameworkUnitTest::PREVIEW_DEFAULT_WIDTH,
        CameraFrameworkUnitTest::PREVIEW_DEFAULT_HEIGHT, CameraFrameworkUnitTest::PREVIEW_FRAMERATE,
        CameraFrameworkUnitTest::MIN_FRAMERATE, CameraFrameworkUnitTest::MAX_FRAMERATE,
        CameraFrameworkUnitTest::ABILITY_FINISH, CameraFrameworkUnitTest::STREAM_FINISH,
        CameraFrameworkUnitTest::VIDEO_STREAM, OHOS_CAMERA_FORMAT_YCRCB_420_SP,
        CameraFrameworkUnitTest::VIDEO_DEFAULT_WIDTH, CameraFrameworkUnitTest::VIDEO_DEFAULT_HEIGHT,
        CameraFrameworkUnitTest::VIDEO_FRAMERATE, CameraFrameworkUnitTest::MIN_FRAMERATE,
        CameraFrameworkUnitTest::MAX_FRAMERATE, CameraFrameworkUnitTest::ABILITY_FINISH,
        CameraFrameworkUnitTest::STREAM_FINISH, CameraFrameworkUnitTest::PHOTO_STREAM,
        OHOS_CAMERA_FORMAT_JPEG, CameraFrameworkUnitTest::PHOTO_DEFAULT_WIDTH,
        CameraFrameworkUnitTest::PHOTO_DEFAULT_HEIGHT, CameraFrameworkUnitTest::PHOTO_FRAMERATE,
        CameraFrameworkUnitTest::MIN_FRAMERATE, CameraFrameworkUnitTest::MAX_FRAMERATE,
        CameraFrameworkUnitTest::ABILITY_FINISH, CameraFrameworkUnitTest::STREAM_FINISH,
        CameraFrameworkUnitTest::MODE_FINISH, CameraFrameworkUnitTest::PORTRAIT_MODE,
        CameraFrameworkUnitTest::PREVIEW_STREAM, OHOS_CAMERA_FORMAT_YCRCB_420_SP,
        CameraFrameworkUnitTest::PREVIEW_DEFAULT_WIDTH, CameraFrameworkUnitTest::PREVIEW_DEFAULT_HEIGHT,
        CameraFrameworkUnitTest::PREVIEW_FRAMERATE, CameraFrameworkUnitTest::MIN_FRAMERATE,
        CameraFrameworkUnitTest::MAX_FRAMERATE, CameraFrameworkUnitTest::ABILITY_ID_ONE,
        CameraFrameworkUnitTest::ABILITY_ID_TWO, CameraFrameworkUnitTest::ABILITY_ID_THREE,
        CameraFrameworkUnitTest::ABILITY_ID_FOUR, CameraFrameworkUnitTest::ABILITY_FINISH,
        CameraFrameworkUnitTest::STREAM_FINISH, CameraFrameworkUnitTest::VIDEO_STREAM, OHOS_CAMERA_FORMAT_YCRCB_420_SP,
        CameraFrameworkUnitTest::VIDEO_DEFAULT_WIDTH, CameraFrameworkUnitTest::VIDEO_DEFAULT_HEIGHT,
        CameraFrameworkUnitTest::VIDEO_FRAMERATE, CameraFrameworkUnitTest::MIN_FRAMERATE,
        CameraFrameworkUnitTest::MAX_FRAMERATE, CameraFrameworkUnitTest::ABILITY_ID_ONE,
        CameraFrameworkUnitTest::ABILITY_ID_TWO, CameraFrameworkUnitTest::ABILITY_ID_THREE,
        CameraFrameworkUnitTest::ABILITY_ID_FOUR, CameraFrameworkUnitTest::ABILITY_FINISH,
        CameraFrameworkUnitTest::STREAM_FINISH, CameraFrameworkUnitTest::PHOTO_STREAM,
        OHOS_CAMERA_FORMAT_JPEG, CameraFrameworkUnitTest::PHOTO_DEFAULT_WIDTH,
        CameraFrameworkUnitTest::PHOTO_DEFAULT_HEIGHT, CameraFrameworkUnitTest::PHOTO_FRAMERATE,
        CameraFrameworkUnitTest::MIN_FRAMERATE, CameraFrameworkUnitTest::MAX_FRAMERATE,
        CameraFrameworkUnitTest::ABILITY_ID_ONE, CameraFrameworkUnitTest::ABILITY_ID_TWO,
        CameraFrameworkUnitTest::ABILITY_ID_THREE, CameraFrameworkUnitTest::ABILITY_ID_FOUR,
        CameraFrameworkUnitTest::ABILITY_FINISH, CameraFrameworkUnitTest::STREAM_FINISH,
        CameraFrameworkUnitTest::MODE_FINISH
    };
    int32_t modes[2] = {0, 1};
    uint8_t filterAbility[2] = {0, 1};
    int32_t filterControl[2] = {0, 1};
    uint8_t beautyAbility[5] = {OHOS_CAMERA_BEAUTY_TYPE_OFF, OHOS_CAMERA_BEAUTY_TYPE_AUTO,
                                OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER,
                                OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE};
    uint8_t faceSlenderBeautyRange[2] = {2, 3};
    int32_t faceSlenderBeautyControl[2] = {2, 3};
    int32_t effectAbility[2] = {0, 1};
    int32_t effectControl[2] = {0, 1};
    class MockStatusCallback : public StatusCallback {
    public:
        void OnCameraStatus(const std::string& cameraId, CameraStatus status) override
        {
            MEDIA_DEBUG_LOG("MockStatusCallback::OnCameraStatus");
            return;
        }
        void OnFlashlightStatus(const std::string& cameraId, FlashStatus status) override
        {
            MEDIA_DEBUG_LOG("MockStatusCallback::OnFlashlightStatus");
            return;
        }
        void OnTorchStatus(TorchStatus status) override
        {
            MEDIA_DEBUG_LOG("MockStatusCallback::OnTorchStatus");
            return;
        }
    };

    explicit MockHCameraHostManager(std::shared_ptr<StatusCallback> statusCallback) : HCameraHostManager(statusCallback)
    {
        cameraDevice = new MockCameraDevice();
        ON_CALL(*this, GetCameras).WillByDefault([](std::vector<std::string> &cameraIds) {
            cameraIds.emplace_back("cam0");
            return CAMERA_OK;
        });
        ON_CALL(*this, GetVersionByCamera).WillByDefault([](const std::string& cameraId) {
            const uint32_t offset = 8;
            uint32_t major = 1;
            uint32_t minor = 1;
            return static_cast<int32_t>((major << offset) | minor);
        });
        ON_CALL(*this, GetCameraAbility).WillByDefault([this](std::string &cameraId,
                                                            std::shared_ptr<OHOS::Camera::CameraMetadata> &ability) {
            int32_t itemCount = 10;
            int32_t dataSize = 100;
            ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
            ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, streams,
                              sizeof(streams) / sizeof(streams[0]));

            ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams,
                              sizeof(streams) / sizeof(streams[0]));

            if (g_mockFlagWithoutAbt) {
                return CAMERA_OK;
            }
            if (g_getCameraAbilityerror) {
                g_getCameraAbilityerror = false;
                return CAMERA_ALLOC_ERROR;
            }

            int32_t compensationRange[2] = {0, 0};
            ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                              sizeof(compensationRange) / sizeof(compensationRange[0]));
            float focalLength = 1.5;
            ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, sizeof(float));

            int32_t sensorOrientation = 0;
            ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, sizeof(int32_t));

            int32_t cameraPosition = 0;
            ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));

            const camera_rational_t aeCompensationStep[] = {{0, 1}};
            ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                              sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));

            int32_t zoomCap[2] = {0, 10};
            ability->addEntry(OHOS_ABILITY_ZOOM_CAP, &zoomCap,
                              sizeof(zoomCap) / sizeof(zoomCap[0]));

            int32_t sceneZoomCap[2] = {1, 10};
            ability->addEntry(OHOS_ABILITY_SCENE_ZOOM_CAP, &sceneZoomCap,
                              sizeof(zoomCap) / sizeof(zoomCap[0]));

            float zoomRatio = 1.0;
            ability->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, sizeof(float));

            uint8_t flaMode = OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN;
            ability->addEntry(OHOS_CONTROL_FLASH_MODE, &flaMode, sizeof(uint8_t));

            uint8_t flashstate = OHOS_CAMERA_FLASH_STATE_READY;
            ability->addEntry(OHOS_CONTROL_FLASH_STATE, &flashstate, sizeof(uint8_t));

            uint8_t fMode = FOCUS_MODE_AUTO;
            ability->addEntry(OHOS_CONTROL_FOCUS_MODE, &fMode, sizeof(uint8_t));

            uint8_t focusState = OHOS_CAMERA_FOCUS_STATE_SCAN;
            ability->addEntry(OHOS_CONTROL_FOCUS_STATE, &focusState, sizeof(uint8_t));

            uint8_t exMode = 0;
            ability->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &exMode, sizeof(uint8_t));

            uint8_t muteMode = OHOS_CAMERA_MUTE_MODE_OFF;
            ability->addEntry(OHOS_CONTROL_MUTE_MODE, &muteMode, sizeof(uint8_t));

            int32_t activeArraySize[] = {
                0, 0, CameraFrameworkUnitTest::PREVIEW_DEFAULT_WIDTH, CameraFrameworkUnitTest::PREVIEW_DEFAULT_HEIGHT
            };
            ability->addEntry(OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &activeArraySize, sizeof(int32_t));

            uint8_t videoStabilizationMode = OHOS_CAMERA_VIDEO_STABILIZATION_OFF;
            ability->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabilizationMode, sizeof(uint8_t));

            uint8_t faceDetectMode = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
            ability->addEntry(OHOS_STATISTICS_FACE_DETECT_MODE, &faceDetectMode, sizeof(uint8_t));

            uint8_t value_u8 = 0;
            ability->addEntry(OHOS_ABILITY_CAMERA_TYPE, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_FLASH_MODES, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_FOCUS_MODES, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_EXPOSURE_MODES, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_PRELAUNCH_AVAILABLE, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &value_u8, sizeof(uint8_t));
            ability->addEntry(OHOS_ABILITY_MUTE_MODES, &value_u8, sizeof(uint8_t));

            uint32_t value_u32[2] = {0, 10};
            ability->addEntry(OHOS_ABILITY_FPS_RANGES, &value_u32, sizeof(value_u32) / sizeof(value_u32[0]));

            float value_f[1] = {1.0};
            ability->addEntry(OHOS_ABILITY_ZOOM_RATIO_RANGE, &value_f, sizeof(value_f) / sizeof(value_f[0]));

            int32_t aeRegions = 0;
            ability->addEntry(OHOS_CONTROL_AE_REGIONS, &aeRegions, sizeof(int32_t));

            int32_t aeExposureCompensation = 0;
            ability->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, sizeof(int32_t));

            uint8_t exposureState = 0;
            ability->addEntry(OHOS_CONTROL_EXPOSURE_STATE, &exposureState, sizeof(uint8_t));

            uint8_t mirror = OHOS_CAMERA_MIRROR_OFF;
            ability->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, sizeof(uint8_t));

            int32_t orientation = OHOS_CAMERA_JPEG_ROTATION_0;
            ability->addEntry(OHOS_JPEG_ORIENTATION, &orientation, sizeof(int32_t));

            ability->addEntry(OHOS_ABILITY_CAMERA_MODES, &modes, sizeof(modes) / sizeof(modes[0]));

            ability->addEntry(OHOS_ABILITY_SCENE_FILTER_TYPES, &filterAbility,
                              sizeof(filterAbility) / sizeof(filterAbility[0]));

            ability->addEntry(OHOS_CONTROL_FILTER_TYPE, &filterControl,
                              sizeof(filterControl) / sizeof(filterControl[0]));

            ability->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES, beautyAbility,
                              sizeof(beautyAbility) / sizeof(beautyAbility[0]));

            ability->addEntry(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, &faceSlenderBeautyRange,
                              sizeof(faceSlenderBeautyRange) / sizeof(faceSlenderBeautyRange[0]));

            ability->addEntry(OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &faceSlenderBeautyControl,
                              sizeof(faceSlenderBeautyControl) / sizeof(faceSlenderBeautyControl[0]));

            ability->addEntry(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &effectAbility,
                              sizeof(effectAbility) / sizeof(effectAbility[0]));

            ability->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &effectControl,
                              sizeof(effectControl) / sizeof(effectControl[0]));
            return CAMERA_OK;
        });
        ON_CALL(*this, OpenCameraDevice).WillByDefault([this](std::string &cameraId,
                                                            const sptr<ICameraDeviceCallback> &callback,
                                                            sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> &pDevice) {
            pDevice = cameraDevice;
            return CAMERA_OK;
        });
        ON_CALL(*this, SetFlashlight(_, _)).WillByDefault(Return(CAMERA_OK));
        ON_CALL(*this, SetCallback(_)).WillByDefault(Return(CAMERA_OK));
    }
    ~MockHCameraHostManager() {}
    MOCK_METHOD1(GetVersionByCamera, int32_t(const std::string& cameraId));
    MOCK_METHOD1(GetCameras, int32_t(std::vector<std::string> &cameraIds));
    MOCK_METHOD1(SetCallback, int32_t(sptr<ICameraHostCallback> &callback));
    MOCK_METHOD2(GetCameraAbility, int32_t(std::string &cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata> &ability));
    MOCK_METHOD2(SetFlashlight, int32_t(const std::string &cameraId, bool isEnable));
    MOCK_METHOD3(OpenCameraDevice, int32_t(std::string &cameraId,
        const sptr<ICameraDeviceCallback> &callback, sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> &pDevice));
    sptr<MockCameraDevice> cameraDevice;
};

class FakeHCameraService : public HCameraService {
public:
    explicit FakeHCameraService(sptr<HCameraHostManager> hostManager) : HCameraService(hostManager) {}
    ~FakeHCameraService() {}
};

class FakeCameraManager : public CameraManager {
public:
    explicit FakeCameraManager(sptr<HCameraService> service) : CameraManager(service) {}
    ~FakeCameraManager() {}
};

class CallbackListener : public FocusCallback, public ExposureCallback {
public:
    void OnFocusState(FocusState state) override
    {
        MEDIA_DEBUG_LOG("CallbackListener::OnFocusState ");
        return;
    }

    void OnExposureState(ExposureState state) override
    {
        MEDIA_DEBUG_LOG("CallbackListener::OnExposureState ");
        return;
    }
};

class AppSessionCallback : public SessionCallback {
public:
    void OnError(int32_t errorCode)
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
        return;
    }
};

class AppMacroStatusCallback : public MacroStatusCallback {
public:
    void OnMacroStatusChanged(MacroStatus status)
    {
        MEDIA_DEBUG_LOG("AppMacroStatusCallback");
    }
};

class AppMetadataCallback : public MetadataObjectCallback, public MetadataStateCallback {
public:
    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnMetadataObjectsAvailable received");
    }
    void OnError(int32_t errorCode) const
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
    }
};

sptr<CaptureOutput> CameraFrameworkUnitTest::CreatePhotoOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager->CreatePhotoOutput(photoProfile, surfaceProducer);
}

sptr<CaptureOutput> CameraFrameworkUnitTest::CreatePreviewOutput(int32_t width, int32_t height)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    Profile previewProfile = Profile(previewFormat, previewSize);
    return cameraManager->CreatePreviewOutput(previewProfile, surface);
}

sptr<CaptureOutput> CameraFrameworkUnitTest::CreateVideoOutput(int32_t width, int32_t height)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    return cameraManager->CreateVideoOutput(videoProfile, surface);
}

void CameraFrameworkUnitTest::SessionCommit(sptr<CaptureSession> session)
{
    int32_t ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);
    int32_t captureId = 3;
    EXPECT_CALL(*mockStreamOperator, Capture(captureId, _, true));
    ret = session->Start();
    EXPECT_EQ(ret, 0);
}

void CameraFrameworkUnitTest::SessionControlParams(sptr<CaptureSession> session)
{
    session->LockForControl();

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->SetZoomRatio(zoomRatioRange[0]);
    }

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->SetExposureBias(exposurebiasRange[0]);
    }

    FlashMode flash = FLASH_MODE_ALWAYS_OPEN;
    session->SetFlashMode(flash);

    FocusMode focus = FOCUS_MODE_AUTO;
    session->SetFocusMode(focus);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    session->SetExposureMode(exposure);

    session->UnlockForControl();

    if (!exposurebiasRange.empty()) {
        EXPECT_EQ(session->GetExposureValue(), exposurebiasRange[0]);
    }

    EXPECT_EQ(session->GetFlashMode(), flash);
    EXPECT_EQ(session->GetFocusMode(), focus);
    EXPECT_EQ(session->GetExposureMode(), exposure);
}

void CameraFrameworkUnitTest::PortraitSessionControlParams(sptr<PortraitSession> portraitSession)
{
    portraitSession->LockForControl();

    std::vector<PortraitEffect> effects= portraitSession->GetSupportedPortraitEffects();
    ASSERT_TRUE(effects.size() != 0);

    if (!effects.empty()) {
        portraitSession->SetPortraitEffect(effects[0]);
    }

    std::vector<FilterType> filterLists= portraitSession->GetSupportedFilters();
    ASSERT_TRUE(filterLists.size() != 0);

    if (!filterLists.empty()) {
        portraitSession->SetFilter(filterLists[0]);
    }

    std::vector<BeautyType> beautyLists= portraitSession->GetSupportedBeautyTypes();
    ASSERT_TRUE(beautyLists.size() != 0);

    std::vector<int32_t> rangeLists= portraitSession->GetSupportedBeautyRange(beautyLists[ARRAY_IDX]);
    ASSERT_TRUE(rangeLists.size() != 0);

    if (!beautyLists.empty()) {
        portraitSession->SetBeauty(beautyLists[ARRAY_IDX], rangeLists[0]);
    }

    portraitSession->UnlockForControl();
    ASSERT_EQ(portraitSession->GetPortraitEffect(), effects[0]);
    ASSERT_EQ(portraitSession->GetFilter(), filterLists[0]);
    ASSERT_EQ(portraitSession->GetBeauty(beautyLists[ARRAY_IDX]), rangeLists[0]);
}

void CameraFrameworkUnitTest::PortraitSessionEffectParams(sptr<PortraitSession> portraitSession)
{
    std::vector<PortraitEffect> effects= portraitSession->GetSupportedPortraitEffects();
    ASSERT_TRUE(effects.size() != 0);

    if (!effects.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetPortraitEffect(effects[0]);
        portraitSession->UnlockForControl();
    }
    ASSERT_EQ(portraitSession->GetPortraitEffect(), effects[0]);
}

void CameraFrameworkUnitTest::PortraitSessionFilterParams(sptr<PortraitSession> portraitSession)
{
    std::vector<FilterType> filterLists= portraitSession->GetSupportedFilters();
    ASSERT_TRUE(filterLists.size() != 0);

    if (!filterLists.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetFilter(filterLists[0]);
        portraitSession->UnlockForControl();
    }
    ASSERT_EQ(portraitSession->GetFilter(), filterLists[0]);
}

void CameraFrameworkUnitTest::PortraitSessionBeautyParams(sptr<PortraitSession> portraitSession)
{
    std::vector<BeautyType> beautyLists= portraitSession->GetSupportedBeautyTypes();
    ASSERT_TRUE(beautyLists.size() != 0);

    std::vector<int32_t> rangeLists= portraitSession->GetSupportedBeautyRange(beautyLists[ARRAY_IDX]);
    ASSERT_TRUE(rangeLists.size() != 0);

    if (!beautyLists.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetBeauty(beautyLists[ARRAY_IDX], rangeLists[0]);
        portraitSession->UnlockForControl();
    }
    ASSERT_EQ(portraitSession->GetBeauty(beautyLists[ARRAY_IDX]), rangeLists[0]);
}

void CameraFrameworkUnitTest::SetUpTestCase(void) {}

void CameraFrameworkUnitTest::TearDownTestCase(void) {}

void CameraFrameworkUnitTest::SetUp()
{
    // set native token
    uint64_t tokenId;
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
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    g_mockFlagWithoutAbt = false;
    mockCameraHostManager = new MockHCameraHostManager(nullptr);
    mockCameraDevice = mockCameraHostManager->cameraDevice;
    mockStreamOperator = mockCameraDevice->streamOperator;
    cameraManager = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager));
}

void CameraFrameworkUnitTest::TearDown()
{
    Mock::AllowLeak(mockCameraHostManager);
    Mock::AllowLeak(mockCameraDevice);
    Mock::AllowLeak(mockStreamOperator);
}

MATCHER_P(matchCaptureSetting, captureSetting, "Match Capture Setting")
{
    std::vector<uint8_t> result;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureSetting, result);
    return (arg.captureSetting_ == result);
}

/*
 * Feature: Framework
 * Function: Test get HostName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get HostName
 */
HWTEST_F(CameraFrameworkUnitTest, Camera_fwInfoManager_unittest_001, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(static_cast<int>(cameras.size()), 0);
    std::string hostName = cameras[0]->GetHostName();
    ASSERT_EQ(hostName, "");
}

/*
 * Feature: Framework
 * Function: Test get DeviceType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get DeviceType
 */
HWTEST_F(CameraFrameworkUnitTest, Camera_fwInfoManager_unittest_002, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(static_cast<int>(cameras.size()), 0);
    auto judgeDeviceType = [&cameras] () -> bool {
        bool isOk = false;
        uint16_t deviceType = cameras[0]->GetDeviceType();
        switch (deviceType) {
            case UNKNOWN:
            case PHONE:
            case TABLET:
                isOk = true;
                break;
            default:
                isOk = false;
                break;
        }
        return isOk;
    };
    ASSERT_NE(judgeDeviceType(), false);
}

/*
 * Feature: Framework
 * Function: Test result callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test result callback
 */
HWTEST_F(CameraFrameworkUnitTest, Camera_ResultCallback_unittest, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CameraInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::shared_ptr<TestOnResultCallback> setResultCallback =
    std::make_shared<TestOnResultCallback>("OnResultCallback");

    input->SetResultCallback(setResultCallback);
    std::shared_ptr<ResultCallback> getResultCallback = input->GetResultCallback();
    ASSERT_EQ(getResultCallback, setResultCallback);
}

/*
 * Feature: Framework
 * Function: Test get cameras
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get cameras
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_001, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_TRUE(cameras.size() != 0);
}

/*
 * Feature: Framework
 * Function: Test create input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create input
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_002, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    ASSERT_TRUE(cameras.size() != 0);
    sptr<CameraInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    ASSERT_NE(input->GetCameraDevice(), nullptr);

    input->Release();
}

/*
 * Feature: Framework
 * Function: Test create session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create session
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_003, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test create preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create preview output
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_004, TestSize.Level0)
{
    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = PREVIEW_DEFAULT_HEIGHT;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> preview = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(preview, nullptr);
    preview->Release();
}

/*
 * Feature: Framework
 * Function: Test create preview output with surface as null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create preview output with surface as null
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_005, TestSize.Level0)
{
    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = PREVIEW_DEFAULT_HEIGHT;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<Surface> surface = nullptr;
    sptr<CaptureOutput> preview = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_EQ(preview, nullptr);
}


/*
 * Feature: Framework
 * Function: Test create photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_011, TestSize.Level0)
{
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    sptr<PhotoOutput> photo = cameraManager->CreatePhotoOutput(photoProfile, surfaceProducer);
    ASSERT_NE(photo, nullptr);
    photo->Release();
}

/*
 * Feature: Framework
 * Function: Test create photo output with surface as null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output with surface as null
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_012, TestSize.Level0)
{
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<IBufferProducer> surfaceProducer = nullptr;
    sptr<PhotoOutput> photo = cameraManager->CreatePhotoOutput(photoProfile, surfaceProducer);
    ASSERT_EQ(photo, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create video output
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_015, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);
    video->Release();
}

/*
 * Feature: Framework
 * Function: Test create video output with surface as null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create video output with surface as null
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_016, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    sptr<Surface> surface = nullptr;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager->CreateVideoOutput(videoProfile, surface);
    ASSERT_EQ(video, nullptr);
}

/*
 * Feature: Framework
 * Function: Test manager callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test manager callback
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_019, TestSize.Level0)
{
    std::shared_ptr<TestCameraMngerCallback> setCallback = std::make_shared<TestCameraMngerCallback>("MgrCallback");
    cameraManager->SetCallback(setCallback);
    std::shared_ptr<CameraManagerCallback> getCallback = cameraManager->GetApplicationCallback();
    ASSERT_EQ(setCallback, getCallback);
}

/*
 * Feature: Framework
 * Function: Test set camera parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set camera parameters zoom, focus, flash & exposure
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_020, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    SessionControlParams(session);

    session->RemoveOutput(photo);
    session->RemoveInput(input);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test input callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test input callback
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_021, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CameraInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::shared_ptr<TestDeviceCallback> setCallback = std::make_shared<TestDeviceCallback>("InputCallback");
    input->SetErrorCallback(setCallback);
    std::shared_ptr<ErrorCallback> getCallback = input->GetErrorCallback();
    ASSERT_EQ(setCallback, getCallback);
}

/*
 * Feature: Framework
 * Function: Test preview callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preview callback
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_022, TestSize.Level0)
{
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    std::shared_ptr<PreviewStateCallback> setCallback =
        std::make_shared<TestPreviewOutputCallback>("PreviewStateCallback");
    ((sptr<PreviewOutput> &)preview)->SetCallback(setCallback);
    std::shared_ptr<PreviewStateCallback> getCallback = ((sptr<PreviewOutput> &)preview)->GetApplicationCallback();
    ASSERT_EQ(setCallback, getCallback);
}

/*
 * Feature: Framework
 * Function: Test photo callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo callback
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_023, TestSize.Level0)
{
    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    std::shared_ptr<PhotoStateCallback> setCallback = std::make_shared<TestPhotoOutputCallback>("PhotoStateCallback");
    ((sptr<PhotoOutput> &)photo)->SetCallback(setCallback);
    std::shared_ptr<PhotoStateCallback> getCallback = ((sptr<PhotoOutput> &)photo)->GetApplicationCallback();
    ASSERT_EQ(setCallback, getCallback);
}

/*
 * Feature: Framework
 * Function: Test video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video callback
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_024, TestSize.Level0)
{
    sptr<CaptureOutput> video = CreateVideoOutput();
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoStateCallback> setCallback = std::make_shared<TestVideoOutputCallback>("VideoStateCallback");
    ((sptr<VideoOutput> &)video)->SetCallback(setCallback);
    std::shared_ptr<VideoStateCallback> getCallback = ((sptr<VideoOutput> &)video)->GetApplicationCallback();
    ASSERT_EQ(setCallback, getCallback);
}

/*
 * Feature: Framework
 * Function: Test capture session add input with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add input with invalid value
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_025, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureInput> input = nullptr;
    ret = session->AddInput(input);
    EXPECT_NE(ret, 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session add output with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add output with invalid value
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_026, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureOutput> preview = nullptr;
    ret = session->AddOutput(preview);
    EXPECT_NE(ret, 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding input
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_027, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_NE(ret, 0);
    session->RemoveOutput(preview);
    preview->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding output
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_028, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_NE(ret, 0);
    session->RemoveInput(input);
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session without begin config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session without begin config
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_029, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->AddInput(input);
    EXPECT_NE(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_NE(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_NE(ret, 0);

    ret = session->CommitConfig();
    EXPECT_NE(ret, 0);

    ret = session->Start();
    EXPECT_NE(ret, 0);

    ret = ((sptr<PreviewOutput> &)preview)->Start();
    EXPECT_NE(ret, 0);

    ret = ((sptr<PhotoOutput> &)photo)->Capture();
    EXPECT_NE(ret, 0);

    ret = ((sptr<PreviewOutput> &)preview)->Stop();
    EXPECT_NE(ret, 0);

    ret = session->Stop();
    EXPECT_NE(ret, 0);
    session->RemoveInput(input);
    session->RemoveOutput(preview);
    session->RemoveOutput(photo);
    preview->Release();
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop without adding preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop without adding preview output
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_030, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, Capture(_, _, true)).Times(0);
    ret = session->Start();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, CancelCapture(_)).Times(0);

    ret = session->Stop();
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test session with preview + photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + photo
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_031, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, Capture(1, _, true));
    ret = session->Start();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, Capture(2, _, false));
    ret = ((sptr<PhotoOutput> &)photo)->Capture();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, CancelCapture(1));
    ret = ((sptr<PreviewOutput> &)preview)->Stop();
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test session with preview + photo with camera configuration
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + photo with camera configuration
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_032, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->LockForControl();
        session->SetZoomRatio(zoomRatioRange[0]);
        session->UnlockForControl();
    }

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    if (!zoomRatioRange.empty()) {
        EXPECT_CALL(*mockCameraDevice, UpdateSettings(_));
    }
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test session with preview + video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + video
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_033, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> video = CreateVideoOutput();
    ASSERT_NE(video, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(video);
    EXPECT_EQ(ret, 0);

    SessionCommit(session);

    EXPECT_CALL(*mockStreamOperator, Capture(4, _, true));
    ret = ((sptr<VideoOutput> &)video)->Start();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, CancelCapture(4));
    ret = ((sptr<VideoOutput> &)video)->Stop();
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*mockStreamOperator, CancelCapture(3));
    ret = ((sptr<PreviewOutput> &)preview)->Stop();
    EXPECT_EQ(ret, 0);

    ((sptr<VideoOutput> &)video)->Release();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove output with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove output with null
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_034, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureOutput> output = nullptr;
    ret = session->RemoveOutput(output);
    EXPECT_NE(ret, 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove output
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_035, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> video = CreateVideoOutput();
    ASSERT_NE(video, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(video);
    EXPECT_EQ(ret, 0);

    ret = session->RemoveOutput(video);
    EXPECT_EQ(ret, 0);
    video->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove input with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input with null
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_036, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureInput> input = nullptr;
    ret = session->RemoveInput(input);
    EXPECT_NE(ret, 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_037, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->RemoveInput(input);
    EXPECT_EQ(ret, 0);
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test photo capture with photo settings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo capture with photo settings
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_038, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetRotation(PhotoCaptureSetting::Rotation_90);
    photoSetting->SetQuality(PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);
    EXPECT_EQ(photoSetting->GetRotation(), PhotoCaptureSetting::Rotation_90);
    EXPECT_EQ(photoSetting->GetQuality(), PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);

    EXPECT_CALL(*mockStreamOperator, Capture(_,
        matchCaptureSetting(photoSetting->GetCaptureMetadataSetting()), false));
    ret = ((sptr<PhotoOutput> &)photo)->Capture(photoSetting);
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test GetFocalLength
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFocalLength
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_040, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    double focalLength = session->GetFocalLength();
    ASSERT_EQ(focalLength, 1.5);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}


/*
 * Feature: Framework
 * Function: Test SetMeteringPoint & GetMeteringPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetMeteringPoint & GetMeteringPoint
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_041, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    Point exposurePoint = {1.0, 2.0};
    session->LockForControl();
    session->SetMeteringPoint(exposurePoint);
    session->UnlockForControl();
    ASSERT_EQ((session->GetMeteringPoint().x), exposurePoint.x > 1 ? 1 : exposurePoint.x);
    ASSERT_EQ((session->GetMeteringPoint().y), exposurePoint.y > 1 ? 1 : exposurePoint.y);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}


/*
 * Feature: Framework
 * Function: Test SetFocusPoint & GetFousPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusPoint & GetFousPoint
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_042, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    Point FocusPoint = {1.0, 2.0};
    session->LockForControl();
    session->SetFocusPoint(FocusPoint);
    session->UnlockForControl();
    ASSERT_EQ((session->GetFocusPoint().x), FocusPoint.x > 1 ? 1 : FocusPoint.x);
    ASSERT_EQ((session->GetFocusPoint().y), FocusPoint.y > 1 ? 1 : FocusPoint.y);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with value less then the range
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_043, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->LockForControl();
        session->SetExposureBias(exposurebiasRange[0]-1.0);
        session->UnlockForControl();
        ASSERT_EQ(session->GetExposureValue(), exposurebiasRange[0]);
    }

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with value between the range
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_044, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->LockForControl();
        session->SetExposureBias(exposurebiasRange[0]+1.0);
        session->UnlockForControl();
        EXPECT_TRUE((session->GetExposureValue()>=exposurebiasRange[0] &&
                session->GetExposureValue()<=exposurebiasRange[1]));
    }
    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}


/*
 * Feature: Framework
 * Function: Test GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with value more then the range
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_045, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->LockForControl();
        session->SetExposureBias(exposurebiasRange[1]+1.0);
        session->UnlockForControl();
    }
    ASSERT_EQ(session->GetExposureValue(), exposurebiasRange[1]);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test cameraManager and portrait session with beauty/filter/portrait effects
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager and portrait session with beauty/filter/portrait effects
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_046, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    SceneMode mode = PORTRAIT;
    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionControlParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test cameraManager with GetSupportedModes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedModes to get modes
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_047, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with GetSupportedOutputCapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedOutputCapability to get capability
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_048, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    SceneMode mode = PORTRAIT;
    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreateCaptureSession and CommitConfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager to CreateCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_049, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    SceneMode mode = PORTRAIT;
    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);


    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);


    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);
    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPortraitEffects / GetPortraitEffect / SetPortraitEffect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPortraitEffect and SetPortraitEffect with value
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_050, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    SceneMode mode = PORTRAIT;
    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();


    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionEffectParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedFilters / GetFilter / SetFilter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFilter and SetFilter with value
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_051, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    SceneMode mode = PORTRAIT;
    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionFilterParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedBeautyTypes / GetSupportedBeautyRange / GetBeauty / SetBeauty
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBeauty and SetBeauty with value
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_052, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    SceneMode mode = PORTRAIT;
    std::vector<SceneMode> modes = cameraManager->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();


    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionBeautyParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test cameramanager with updatetorchmode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with updatetorchmode
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_053, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], 0);

    SceneMode mode = PORTRAIT;
    cameraManager->serviceProxy_ = nullptr;
    cameraManager->CreateCaptureSession(mode);
    cameraManager->InitCameraList();

    TorchMode mode1 = TorchMode::TORCH_MODE_OFF;
    TorchMode mode2 = TorchMode::TORCH_MODE_ON;
    cameraManager->torchMode_ = mode1;
    cameraManager->UpdateTorchMode(mode1);
    cameraManager->UpdateTorchMode(mode2);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with parsebasiccapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with parsebasiccapability
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_054, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    cameraManager->ParseBasicCapability(ability, metadata, item);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with no cameraid and cameraobjlist
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with no cameraid and cameraobjlist
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_055, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], 0);

    pid_t pid = 0;
    cameraManager->CameraServerDied(pid);
    sptr<ICameraServiceCallback> cameraServiceCallback = nullptr;
    cameraManager->SetCameraServiceCallback(cameraServiceCallback);
    sptr<ITorchServiceCallback> torchServiceCallback = nullptr;
    cameraManager->SetTorchServiceCallback(torchServiceCallback);
    sptr<ICameraMuteServiceCallback> cameraMuteServiceCallback = nullptr;
    cameraManager->SetCameraMuteServiceCallback(cameraMuteServiceCallback);
    float level = 9.2;
    cameraManager->SetTorchLevel(level);
    string cameraId = "";
    int activeTime = 0;
    EffectParam effectParam = {0, 0, 0};
    cameraManager->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSISTENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);

    cameraManager->cameraObjList = {};
    bool isTorchSupported = cameraManager->IsTorchSupported();
    EXPECT_EQ(isTorchSupported, false);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with serviceProxy_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with serviceProxy_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_056, TestSize.Level0)
{
    sptr<ICameraServiceCallback> callback = new(std::nothrow) CameraStatusServiceCallback(cameraManager);
    cameraManager->cameraSvcCallback_  = callback;

    pid_t pid = 0;
    cameraManager->serviceProxy_  = nullptr;
    cameraManager->CameraServerDied(pid);
    sptr<ICameraServiceCallback> cameraServiceCallback = nullptr;
    cameraManager->SetCameraServiceCallback(cameraServiceCallback);
    sptr<ITorchServiceCallback> torchServiceCallback = nullptr;
    cameraManager->SetTorchServiceCallback(torchServiceCallback);
    sptr<ICameraMuteServiceCallback> cameraMuteServiceCallback = nullptr;
    cameraManager->SetCameraMuteServiceCallback(cameraMuteServiceCallback);

    cameraManager->cameraObjList = {};
    string cameraId = "";
    cameraManager->GetCameraDeviceFromId(cameraId);
    bool isTorchSupported = cameraManager->IsTorchSupported();
    EXPECT_EQ(isTorchSupported, false);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with preswitchcamera
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with preswitchcamera
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_057, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager->GetSupportedOutputCapability(cameras[0], 0);

    std::string cameraId = cameras[0]->GetID();
    cameraManager->PreSwitchCamera(cameraId);

    cameraManager->serviceProxy_ = nullptr;
    cameraManager->PreSwitchCamera(cameraId);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with position and zoomratiorange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameradevice with position and zoomratiorange
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_058, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    cameras[0]->foldScreenType_ = CAMERA_FOLDSCREEN_INNER;
    cameras[0]->cameraPosition_ = CAMERA_POSITION_FRONT;
    cameras[0]->GetPosition();

    cameras[0]->zoomRatioRange_ = {1.1, 2.1};
    cameras[0]->GetZoomRatioRange();
}

/*
 * Feature: Framework
 * Function: Test camerainput with cameraserverdied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camerainput with cameraserverdied
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_059, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    pid_t pid = 0;
    camInput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test camerainput with deviceObj_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camerainput with deviceObj_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_060, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    pid_t pid = 0;
    std::shared_ptr<TestDeviceCallback> setCallback = std::make_shared<TestDeviceCallback>("InputCallback");
    camInput->deviceObj_ = nullptr;
    camInput->SetErrorCallback(setCallback);
    camInput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test camerainput with metadata_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camerainput with metadata_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_061, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    uint32_t metaTag = 0;
    camInput->cameraObj_->metadata_ = nullptr;
    camInput->GetMetaSetting(metaTag);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with cameraserverdied and stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with cameraserverdied and stop
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_062, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureOutput> output = cameraManager->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    pid_t pid = 0;
    metadatOutput->CameraServerDied(pid);
    metadatOutput->Stop();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with stream_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_063, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> output = cameraManager->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    pid_t pid = 0;
    metadatOutput->stream_ = nullptr;
    metadatOutput->CameraServerDied(pid);
    metadatOutput->Stop();
    metadatOutput->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with surface_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with surface_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_064, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> output = cameraManager->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    metadatOutput->surface_ = nullptr;
    metadatOutput->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start when session_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start when session_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_065, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> metadata = cameraManager->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    metadatOutput->session_ = nullptr;
    metadatOutput->Start();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start when not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start when not commit
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_066, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);

    metadatOutput->Start();

    session->CommitConfig();
    session->Start();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start when stream_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_067, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();

    session->AddInput(input);
    session->AddOutput(metadata);

    session->CommitConfig();
    session->Start();

    metadatOutput->stream_ = nullptr;
    metadatOutput->Start();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_068, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();

    session->AddInput(input);
    session->AddOutput(metadata);

    session->CommitConfig();
    session->Start();

    metadatOutput->Start();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when destruction
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_069, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> output = cameraManager->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    metadatOutput->~MetadataOutput();
    metadatOutput->Stop();
}

/*
 * Feature: Framework
 * Function: Test photooutput with cameraserverdied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with cameraserverdied
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_070, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    pid_t pid = 0;
    photoOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test photooutput with cameraserverdied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with cameraserverdied
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_071, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    pid_t pid = 0;
    std::shared_ptr<PhotoStateCallback> setCallback = std::make_shared<TestPhotoOutputCallback>("PhotoStateCallback");
    ((sptr<PhotoOutput>&)photoOutput)->SetCallback(setCallback);
    photoOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test photooutput with cameraserverdied when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with cameraserverdied when stream_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_072, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    pid_t pid = 0;
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;
    phtOutput->stream_ = nullptr;
    photoOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test photooutput with confirmcapture when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photooutput with confirmcapture when stream_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_073, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    sptr<PhotoOutput> phtOutput = (sptr<PhotoOutput>&)photoOutput;

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photoOutput);
    session->CommitConfig();

    phtOutput->stream_ = nullptr;
    phtOutput->ConfirmCapture();

    phtOutput->~PhotoOutput();
    phtOutput->ConfirmCapture();

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test previewoutput 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_074, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    auto previewOutput = (sptr<PreviewOutput>&)preview;
    previewOutput->stream_ = nullptr;
    previewOutput->session_ = nullptr;

    previewOutput->OnSketchStatusChanged(SketchStatus::STOPED);
    previewOutput->IsSketchSupported();

    Size previewSize = {};
    previewOutput->stream_ = nullptr;
    previewOutput->CreateSketchWrapper(previewSize);
}

/*
 * Feature: Framework
 * Function: Test previewoutput with callback and cameraserverdied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewoutput with callback and cameraserverdied
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_075, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    auto previewOutput = (sptr<PreviewOutput>&)preview;

    std::string eventString = "sketchAvailable";
    previewOutput->sketchWrapper_ = nullptr;
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);

    pid_t pid = 0;
    previewOutput->stream_ = nullptr;
    previewOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_076, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
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
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    SketchWrapper *sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    int32_t modeName = session->GetFeaturesMode();
    int ret = sketchWrapper->Init(deviceMetadata, modeName);
    EXPECT_EQ(ret, CAMERA_OK);

    sketchWrapper->sketchStream_ = nullptr;
    ret = sketchWrapper->AttachSketchSurface(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
    sketchWrapper->StartSketchStream();

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    sketchWrapper->UpdateSketchEnableRatio(metadata);
    sketchWrapper->UpdateSketchReferenceFovRatio(metadata);
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_077, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
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
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    SketchWrapper *sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    
    int32_t modeName = session->GetFeaturesMode();
    int ret = sketchWrapper->Init(deviceMetadata, modeName);
    EXPECT_EQ(ret, CAMERA_OK);

    float sketchRatio = sketchWrapper->GetSketchEnableRatio(session->GetFeaturesMode());
    sketchWrapper->hostStream_ = nullptr;
    ret = sketchWrapper->UpdateSketchRatio(sketchRatio);
    sketchWrapper->Destroy();
}

/*
 * Feature: Framework
 * Function: Test sketchwrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchwrapper
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_078, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
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
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(previewOutput, nullptr);

    Size sketchSize;
    sketchSize.width = 640;
    sketchSize.height = 480;

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    SketchWrapper *sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), sketchSize);
    ASSERT_NE(sketchWrapper, nullptr);
    
    int32_t modeName = session->GetFeaturesMode();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    const camera_device_metadata_tag_t tag1 = OHOS_CONTROL_ZOOM_RATIO;
    sketchWrapper->OnControlMetadataDispatch(modeName, tag1, item);
    const camera_device_metadata_tag_t tag2 = OHOS_CONTROL_CAMERA_MACRO;
    sketchWrapper->OnControlMetadataDispatch(modeName, tag2, item);
}

/*
 * Feature: Framework
 * Function: Test videooutput with cameraserverdied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with cameraserverdied
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_079, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    pid_t pid = 0;
    video->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test videooutput with cameraserverdied when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with cameraserverdied when stream_ is nullptr
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_080, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    pid_t pid = 0;
    video->stream_ = nullptr;
    std::shared_ptr<VideoStateCallback> setCallback = std::make_shared<TestVideoOutputCallback>("VideoStateCallback");
    video->SetCallback(setCallback);
    video->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test videooutput when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput when destruction
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_081, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    video->~VideoOutput();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_082, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    camDevice->UpdateSettingOnce(settings);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_083, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = cameras[0]->GetMetadata();
    camDevice->UpdateSettingOnce(settings);

    camDevice->RegisterFoldStatusListener();
    camDevice->UnRegisterFoldStatusListener();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_084, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    camDevice->UnRegisterFoldStatusListener();
    camDevice->RegisterFoldStatusListener();
    camDevice->UnRegisterFoldStatusListener();
    camDevice->cameraHostManager_ = nullptr;
    camDevice->RegisterFoldStatusListener();
    camDevice->UnRegisterFoldStatusListener();

    std::vector<int32_t> results = {};
    camDevice->EnableResult(results);
    camDevice->DisableResult(results);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut;
    camDevice->GetStatus(metaIn, metaOut);

    camDevice->Close();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_085, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    camDevice->hdiCameraDevice_ = nullptr;
    camDevice->InitStreamOperator();
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_086, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos = {};
    camDevice->CreateStreams(streamInfos);

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceSettings = cameras[0]->GetMetadata();
    int32_t operationMode = 0;
    camDevice->streamOperator_ = nullptr;
    camDevice->CommitStreams(deviceSettings, operationMode);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_087, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    std::vector<StreamInfo_V1_1> streamInfos = {};
    camDevice->UpdateStreams(streamInfos);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_088, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    int32_t captureId = 0;
    const std::vector<int32_t> streamIds = {1, 2};
    camDevice->OnCaptureStarted(captureId, streamIds);

    HDI::Camera::V1_2::CaptureStartedInfo it1;
    it1.streamId_ = 1;
    it1.exposureTime_ = 1;
    HDI::Camera::V1_2::CaptureStartedInfo it2;
    it2.streamId_ = 2;
    it2.exposureTime_ = 2;
    std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> captureStartedInfo = {};
    captureStartedInfo.push_back(it1);
    captureStartedInfo.push_back(it2);
    camDevice->OnCaptureStartedV1_2(captureId, captureStartedInfo);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_089, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    int32_t captureId = 0;
    const std::vector<int32_t> streamIds = {1, 2};
    camDevice->OnCaptureStarted(captureId, streamIds);
    const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> captureStartedInfo = {};
    camDevice->OnCaptureStartedV1_2(captureId, captureStartedInfo);

    CaptureEndedInfo it1;
    it1.streamId_ = 1;
    it1.frameCount_ = 1;
    CaptureEndedInfo it2;
    it2.streamId_ = 2;
    it2.frameCount_ = 2;
    std::vector<CaptureEndedInfo> captureEndedInfo = {};
    captureEndedInfo.push_back(it1);
    captureEndedInfo.push_back(it2);
    camDevice->OnCaptureEnded(captureId, captureEndedInfo);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_090, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    int32_t captureId = 0;
    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> captureErrorInfo = {};
    captureErrorInfo.push_back(it1);
    captureErrorInfo.push_back(it2);
    camDevice->OnCaptureError(captureId, captureErrorInfo);

    const std::vector<int32_t> streamIds = {1, 2};
    uint64_t timestamp = 5;
    camDevice->OnFrameShutter(captureId, streamIds, timestamp);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_091, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = cameras[0]->GetMetadata();
    camDevice->CheckOnResultData(nullptr);
    camDevice->CheckOnResultData(cameraResult);
}

/*
 * Feature: coverage
 * Function: Test HStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_092, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);
    sptr<HStreamRepeat> streamRepeat1 =
        new (std::nothrow) HStreamRepeat(producer, 4, 1280, 960, RepeatStreamType::PREVIEW);

    SketchStatus status = SketchStatus::STARTED;
    streamRepeat->repeatStreamType_ = RepeatStreamType::SKETCH;
    streamRepeat->parentStreamRepeat_ = streamRepeat1;
    streamRepeat->UpdateSketchStatus(status);
}

/*
 * Feature: coverage
 * Function: Test HStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_093, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);

    SketchStatus status = SketchStatus::STARTED;
    streamRepeat->OnSketchStatusChanged(status);
}

/*
 * Feature: coverage
 * Function: Test HStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_094, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);

    sptr<IStreamRepeat> sketchStream = nullptr;
    float sketchRatio = 0;
    streamRepeat->ForkSketchStreamRepeat(0, 1, sketchStream, sketchRatio);
    streamRepeat->ForkSketchStreamRepeat(1, 0, sketchStream, sketchRatio);
}

/*
 * Feature: coverage
 * Function: Test HStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_095, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);

    float sketchRatio = 0;
    streamRepeat->sketchStreamRepeat_ = nullptr;
    streamRepeat->RemoveSketchStreamRepeat();
    streamRepeat->UpdateSketchRatio(sketchRatio);
}

/*
 * Feature: coverage
 * Function: Test HStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_096, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);

    uint32_t interfaceCode = 5;
    streamRepeat->OperatePermissionCheck(interfaceCode);
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_097, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    std::vector<StreamInfo_V1_1> streamInfos = {};
    camSession->GetCurrentStreamInfos(streamInfos);
    camSession->AddOutputStream(nullptr);
    camSession->RemoveOutputStream(nullptr);
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_098, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    camSession->cameraDevice_ = nullptr;
    camSession->LinkInputAndOutputs();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_099, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    bool isNeedUpdate = false;
    ColorSpace colorSpace = ColorSpace::SRGB;
    ColorSpace captureColorSpace = ColorSpace::SRGB;
    camSession->currColorSpace_ = ColorSpace::BT709;
    camSession->currCaptureColorSpace_ = ColorSpace::BT709;
    camSession->SetColorSpace(colorSpace, captureColorSpace, isNeedUpdate);
    camSession->currColorSpace_ = ColorSpace::SRGB;
    camSession->SetColorSpace(colorSpace, captureColorSpace, isNeedUpdate);
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_100, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    camSession->RestartStreams();

    ColorSpace colorSpace = ColorSpace::SRGB;
    camSession->CheckIfColorSpaceMatchesFormat(colorSpace);
    colorSpace = ColorSpace::BT2020_HLG ;
    camSession->CheckIfColorSpaceMatchesFormat(colorSpace);
    colorSpace = ColorSpace::BT2020_PQ ;
    camSession->CheckIfColorSpaceMatchesFormat(colorSpace);
    colorSpace = ColorSpace::BT2020_HLG_LIMIT ;
    camSession->CheckIfColorSpaceMatchesFormat(colorSpace);
    colorSpace = ColorSpace::BT2020_PQ_LIMIT;
    camSession->CheckIfColorSpaceMatchesFormat(colorSpace);
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_101, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    const uint32_t callingTokenId = 0;
    const std::string permissionName = "camera";
    camSession->RegisterPermissionCallback(callingTokenId, permissionName);
    camSession->StartUsingPermissionCallback(callingTokenId, permissionName);
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_102, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    camSession->SetColorSpaceForStreams();

    std::vector<StreamInfo_V1_1> streamInfos = {};
    camSession->CancelStreamsAndGetStreamInfos(streamInfos);

    camSession->isSessionStarted_ = true;
    camSession->RestartStreams();

    const uint32_t callingTokenId = 0;
    const std::string permissionName = "camera";
    std::shared_ptr<CameraUseStateChangeCb> cameraUseStateChangeCb =
        std::make_shared<CameraUseStateChangeCb>(camSession);
    camSession->cameraUseCallbackPtr_ = cameraUseStateChangeCb;
    camSession->StartUsingPermissionCallback(callingTokenId, permissionName);
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_103, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    float currentFps = 0;
    float currentZoomRatio = 0;
    camSession->QueryFpsAndZoomRatio(currentFps, currentZoomRatio);
    std::vector<float> crossZoomAndTime = {0, 0};
    int32_t operationMode = 0;
    camSession->QueryZoomPerformance(crossZoomAndTime, operationMode);
    int32_t smoothZoomType = 0;
    float targetZoomRatio = 0;
    float duration = 0;
    camSession->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_104, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureOutput> output = cameraManager->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    std::shared_ptr<MetadataStateCallback> metadataStateCallback = std::make_shared<AppMetadataCallback>();
    metadatOutput->SetCallback(metadataStateCallback);

    pid_t pid = 0;
    metadatOutput->CameraServerDied(pid);
}

/*
 * Feature: coverage
 * Function: Test HStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat
 */
HWTEST_F(CameraFrameworkUnitTest, camera_framework_unittest_105, TestSize.Level0)
{
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);

    StreamInfo_V1_1 streamInfo;
    streamRepeat->repeatStreamType_ = RepeatStreamType::SKETCH;
    streamRepeat->SetStreamInfo(streamInfo);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_001, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);
    ASSERT_NE(camDevice, nullptr);

    int32_t ret = camDevice->HCameraDevice::OpenDevice();
    EXPECT_EQ(ret, 0);

    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);

    ret = camDevice->HCameraDevice::EnableResult(result);
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::DisableResult(result);
    EXPECT_EQ(ret, 0);

    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = camDevice->HCameraDevice::GetStreamOperator();
    EXPECT_TRUE(streamOperator != nullptr);

    ret = camDevice->HCameraDevice::OnError(REQUEST_TIMEOUT, 0);
    EXPECT_EQ(ret, 0);

    ret = camDevice->HCameraDevice::CloseDevice();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dump with args empty
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_002, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<FakeHCameraService> mockHCameraService = new FakeHCameraService(mockCameraHostManager);
    sptr<HCameraService> camService = (sptr<HCameraService> &)mockHCameraService;
    ASSERT_NE(camService, nullptr);

    std::vector<std::string> cameraIds = {};
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList = {};
    int32_t ret = camService->GetCameras(cameraIds, cameraAbilityList);

    int fd = 0;
    std::vector<std::u16string> args = {};
    ret = camService->Dump(fd, args);
    EXPECT_EQ(ret, 0);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_003, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    sptr<StreamOperatorCallback> streamOperatorCb = nullptr;
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    int32_t ret = camSession->AddInput(cameraDevice);
    EXPECT_EQ(ret, 10);

    ret = camSession->RemoveInput(cameraDevice);
    EXPECT_EQ(ret, 10);

    ret = camSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = camSession->BeginConfig();
    EXPECT_EQ(ret, 10);

    cameraDevice = nullptr;
    ret = camSession->AddInput(cameraDevice);
    EXPECT_EQ(ret, 2);

    ret = camSession->RemoveInput(cameraDevice);
    EXPECT_EQ(ret, 2);

    sptr<IStreamCommon> stream_2 = nullptr;
    ret = camSession->AddOutput(StreamType::CAPTURE, stream_2);
    EXPECT_EQ(ret, 2);

    ret = camSession->RemoveOutput(StreamType::CAPTURE, stream_2);
    EXPECT_EQ(ret, 2);

    input->Close();
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_004, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<FakeHCameraService> mockHCameraService = new FakeHCameraService(mockCameraHostManager);
    sptr<HCameraService> cameraService = (sptr<HCameraService> &)mockHCameraService;
    ASSERT_NE(cameraService, nullptr);

    cameraService->OnStop();
    cameraService->OnStart();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> Producer = Surface->GetProducer();

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamRepeat> output = nullptr;
    int32_t intResult = cameraService->CreateDeferredPreviewOutput(0, width, height, output);
    EXPECT_EQ(intResult, 2);

    width = 0;
    intResult = cameraService->CreateDeferredPreviewOutput(0, width, height, output);
    EXPECT_EQ(intResult, 2);

    Producer = nullptr;
    intResult = cameraService->CreatePreviewOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    Producer = Surface->GetProducer();
    intResult = cameraService->CreatePreviewOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    width = PREVIEW_DEFAULT_WIDTH;
    intResult = cameraService->CreatePreviewOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    intResult = cameraService->CreateVideoOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    width = 0;
    intResult = cameraService->CreateVideoOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    Producer = nullptr;
    intResult = cameraService->CreateVideoOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    cameraService->OnStart();
    cameraService->OnStop();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_005, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<FakeHCameraService> mockHCameraService = new FakeHCameraService(mockCameraHostManager);
    sptr<HCameraService> cameraService = (sptr<HCameraService> &)mockHCameraService;
    ASSERT_NE(cameraService, nullptr);

    int32_t width = 0;
    int32_t height = 0;

    cameraService->OnStop();
    cameraService->OnStart();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> Producer = Surface->GetProducer();

    sptr<IStreamCapture> output_1 = nullptr;
    int32_t intResult = cameraService->CreatePhotoOutput(Producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, 2);

    width = PHOTO_DEFAULT_WIDTH;
    intResult = cameraService->CreatePhotoOutput(Producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, 2);

    Producer = nullptr;
    intResult = cameraService->CreatePhotoOutput(Producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, 2);

    sptr<IStreamMetadata> output_2 = nullptr;
    intResult = cameraService->CreateMetadataOutput(Producer, 0, output_2);
    EXPECT_EQ(intResult, 2);

    cameraService->OnStart();
    cameraService->OnStop();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_006, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<FakeHCameraService> mockHCameraService = new FakeHCameraService(mockCameraHostManager);
    sptr<HCameraService> cameraService = (sptr<HCameraService> &)mockHCameraService;
    ASSERT_NE(cameraService, nullptr);

    cameraService->OnStop();
    cameraService->OnStart();

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = cameraService->SetCallback(callback);
    EXPECT_EQ(intResult, 2);

    callback = new(std::nothrow) CameraStatusServiceCallback(cameraManager);
    intResult = cameraService->SetCallback(callback);
    EXPECT_EQ(intResult, 0);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<ICameraMuteServiceCallback> callback_2 = nullptr;
    intResult = cameraService->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 2);

    callback_2 = new(std::nothrow) CameraMuteServiceCallback(cameraManager);
    intResult = cameraService->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 0);

    std::string cameraId = camInput->GetCameraId();
    int activeTime = 0;
    EffectParam effectParam = {0, 0, 0};

    intResult = cameraService->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSISTENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);

    cameraId = "";
    intResult = cameraService->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSISTENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);

    cameraService->OnStop();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test different status with OnReceive
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_007, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    HDI::ServiceManager::V1_0::ServiceStatus status;

    status.serviceName = "1";
    cameraHostManager->OnReceive(status);

    status.deviceClass = DEVICE_CLASS_CAMERA;
    status.serviceName = "distributed_camera_service";
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_START;
    cameraHostManager->OnReceive(status);
    cameraHostManager->OnReceive(status);

    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP;
    cameraHostManager->OnReceive(status);

    status.status = 4;
    cameraHostManager->OnReceive(status);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with no static capability.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_008, TestSize.Level0)
{
    g_mockFlagWithoutAbt = true;
    sptr<CameraManager> camManager = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager));

    std::vector<sptr<CameraDevice>> cameras = camManager->GetSupportedCameras();
    sptr<CaptureInput> input = camManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = camManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<CameraOutputCapability> cameraOutputCapability = camManager->GetSupportedOutputCapability(cameras[0]);

    std::vector<VideoStabilizationMode> videoStabilizationMode = session->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);

    int32_t intResult = session->GetSupportedStabilizationMode(videoStabilizationMode);
    EXPECT_EQ(intResult, 0);

    std::vector<ExposureMode> getSupportedExpModes = session->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes.empty(), true);

    EXPECT_EQ(session->GetSupportedExposureModes(getSupportedExpModes), 0);

    EXPECT_EQ(session->GetExposureMode(), -1);
    EXPECT_EQ((session->GetMeteringPoint().x), 0);
    EXPECT_EQ((session->GetMeteringPoint().y), 0);

    float exposureValue = session->GetExposureValue();
    EXPECT_EQ(exposureValue, 0);
    int32_t exposureValueGet = session->GetExposureValue(exposureValue);
    EXPECT_EQ(exposureValueGet, 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with no static capability.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_009, TestSize.Level0)
{
    g_mockFlagWithoutAbt = true;
    sptr<CameraManager> camManager = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager));

    std::vector<sptr<CameraDevice>> cameras = camManager->GetSupportedCameras();

    sptr<CaptureInput> input = camManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = camManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<CameraOutputCapability> cameraOutputCapability = camManager->GetSupportedOutputCapability(cameras[0]);

    std::vector<FocusMode> supportedFocusModes = session->GetSupportedFocusModes();
    EXPECT_EQ(supportedFocusModes.empty(), true);
    EXPECT_EQ(session->GetSupportedFocusModes(supportedFocusModes), 0);

    EXPECT_EQ(session->GetFocusMode(), 0);

    float focalLength = session->GetFocalLength();
    EXPECT_EQ(focalLength, 0);
    EXPECT_EQ(session->GetFocalLength(focalLength), 0);

    std::vector<FlashMode> supportedFlashModes = session->GetSupportedFlashModes();
    EXPECT_EQ(supportedFlashModes.empty(), true);
    EXPECT_EQ(session->GetSupportedFlashModes(supportedFlashModes), 0);
    EXPECT_EQ(session->GetFlashMode(), 0);
    EXPECT_EQ(session->GetZoomRatio(), 0);

    bool isSupported;
    EXPECT_EQ(session->IsVideoStabilizationModeSupported(MIDDLE, isSupported), 0);
    EXPECT_EQ(session->SetVideoStabilizationMode(MIDDLE), 0);
    EXPECT_EQ(session->IsFlashModeSupported(FLASH_MODE_AUTO), false);
    EXPECT_EQ(session->IsFlashModeSupported(FLASH_MODE_AUTO, isSupported), 0);

    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput> &)photo;
    EXPECT_EQ(photoOutput->IsMirrorSupported(), false);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dump with no static capability.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_010, TestSize.Level0)
{
    g_mockFlagWithoutAbt = true;
    sptr<CameraManager> camManager = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager));
    std::vector<sptr<CameraDevice>> cameras = camManager->GetSupportedCameras();

    sptr<CaptureInput> input = camManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<FakeHCameraService> mockHCameraService = new FakeHCameraService(mockCameraHostManager);
    sptr<HCameraService> camService = (sptr<HCameraService> &)mockHCameraService;
    ASSERT_NE(camService, nullptr);

    camService->OnStart();

    std::vector<std::string> cameraIds = {};
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList = {};
    int32_t ret = camService->GetCameras(cameraIds, cameraAbilityList);

    int fd = 0;
    std::vector<std::u16string> args = {};
    ret = camService->Dump(fd, args);
    EXPECT_EQ(ret, 0);

    std::u16string cameraServiceInfo = u"";
    args.push_back(cameraServiceInfo);
    ret = camService->Dump(fd, args);
    EXPECT_EQ(ret, 10);

    camService->OnStop();
    input->Close();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamCapture SetRotation with no static capability.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_011, TestSize.Level0)
{
    g_mockFlagWithoutAbt = true;
    sptr<CameraManager> camManager = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager));
    std::vector<sptr<CameraDevice>> cameras = camManager->GetSupportedCameras();

    sptr<CaptureInput> input = camManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = camManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetRotation(PhotoCaptureSetting::Rotation_90);
    photoSetting->SetQuality(PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);
    EXPECT_EQ(photoSetting->GetRotation(), PhotoCaptureSetting::Rotation_90);
    EXPECT_EQ(photoSetting->GetQuality(), PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);

    EXPECT_CALL(*mockStreamOperator, Capture(_,
        matchCaptureSetting(photoSetting->GetCaptureMetadataSetting()), false));
    ret = ((sptr<PhotoOutput> &)photo)->Capture(photoSetting);
    EXPECT_EQ(ret, 0);

    input->Close();
    session->Release();
    input->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat with no static capability.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_012, TestSize.Level0)
{
    g_mockFlagWithoutAbt = true;
    sptr<CameraManager> camManager = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager));
    int32_t format = CAMERA_FORMAT_YUV_420_SP;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;

    std::vector<sptr<CameraDevice>> cameras = camManager->GetSupportedCameras();

    sptr<CaptureInput> input = camManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureOutput> metadatOutput = camManager->CreateMetadataOutput();
    ASSERT_NE(metadatOutput, nullptr);

    sptr<CaptureSession> session = camManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);
    EXPECT_EQ(session->AddOutput(metadatOutput), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer1 = Surface->GetProducer();
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer1, format, width, height, RepeatStreamType::PREVIEW);

    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetRotation(PhotoCaptureSetting::Rotation_90);
    photoSetting->SetQuality(PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);
    EXPECT_EQ(photoSetting->GetRotation(), PhotoCaptureSetting::Rotation_90);
    EXPECT_EQ(photoSetting->GetQuality(), PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM);

    EXPECT_EQ(streamRepeat->LinkInput(mockStreamOperator, photoSetting->GetCaptureMetadataSetting()), 8);

    EXPECT_EQ(streamRepeat->Stop(), CAMERA_INVALID_STATE);
    EXPECT_EQ(streamRepeat->Start(), CAMERA_INVALID_STATE);

    EXPECT_EQ(streamRepeat->AddDeferredSurface(producer1), CAMERA_INVALID_STATE);

    EXPECT_EQ(streamRepeat->Start(), CAMERA_INVALID_STATE);
    EXPECT_EQ(streamRepeat->Stop(), CAMERA_INVALID_STATE);

    input->Close();
    session->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_013, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    std::string permissionName = "permissionName";
    uint32_t callingTokenId = 0;
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {permissionName};
    scopeInfo.tokenIDs = {callingTokenId};

    int32_t permStateChangeType = 0;
    Security::AccessToken::PermStateChangeInfo info;
    info.permStateChangeType = permStateChangeType;
    info.tokenID = Security::AccessToken::INVALID_TOKENID;
    info.permissionName = permissionName;

    int32_t permStateChangeType1 = 1;
    Security::AccessToken::PermStateChangeInfo info1;
    info1.permStateChangeType = permStateChangeType1;
    info1.tokenID = Security::AccessToken::INVALID_TOKENID;
    info1.permissionName = permissionName;

    std::shared_ptr<PermissionStatusChangeCb> permissionStatusChangeCb =
        std::make_shared<PermissionStatusChangeCb>(camSession, scopeInfo);
    permissionStatusChangeCb->PermStateChangeCallback(info);
    permissionStatusChangeCb->PermStateChangeCallback(info);
    permissionStatusChangeCb->PermStateChangeCallback(info1);

    std::shared_ptr<CameraUseStateChangeCb> cameraUseStateChangeCb =
        std::make_shared<CameraUseStateChangeCb>(camSession);
    cameraUseStateChangeCb->StateChangeNotify(Security::AccessToken::INVALID_TOKENID, false);
    cameraUseStateChangeCb->StateChangeNotify(Security::AccessToken::INVALID_TOKENID, true);
    cameraUseStateChangeCb->StateChangeNotify(Security::AccessToken::INVALID_TOKENID, false);

    input->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_014, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    camSession->BeginConfig();
    camSession->Start();

    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    EXPECT_EQ(camSession->AddInput(cameraDevice), 0);

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();

    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, 4, 1280, 960, RepeatStreamType::PREVIEW);
    auto streamRepeat1 = new (std::nothrow) HStreamRepeat(producer, 3, 640, 480, RepeatStreamType::PREVIEW);
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, 4, 1280, 960);

    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat1), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture), 0);

    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> info = {};
    info.push_back(it1);
    info.push_back(it2);
    camSession->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {1, 2};
    camSession->OnFrameShutter(0, streamIds, 0);

    input->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_015, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);

    camSession->BeginConfig();
    camSession->Start();

    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    EXPECT_EQ(camSession->AddInput(cameraDevice), 0);

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, 4, 1280, 960);
    sptr<HStreamCapture> streamCapture1 = new (std::nothrow) HStreamCapture(producer, 3, 640, 480);
    sptr<HStreamRepeat> streamRepeat =
        new (std::nothrow) HStreamRepeat(producer, 4, 1280, 960, RepeatStreamType::PREVIEW);

    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture1), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat), 0);

    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> info = {};
    info.push_back(it1);
    info.push_back(it2);
    camSession->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {1, 2};
    camSession->OnFrameShutter(0, streamIds, 0);

    input->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_016, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, PORTRAIT);

    EXPECT_EQ(camSession->CommitConfig(), CAMERA_INVALID_STATE);
    camSession->BeginConfig();
    camSession->Start();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamCapture> streamCapture= new(std::nothrow) HStreamCapture(producer, 0, 0, 0);

    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    EXPECT_EQ(camSession->AddInput(cameraDevice), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture), 0);

    camSession->CommitConfig();

    CaptureErrorInfo it1;
    it1.streamId_ = 0;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> info = {};
    info.push_back(it1);
    info.push_back(it2);
    camSession->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {0, 1, 2};
    camSession->OnFrameShutter(0, streamIds, 0);
    camSession->BeginConfig();

    input->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_017, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    sptr<StreamOperatorCallback> streamOperatorCb = nullptr;
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    sptr<HCaptureSession> camSession1 = new (std::nothrow) HCaptureSession(12, mode);
    ASSERT_NE(camSession, nullptr);
    EXPECT_EQ(camSession->Start(), CAMERA_INVALID_STATE);
    camSession1->Start();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, 0, 0, 0, RepeatStreamType::PREVIEW);
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_INVALID_STATE);
    EXPECT_EQ(camSession->RemoveOutput(StreamType::REPEAT, streamRepeat), CAMERA_INVALID_STATE);

    sptr<ICameraDeviceService> cameraDevice = camInput->GetCameraDevice();
    camSession->BeginConfig();
    camSession->Start();
    camSession->AddOutput(StreamType::METADATA, streamMetadata);
    camSession->AddOutput(StreamType::METADATA, streamMetadata);
    camSession->RemoveOutput(StreamType::METADATA, streamMetadata);
    camSession->AddInput(cameraDevice);

    camSession->AddInput(cameraDevice);

    sptr<ICaptureSessionCallback> callback1 = nullptr;
    camSession->SetCallback(callback1);

    std::string dumpString = "HCaptureSession";
    camSession->dumpSessionInfo(dumpString);
    camSession->dumpSessions(dumpString);

    input->Close();
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_018, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    session->LockForControl();

    Point exposurePoint = {1.0, 2.0};
    session->SetMeteringPoint(exposurePoint);
    session->SetMeteringPoint(exposurePoint);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    session->SetExposureMode(exposure);

    ret = session->GetExposureMode(exposure);
    EXPECT_EQ(ret, 0);

    ExposureMode exposureMode = session->GetExposureMode();
    int32_t setExposureMode = session->SetExposureMode(exposureMode);
    EXPECT_EQ(setExposureMode, 0);

    session->UnlockForControl();
    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMeteringPoint and GetMeteringPoint with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_019, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    session->LockForControl();

    Point exposurePointGet = session->GetMeteringPoint();
    int32_t getMeteringPoint = session->GetMeteringPoint(exposurePointGet);
    EXPECT_EQ(getMeteringPoint, 0);

    float exposureValue = session->GetExposureValue();
    int32_t exposureValueGet = session->GetExposureValue(exposureValue);
    EXPECT_EQ(exposureValueGet, 0);

    int32_t setExposureBias = session->SetExposureBias(exposureValue);
    EXPECT_EQ(setExposureBias, 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_020, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    std::shared_ptr<ExposureCallback> exposureCallback = std::make_shared<CallbackListener>();
    session->SetExposureCallback(exposureCallback);
    session->ProcessAutoExposureUpdates(metadata);

    std::shared_ptr<FocusCallback> focusCallback = std::make_shared<CallbackListener>();
    session->SetFocusCallback(focusCallback);
    session->ProcessAutoFocusUpdates(metadata);

    std::vector<FocusMode> getSupportedFocusModes = session->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), false);
    int32_t supportedFocusModesGet = session->GetSupportedFocusModes(getSupportedFocusModes);
    EXPECT_EQ(supportedFocusModesGet, 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_021, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<FlashMode> getSupportedFlashModes = session->GetSupportedFlashModes();
    EXPECT_EQ(getSupportedFlashModes.empty(), false);
    int32_t getSupportedFlashMode = session->GetSupportedFlashModes(getSupportedFlashModes);
    EXPECT_EQ(getSupportedFlashMode, 0);

    FlashMode flashMode = session->GetFlashMode();
    int32_t flashModeGet = session->GetFlashMode(flashMode);
    EXPECT_EQ(flashModeGet, 0);
    int32_t setFlashMode = session->SetFlashMode(flashMode);
    EXPECT_EQ(setFlashMode, 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusPoint & GetFousPoint with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_022, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    Point FocusPoint = {1.0, 2.0};
    session->LockForControl();
    session->SetFocusPoint(FocusPoint);
    session->UnlockForControl();

    session->GetFocusPoint(FocusPoint);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Close();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_023, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->GetFocusMode(), 2);

    session->LockForControl();

    FlashMode flash = FLASH_MODE_ALWAYS_OPEN;
    session->SetFlashMode(flash);
    session->SetFlashMode(flash);

    FocusMode focus = FOCUS_MODE_CONTINUOUS_AUTO;
    session->SetFocusMode(focus);
    session->SetFocusMode(focus);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    session->SetExposureMode(exposure);

    float zoomRatioRange = session->GetZoomRatio();
    session->SetZoomRatio(zoomRatioRange);
    session->SetZoomRatio(zoomRatioRange);

    session->UnlockForControl();

    EXPECT_EQ(session->GetFocusMode(focus), 0);

    cameraManager->GetSupportedOutputCapability(cameras[0], 0);

    VideoStabilizationMode stabilizationMode = MIDDLE;
    session->GetActiveVideoStabilizationMode();
    session->GetActiveVideoStabilizationMode(stabilizationMode);
    session->SetVideoStabilizationMode(stabilizationMode);

    input->Close();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test IsCameraNeedClose & CheckPermission
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsCameraNeedClose & CheckPermission
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_024, TestSize.Level0)
{
    CamRetCode rc1 = HDI::Camera::V1_0::CAMERA_BUSY;
    EXPECT_EQ(HdiToServiceError(rc1), CAMERA_DEVICE_BUSY);
    CamRetCode rc2 = HDI::Camera::V1_0::INVALID_ARGUMENT;
    EXPECT_EQ(HdiToServiceError(rc2), CAMERA_INVALID_ARG);
    CamRetCode rc3 = HDI::Camera::V1_0::CAMERA_CLOSED;
    EXPECT_EQ(HdiToServiceError(rc3), CAMERA_DEVICE_CLOSED);
    CreateMsg(NULL);

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    pid_t pid = IPCSkeleton::GetCallingPid();
    IsCameraNeedClose(callerToken, pid, pid);
    IsCameraNeedClose(123, pid, pid);
    CheckPermission("unittest", 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_025, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);

    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = nullptr;
    sptr<CameraInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<ICameraDeviceServiceCallback> callback1 = new(std::nothrow) CameraDeviceServiceCallback(input);

    camDevice->EnableResult(result);
    camDevice->DisableResult(result);

    int32_t ret = camDevice->OpenDevice();
    EXPECT_EQ(ret, 0);
    camDevice->UpdateSetting(nullptr);
    sptr<ICameraDeviceServiceCallback> callback = nullptr;
    camDevice->SetCallback(callback);
    camDevice->GetSettings();
    camDevice->SetCallback(callback1);
    camDevice->OnError(REQUEST_TIMEOUT, 0) ;
    camDevice->OnError(DEVICE_PREEMPT, 0) ;
    camDevice->OnError(DRIVER_ERROR, 0) ;

    EXPECT_EQ(camDevice->CloseDevice(), 0);
    EXPECT_EQ(camDevice->GetEnabledResults(result), 11);
    EXPECT_EQ(camDevice->CloseDevice(), 0);
    camDevice->~HCameraDevice();
}

/*
 * Feature: Framework
 * Function: Test HStreamRepeat & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamRepeat & HStreamCommon
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_026, TestSize.Level0)
{
    int32_t format = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::string  dumpString ="HStreamRepeat";
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<IStreamRepeatCallback> callback = nullptr;
    sptr<OHOS::IBufferProducer> producer = nullptr;
    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer1 = Surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat =
        new (std::nothrow) HStreamRepeat(nullptr, format, width, height, RepeatStreamType::PREVIEW);

    EXPECT_EQ(streamRepeat->Start(), CAMERA_INVALID_STATE);
    EXPECT_EQ(streamRepeat->SetCallback(callback), CAMERA_INVALID_ARG);
    EXPECT_EQ(streamRepeat->OnFrameError(BUFFER_LOST), 0);
    EXPECT_EQ(streamRepeat->AddDeferredSurface(producer), CAMERA_INVALID_ARG);
    streamRepeat->DumpStreamInfo(dumpString);
    EXPECT_EQ(streamRepeat->AddDeferredSurface(producer1), CAMERA_INVALID_STATE);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata1 = nullptr;
    EXPECT_EQ(streamRepeat->LinkInput(mockStreamOperator, metadata), CAMERA_OK);
    streamRepeat->LinkInput(mockStreamOperator, metadata1);
    mockStreamOperator = nullptr;
    streamRepeat->LinkInput(mockStreamOperator, metadata);
    streamRepeat->DumpStreamInfo(dumpString);
    EXPECT_EQ(streamRepeat->Stop(), CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadata & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamMetadata & HStreamCommon
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_027, TestSize.Level0)
{
    int32_t format = 0;
    std::string  dumpString ="HStreamMetadata";
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, format);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata1 = nullptr;
    streamMetadata->LinkInput(mockStreamOperator, metadata);
    streamMetadata->LinkInput(mockStreamOperator, metadata1);
    mockStreamOperator = nullptr;
    streamMetadata->LinkInput(mockStreamOperator, metadata);
    streamMetadata->Stop();
    streamMetadata->Start();
    streamMetadata->DumpStreamInfo(dumpString);
    streamMetadata->Start();
    streamMetadata->Stop();
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadata & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamMetadata & HStreamCommon
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_028, TestSize.Level0)
{
    int32_t format = 0;
    std::string  dumpString ="HStreamMetadata";
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, format);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    streamMetadata->Start();
    streamMetadata->LinkInput(mockStreamOperator, metadata);
    streamMetadata->Stop();
}

/*
 * Feature: Framework
 * Function: Test HStreamCapture & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamCapture & HStreamCommon
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_029, TestSize.Level0)
{
    int32_t format = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t captureId = 0;
    int32_t frameCount = 0;
    uint64_t timestamp = 0;
    std::string  dumpString ="hstream_capture";
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<IStreamCaptureCallback> callback = nullptr;
    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<OHOS::IBufferProducer> producer1 = nullptr;
    sptr<HStreamCapture> streamCapture= new(std::nothrow) HStreamCapture(producer, format, width, height);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    EXPECT_EQ(streamCapture->SetThumbnail(false, producer1), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetThumbnail(false, producer), CAMERA_OK);
    EXPECT_EQ(streamCapture->SetThumbnail(true, producer1), CAMERA_OK);
    streamCapture->DumpStreamInfo(dumpString);
    EXPECT_EQ(streamCapture->SetThumbnail(true, producer), CAMERA_OK);
    streamCapture->SetRotation(metadata);
    mockStreamOperator = nullptr;
    streamCapture->LinkInput(mockStreamOperator, metadata);
    EXPECT_EQ(streamCapture->Capture(metadata),  CAMERA_INVALID_STATE);
    streamCapture->PrintDebugLog(metadata);
    EXPECT_EQ(streamCapture->SetCallback(callback), CAMERA_INVALID_ARG);
    EXPECT_EQ(streamCapture->OnCaptureEnded(captureId, frameCount), CAMERA_OK);
    EXPECT_EQ(streamCapture->OnCaptureError(captureId, frameCount), CAMERA_OK);
    EXPECT_EQ(streamCapture->OnCaptureError(captureId, BUFFER_LOST), CAMERA_OK);
    EXPECT_EQ(streamCapture->OnFrameShutter(captureId, timestamp), CAMERA_OK);
    streamCapture->DumpStreamInfo(dumpString);

    EXPECT_EQ(streamCapture->Release(),  0);
}

/*
 * Feature: Framework
 * Function: Test HCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraDevice
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_030, TestSize.Level0)
{
    std::vector<int32_t> result;
    result.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    result.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);

    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    std::string cameraId = cameras[0]->GetID();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    uint32_t callerToken1 = 3;
    sptr<HCameraDevice> camDevice = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);
    sptr<HCameraDevice> camDevice1 = new(std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken1);

    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = nullptr;
    sptr<CameraInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<ICameraDeviceServiceCallback> callback1 = new(std::nothrow) CameraDeviceServiceCallback(input);
    camDevice->EnableResult(result);
    camDevice->DisableResult(result);

    int32_t ret = camDevice->OpenDevice();
    EXPECT_EQ(ret, 0);
    camDevice->Open();
    g_getCameraAbilityerror = true;
    camDevice->GetSettings();
    g_openCameraDevicerror = true;
    EXPECT_EQ(camDevice->OpenDevice(), 11);

    camDevice->CloseDevice();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraHostManager with anomalous branch.
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_031, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    std::vector<std::string> cameraIds = {};
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager;
    ASSERT_NE(cameraHostManager, nullptr);

    std::string cameraId = cameras[0]->GetID();
    EXPECT_EQ(cameraHostManager->HCameraHostManager::GetCameras(cameraIds), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameras[0]->GetMetadata();
    EXPECT_EQ(cameraHostManager->HCameraHostManager::GetCameraAbility(cameraId, ability), 2);
    EXPECT_EQ(cameraHostManager->HCameraHostManager::SetFlashlight(cameraId, false), 2);

    cameraId = "HCameraHostManager";

    cameraHostManager->AddCameraDevice(cameraId, nullptr);
    EXPECT_EQ(cameraHostManager->HCameraHostManager::SetFlashlight(cameraId, true), 2);

    cameraHostManager->CloseCameraDevice(cameraId);

    ability = cameras[0]->GetMetadata();
    EXPECT_EQ(cameraHostManager->HCameraHostManager::GetCameraAbility(cameraId, ability), 2);

    EXPECT_EQ(cameraHostManager->HCameraHostManager::GetVersionByCamera(cameraId), 0);

    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> pDevice;
    cameraHostManager->HCameraHostManager::OpenCameraDevice(cameraId, nullptr, pDevice);

    cameraId = cameras[0]->GetID();
    HDI::ServiceManager::V1_0::ServiceStatus status;
    status.deviceClass = DEVICE_CLASS_CAMERA;
    status.serviceName = "distributed_camera_service";
    status.status = HDI::ServiceManager::V1_0::SERVIE_STATUS_START;
    cameraHostManager->HCameraHostManager::OnReceive(status);

    EXPECT_EQ(cameraHostManager->HCameraHostManager::SetFlashlight(cameraId, false), 2);

    std::shared_ptr<MockHCameraHostManager::MockStatusCallback> mockStatusCallback =
    std::make_shared<MockHCameraHostManager::MockStatusCallback>();
    sptr<MockHCameraHostManager> mockCameraHostManager_2 =
        new (std::nothrow) MockHCameraHostManager(mockStatusCallback);
    sptr<HCameraHostManager> cameraHostManager_2 = (sptr<HCameraHostManager> &)mockCameraHostManager_2;

    cameraHostManager_2->AddCameraDevice(cameraId, nullptr);

    input->Close();
}


/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_032, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    Size previewSize = {.width = 1440, .height = 1080};

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    SketchWrapper *sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), previewSize);
    ASSERT_NE(sketchWrapper, nullptr);

    previewOutput->IsSketchSupported();
    int32_t ret = session->BeginConfig();

    previewOutput->AttachSketchSurface(surface);
    previewOutput->StartSketch();
    previewOutput->StopSketch();

    previewOutput->OnSketchStatusChanged(SketchStatus::STOPED);
    previewOutput->IsSketchSupported();

    previewOutput->CreateSketchWrapper(previewSize);
    previewOutput->GetSketchRatio();
    previewOutput->OnSketchStatusChanged(SketchStatus::STOPED);

    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    previewOutput->SetSession(session);
    previewOutput->AttachSketchSurface(surface);
    previewOutput->CreateSketchWrapper(previewSize);
    previewOutput->GetSketchRatio();
    previewOutput->GetDeviceMetadata();
    previewOutput->FindSketchSize();
    previewOutput->OnSketchStatusChanged(SketchStatus::STOPED);
    previewOutput->AttachSketchSurface(surface);
    previewOutput->StartSketch();
    previewOutput->StopSketch();

    ret = session->CommitConfig();
    previewOutput->StartSketch();
    previewOutput->StopSketch();

    previewOutput->sketchWrapper_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), previewSize);
    previewOutput->StartSketch();
    previewOutput->StopSketch();
    previewOutput->AttachSketchSurface(surface);

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_033, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;
    previewOutput->IsSketchSupported();
    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    previewOutput->SetSession(session);
    previewOutput->FindSketchSize();
    previewOutput->EnableSketch(true);
    ret = session->CommitConfig();
    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_034, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    Size previewSize = {.width = 1440, .height = 1080};
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    previewOutput->IsSketchSupported();
    std::string eventString = "test";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);
    eventString = "sketchAvailable";
    previewOutput->sketchWrapper_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), previewSize);
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);
    previewOutput->CameraServerDied(0);
    std::shared_ptr<PreviewStateCallback> previewStateCallback =
        std::make_shared<TestPreviewOutputCallback>("PreviewStateCallback");
    previewOutput->SetCallback(previewStateCallback);
    previewOutput->CameraServerDied(0);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    previewOutput->SetSession(session);
    previewOutput->FindSketchSize();

    eventString = "test";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);
    eventString = "sketchAvailable";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);

    ret = session->CommitConfig();

    eventString = "test";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);
    eventString = "sketchAvailable";
    previewOutput->OnNativeRegisterCallback(eventString);
    previewOutput->OnNativeUnregisterCallback(eventString);

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test sketchWrapper
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test sketchWrapper with anomalous branch
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_035, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    Size previewSize = {.width = 1440, .height = 1080};
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();


    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata = cameras[0]->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);
    int32_t modeName = session->GetFeaturesMode();
    CameraFormat previewFormat = CAMERA_FORMAT_YCBCR_420_888;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> preview = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    SketchWrapper *sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), previewSize);
    ASSERT_NE(sketchWrapper, nullptr);
    std::shared_ptr<PreviewStateCallback> setCallback =
        std::make_shared<TestPreviewOutputCallback>("PreviewStateCallback");
    ASSERT_NE(setCallback, nullptr);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);

    sketchWrapper->Init(deviceMetadata, modeName);
    sketchWrapper->AttachSketchSurface(surface);
    sketchWrapper->UpdateSketchRatio(1.0f);
    sketchWrapper->SetPreviewStateCallback(setCallback);
    sketchWrapper->OnSketchStatusChanged(0);
    sketchWrapper->OnSketchStatusChanged(SketchStatus::STARTED, 0);
    sketchWrapper->OnSketchStatusChanged(SketchStatus::STOPED, 0);
    sketchWrapper->currentSketchStatusData_.sketchRatio = 1.0f;
    sketchWrapper->OnSketchStatusChanged(modeName);
    sketchWrapper->OnSketchStatusChanged(SketchStatus::STOPED, 1.0f);
    sketchWrapper->UpdateSketchReferenceFovRatio(item, SketchWrapper::g_sketchReferenceFovRatioMap_);
    auto sketchReferenceFovRangeVec = std::vector<SketchWrapper::SketchReferenceFovRange>(5);
    SketchWrapper::SketchReferenceFovRange sketchReferenceFovRange =
        {.zoomMin = -1.0f, .zoomMax = -1.0f, .referenceValue = -1.0f};
    sketchReferenceFovRangeVec[0] = sketchReferenceFovRange;
    sketchReferenceFovRange = {.zoomMin = -1.0f, .zoomMax = 100.0f, .referenceValue = -1.0f};
    SketchWrapper::g_sketchReferenceFovRatioMap_[-1] = sketchReferenceFovRangeVec;
    sketchWrapper->GetSketchReferenceFovRatio(-1, -1.0f);
    sketchReferenceFovRangeVec[1] = sketchReferenceFovRange;
    sketchReferenceFovRange = {.zoomMin = 100.0f, .zoomMax = 1.0f, .referenceValue = -1.0f};
    sketchReferenceFovRangeVec[2] = sketchReferenceFovRange;
    sketchReferenceFovRange = {.zoomMin = 100.0f, .zoomMax = 100.0f, .referenceValue = -1.0f};
    sketchReferenceFovRangeVec[3] = sketchReferenceFovRange;
    sketchReferenceFovRange = {.zoomMin = 100.0f, .zoomMax = 200.0f, .referenceValue = -1.0f};
    sketchReferenceFovRangeVec[4] = sketchReferenceFovRange;
    SketchWrapper::g_sketchReferenceFovRatioMap_[100] = sketchReferenceFovRangeVec;
    sketchWrapper->GetSketchReferenceFovRatio(100, -1.0f);
    sketchWrapper->GetSketchReferenceFovRatio(100, 200.0f);
    sketchWrapper->GetSketchReferenceFovRatio(100, 100.0f);
    sketchWrapper->UpdateSketchReferenceFovRatio(item, SketchWrapper::g_sketchReferenceFovRatioMap_);

    ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    previewOutput->SetSession(session);
    ret = session->CommitConfig();
    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test PreviewOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PreviewOutput in ~PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_036, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    Size previewSize = {.width = 1440, .height = 1080};

    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    int32_t ret = session->BeginConfig();
    ret = session->AddInput(input);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();

    previewOutput->~PreviewOutput();
    previewOutput->SetSession(session);
    previewOutput->AttachSketchSurface(surface);
    previewOutput->StartSketch();
    previewOutput->StopSketch();
    previewOutput->sketchWrapper_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), previewSize);
    previewOutput->OnNativeRegisterCallback("sketchAvailable");
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_037, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    Size previewSize = {.width = 1440, .height = 1080};
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata = cameras[0]->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;
    SketchWrapper *sketchWrapper = new (std::nothrow) SketchWrapper(previewOutput->GetStream(), previewSize);
    ASSERT_NE(sketchWrapper, nullptr);

    int32_t ret = session->BeginConfig();
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    item.count = 0;
    previewOutput->OnMetadataChanged(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, item);
    item.count = 1;
    previewOutput->OnMetadataChanged(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, item);
    previewOutput->sketchWrapper_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), previewSize);

    previewOutput->SetSession(nullptr);
    previewOutput->OnSketchStatusChanged(SketchStatus::STOPED);
    previewOutput->OnMetadataChanged(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, item);
    previewOutput->SetSession(session);
    previewOutput->OnMetadataChanged(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, item);
    previewOutput->OnSketchStatusChanged(SketchStatus::STOPED);
    
    ret = session->CommitConfig();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_038, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    Size previewSize = {.width = 1440, .height = 1080};
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata = cameras[0]->GetMetadata();
    ASSERT_NE(deviceMetadata, nullptr);
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    CameraFormat previewFormat = CAMERA_FORMAT_YCBCR_420_888;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> preview = cameraManager->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;
    previewOutput->IsSketchSupported();
    previewOutput->previewProfile_.format_ = CAMERA_FORMAT_YUV_420_SP;
    previewOutput->IsSketchSupported();
    previewOutput->previewProfile_.format_ = CAMERA_FORMAT_JPEG;
    previewOutput->IsSketchSupported();
    
    int32_t ret = session->BeginConfig();
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in PreviewOutput
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_039, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    Size previewSize = {.width = 1440, .height = 1080};

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto previewOutput = (sptr<PreviewOutput>&)preview;

    int32_t ret = session->BeginConfig();
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    previewOutput->SetSession(session);

    previewOutput->AttachSketchSurface(surface);
    previewOutput->StartSketch();
    previewOutput->StopSketch();
    previewOutput->sketchWrapper_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), previewSize);
    previewOutput->AttachSketchSurface(surface);
    previewOutput->AttachSketchSurface(nullptr);
    previewOutput->StartSketch();
    previewOutput->StopSketch();
    previewOutput->OnNativeRegisterCallback("sketchAvailable");

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if captureSession_ == nullptr in CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_040, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto appCallback = std::make_shared<AppSessionCallback>();

    session->BeginConfig();
    session->CameraServerDied(0);
    session->appCallback_ = appCallback;
    session->CameraServerDied(0);
    session->captureSession_ = nullptr;
    session->CameraServerDied(0);
    session->appCallback_ = nullptr;

    session->AddInput(input);
    session->AddOutput(preview);
    session->CommitConfig();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_041, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    session->PrepareZoom();
    session->UnPrepareZoom();

    int32_t ret = session->BeginConfig();
    session->PrepareZoom();
    session->UnPrepareZoom();

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    session->SetSmoothZoom(0, 0);

    ret = session->CommitConfig();
    session->PrepareZoom();
    session->UnPrepareZoom();
    session->SetSmoothZoom(0, 0);

    session->LockForControl();
    session->PrepareZoom();
    session->UnPrepareZoom();
    session->UnlockForControl();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in ~CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_042, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    int32_t ret = session->BeginConfig();
    ret = session->AddInput(input);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    session->~CaptureSession();
    session->PrepareZoom();
    session->UnPrepareZoom();
    session->SetSmoothZoom(0, 0);
    session->SetBeauty(AUTO_TYPE, 0);
    
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionCommited() && !IsSessionConfiged() in CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_043, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    session->SetBeautyValue(AUTO_TYPE, 0);
    
    session->SetBeauty(AUTO_TYPE, 0);
    int32_t ret = session->BeginConfig();
    session->SetBeauty(AUTO_TYPE, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    session->SetBeauty(AUTO_TYPE, 0);

    session->CalculateExposureValue(100.0);

    session->LockForControl();
    session->SetBeauty(AUTO_TYPE, 0);
    session->SetFilter(NONE);
    session->UnlockForControl();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test inputDevice_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test inputDevice_ in CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_044, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    auto macroStatusCallback = std::make_shared<AppMacroStatusCallback>();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();

    session->GetColorEffect();
    session->EnableMacro(true);
    
    int32_t ret = session->BeginConfig();
    
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    session->GetColorEffect();

    ((sptr<CameraInput>&)(session->inputDevice_))->cameraObj_ = nullptr;
    session->GetColorEffect();
    session->IsMacroSupported();
    session->inputDevice_ = nullptr;
    session->GetColorEffect();
    session->IsMacroSupported();
    session->EnableMacro(true);
    
    session->LockForControl();
    session->SetColorEffect(COLOR_EFFECT_NORMAL);
    session->UnlockForControl();

    session->macroStatusCallback_ = macroStatusCallback;
    session->ProcessMacroStatusChange(metadata);

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_045, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    auto hCameraService = new HCameraService(0, true);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();

    hCameraService->UpdateSkinSmoothSetting(metadata, 0);
    hCameraService->UpdateSkinSmoothSetting(metadata, 1);
    hCameraService->UpdateSkinSmoothSetting(nullptr, 1);
    hCameraService->UpdateFaceSlenderSetting(metadata, 0);
    hCameraService->UpdateFaceSlenderSetting(metadata, 1);
    hCameraService->UpdateFaceSlenderSetting(nullptr, 1);
    hCameraService->UpdateSkinToneSetting(metadata, 0);
    hCameraService->UpdateSkinToneSetting(metadata, 1);
    hCameraService->UpdateSkinToneSetting(nullptr, 1);
}


/*
 * Feature: Framework
 * Function: Test !IsSessionConfiged() || input == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionConfiged() || input == nullptr in CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_046, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    sptr<CaptureInput> input1 = nullptr;
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    session->CanAddInput(input);
    session->BeginConfig();
    session->CanAddInput(input);
    session->CanAddInput(input1);
    session->captureSession_ = nullptr;
    session->CanAddInput(input);
    
    session->AddInput(input);
    session->AddOutput(preview);

    session->CommitConfig();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionConfiged() || output == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionConfiged() || output == nullptr in CaptureSession
 */
HWTEST_F(CameraFrameworkUnitTest, camera_fwcoverage_unittest_047, TestSize.Level0)
{
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(cameras[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager, OpenCameraDevice(_, _, _));
    EXPECT_CALL(*mockCameraDevice, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    
    sptr<CaptureSession> session = cameraManager->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    sptr<CaptureOutput> output = nullptr;
    ASSERT_NE(preview, nullptr);

    session->CanAddOutput(preview);
    session->BeginConfig();
    session->CanAddOutput(output);
    preview->~CaptureOutput();
    session->CanAddOutput(preview);
    
    
    session->AddInput(input);
    session->AddOutput(preview);

    session->CommitConfig();

    session->RemoveOutput(preview);
    session->RemoveInput(input);
    input->Release();
    session->Release();
}


} // CameraStandard
} // OHOS
