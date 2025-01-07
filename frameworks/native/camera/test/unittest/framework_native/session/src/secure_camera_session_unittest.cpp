/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "secure_camera_session_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "istream_repeat_callback.h"
#include "v1_0/istream_operator.h"
#include "hcamera_host_manager.h"
#include "hcamera_service.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

bool g_mockFlagWithoutAbt = false;
bool g_getCameraAbilityerror = false;
bool g_openCameraDevicerror = false;
int g_num = 0;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

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
        ON_CALL(*this, IsStreamsSupported(_, _, A<const std::shared_ptr<OHOS::HDI::Camera::V1_0::StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported(_, _, A<const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo> &>(), _))
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
        const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& streamInfos));
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
        const std::shared_ptr<OHOS::HDI::Camera::V1_0::StreamInfo> &info, StreamSupportType &type));
    MOCK_METHOD4(IsStreamsSupported, int32_t(OperationMode mode, const std::vector<uint8_t>& modeSetting,
        const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& infos, StreamSupportType& type));
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
    struct StreamFormatConfig {
        camera_format_t cameraFormat;
        int32_t streamWidth;
        int32_t streamHeight;
        int32_t fixedFrameRate;
        int32_t minFrameRate;
        int32_t maxFrameRate;
        std::vector<int32_t> streamAbilities = {};
        void IntoVector(std::vector<int32_t>& vector) const
        {
            static const int32_t abilityFinish = -1;
            vector.emplace_back(cameraFormat);
            vector.emplace_back(streamWidth);
            vector.emplace_back(streamHeight);
            vector.emplace_back(fixedFrameRate);
            vector.emplace_back(minFrameRate);
            vector.emplace_back(maxFrameRate);
            vector.insert(vector.end(), streamAbilities.begin(), streamAbilities.end());
            vector.emplace_back(abilityFinish);
        }
    };

    struct StreamConfig {
        int32_t streamType;
        std::vector<StreamFormatConfig> streamFormatConfigs;

        void IntoVector(std::vector<int32_t>& vector) const
        {
            static const int32_t streamFinish = -1;
            vector.emplace_back(streamType);
            for (auto& formatConfig : streamFormatConfigs) {
                formatConfig.IntoVector(vector);
            }
            vector.emplace_back(streamFinish);
        }
    };

    struct ModeConfig {
        int32_t modeName;
        std::vector<StreamConfig> streams = {};
        void IntoVector(std::vector<int32_t>& vector) const
        {
            static const int32_t modeFinish = -1;
            vector.emplace_back(modeName);
            for (auto& stream : streams) {
                stream.IntoVector(vector);
            }
            vector.emplace_back(modeFinish);
        }
    };

    struct ModeConfigs {
        std::vector<ModeConfig> configs = {};
        explicit ModeConfigs(std::vector<ModeConfig> modeConfigs) : configs(std::move(modeConfigs)) {}

        std::vector<uint8_t> GetModes() const
        {
            std::vector<uint8_t> modes = {};
            for (auto& config : configs) {
                modes.emplace_back(config.modeName);
            }
            return modes;
        }

        std::vector<int32_t> GetDatas() const
        {
            std::vector<int32_t> datas = {};
            for (auto& config : configs) {
                config.IntoVector(datas);
            }
            return datas;
        }
    };

    const ModeConfig DEFAULT_MODE_CONFIG = { SecureCameraSessionUnitTest::DEFAULT_MODE, {
        { SecureCameraSessionUnitTest::PREVIEW_STREAM, { { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 } } },
        { SecureCameraSessionUnitTest::VIDEO_STREAM, { { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0 } } },
        { SecureCameraSessionUnitTest::PHOTO_STREAM, { { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0 } } } } };

    const ModeConfig PHOTO_MODE_CONFIG = { SecureCameraSessionUnitTest::PHOTO_MODE,
        {
            { SecureCameraSessionUnitTest::PREVIEW_STREAM,
                {
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 720, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1080, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1440, 1440, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 960, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1440, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1440, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1280, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 2560, 1440, 0, 0, 0 },
                } },
            { SecureCameraSessionUnitTest::PHOTO_STREAM,
                {
                    { OHOS_CAMERA_FORMAT_JPEG, 720, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 1080, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 2160, 2160, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 3072, 3072, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_JPEG, 960, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 1440, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 2880, 2160, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 4096, 3072, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_JPEG, 1280, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 1920, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 3840, 2160, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 4096, 2304, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0 },
                } },
        } };

    const ModeConfig VIDEO_MODE_CONFIG = { SecureCameraSessionUnitTest::VIDEO_MODE,
        {
            { SecureCameraSessionUnitTest::PREVIEW_STREAM,
                {
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 720, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1080, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_P010, 1080, 1080, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 960, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1440, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_P010, 1440, 1080, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1280, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_YCRCB_P010, 1920, 1080, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 },
                } },
            { SecureCameraSessionUnitTest::VIDEO_STREAM,
                {
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 720, 720, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1080, 1080, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 2160, 2160, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_P010, 2160, 2160, 30, 24, 30 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 960, 720, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1440, 1080, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 2880, 2160, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_P010, 2880, 2160, 30, 24, 30 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1280, 720, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1080, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 3840, 2160, 30, 24, 30 },
                    { OHOS_CAMERA_FORMAT_YCRCB_P010, 3840, 2160, 30, 24, 30 },

                    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 24, 30 },
                } },
            { SecureCameraSessionUnitTest::PHOTO_STREAM,
                {
                    { OHOS_CAMERA_FORMAT_JPEG, 2304, 2304, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 3072, 2304, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 4096, 2304, 0, 0, 0 },

                    { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 1280, 720, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 1920, 1080, 0, 0, 0 },
                    { OHOS_CAMERA_FORMAT_JPEG, 3840, 2160, 0, 0, 0 },
                } },
        } };

    const ModeConfig PORTRAIT_MODE_CONFIG = { SecureCameraSessionUnitTest::PORTRAIT_MODE, {
        { SecureCameraSessionUnitTest::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } },
        { SecureCameraSessionUnitTest::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } },
        { SecureCameraSessionUnitTest::PHOTO_STREAM, {
            { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } } } };

    const ModeConfig NIGHT_MODE_CONFIG = { SecureCameraSessionUnitTest::NIGHT_MODE, {
        { SecureCameraSessionUnitTest::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } },
        { SecureCameraSessionUnitTest::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } },
        { SecureCameraSessionUnitTest::PHOTO_STREAM, {
            { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } } } };

    const ModeConfig SCAN_MODE_CONFIG = { SecureCameraSessionUnitTest::SCAN_MODE, {
        { SecureCameraSessionUnitTest::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } },
        { SecureCameraSessionUnitTest::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR } } } },
        { SecureCameraSessionUnitTest::PHOTO_STREAM, {
            { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0, {
                SecureCameraSessionUnitTest::ABILITY_ID_ONE,
                SecureCameraSessionUnitTest::ABILITY_ID_TWO,
                SecureCameraSessionUnitTest::ABILITY_ID_THREE,
                SecureCameraSessionUnitTest::ABILITY_ID_FOUR, } } } } } };

    const ModeConfig SLOW_MODE_CONFIG = { SecureCameraSessionUnitTest::SLOW_MODE, {
        { SecureCameraSessionUnitTest::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1080, 0, 0, 0} } },
        { SecureCameraSessionUnitTest::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1080, 0, 0, 0} } }}};

    const ModeConfigs ABILITY_MODE_CONFIGS = ModeConfigs(std::vector<ModeConfig> { DEFAULT_MODE_CONFIG,
        PHOTO_MODE_CONFIG, VIDEO_MODE_CONFIG, PORTRAIT_MODE_CONFIG, NIGHT_MODE_CONFIG, SCAN_MODE_CONFIG,
        SLOW_MODE_CONFIG });

    uint8_t filterAbility[2] = {0, 1};
    int32_t filterControl[2] = {0, 1};
    uint8_t beautyAbility[5] = {OHOS_CAMERA_BEAUTY_TYPE_OFF, OHOS_CAMERA_BEAUTY_TYPE_AUTO,
                                OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER,
                                OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE};
    uint8_t faceSlenderBeautyRange[2] = {2, 3};
    int32_t faceSlenderBeautyControl[2] = {2, 3};
    int32_t effectAbility[2] = {0, 1};
    int32_t effectControl[2] = {0, 1};
    int32_t photoFormats[2] = {OHOS_CAMERA_FORMAT_YCRCB_420_SP, OHOS_CAMERA_FORMAT_JPEG};
    class MockStatusCallback : public StatusCallback {
    public:
        void OnCameraStatus(const std::string& cameraId, CameraStatus status, CallbackInvoker invoker) override
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
            auto streamsInfo = ABILITY_MODE_CONFIGS.GetDatas();
            ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
            ability->addEntry(
                OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, streamsInfo.data(), streamsInfo.size());

            ability->addEntry(
                OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streamsInfo.data(), streamsInfo.size());

            if (g_mockFlagWithoutAbt) {
                return CAMERA_OK;
            }
            if (g_getCameraAbilityerror) {
                g_getCameraAbilityerror = false;
                return CAMERA_ALLOC_ERROR;
            }

            int32_t compensationRange[2] = {0, 0};
            ability->addEntry(OHOS_ABILITY_AE_COMPENSATION_RANGE, compensationRange,
                              sizeof(compensationRange) / sizeof(compensationRange[0]));
            float focalLength = 1.5;
            ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, sizeof(float));

            int32_t sensorOrientation = 0;
            ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, sizeof(int32_t));

            int32_t cameraPosition = 0;
            ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));

            const camera_rational_t aeCompensationStep[] = {{0, 1}};
            ability->addEntry(OHOS_ABILITY_AE_COMPENSATION_STEP, &aeCompensationStep,
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
                0, 0, SecureCameraSessionUnitTest::PREVIEW_DEFAULT_WIDTH,
                SecureCameraSessionUnitTest::PREVIEW_DEFAULT_HEIGHT
            };
            ability->addEntry(OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &activeArraySize, sizeof(int32_t));

            uint8_t videoStabilizationMode = OHOS_CAMERA_VIDEO_STABILIZATION_OFF;
            ability->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabilizationMode, sizeof(uint8_t));

            uint8_t faceDetectMode = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
            ability->addEntry(OHOS_STATISTICS_FACE_DETECT_MODE, &faceDetectMode, sizeof(uint8_t));

            uint8_t type = 5;
            ability->addEntry(OHOS_ABILITY_CAMERA_TYPE, &type, sizeof(uint8_t));
            uint8_t value_u8 = 0;
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

            std::vector<uint8_t> modes = ABILITY_MODE_CONFIGS.GetModes();
            ability->addEntry(OHOS_ABILITY_CAMERA_MODES, modes.data(), modes.size());

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
            ability->addEntry(OHOS_STREAM_AVAILABLE_FORMATS, &photoFormats,
                              sizeof(photoFormats) / sizeof(photoFormats[0]));
                        return CAMERA_OK;
        });
        ON_CALL(*this, OpenCameraDevice).WillByDefault([this](std::string &cameraId,
                                                            const sptr<ICameraDeviceCallback> &callback,
                                                            sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> &pDevice,
                                                            bool isEnableSecCam) {
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
    MOCK_METHOD4(OpenCameraDevice, int32_t(std::string &cameraId,
        const sptr<ICameraDeviceCallback> &callback, sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> &pDevice,
        bool isEnableSecCam));
    sptr<MockCameraDevice> cameraDevice;
};

class FakeHCameraService : public HCameraService {
public:
    explicit FakeHCameraService(sptr<HCameraHostManager> hostManager) : HCameraService(hostManager)
    {
        SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    }
    ~FakeHCameraService() {}
};

class FakeCameraManager : public CameraManager {
public:
    explicit FakeCameraManager(sptr<HCameraService> service) : CameraManager(service) {}
    ~FakeCameraManager() {}
};

sptr<CaptureOutput> SecureCameraSessionUnitTest::CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[1],
        static_cast<int32_t>(SceneMode::SECURE));
    if (!outputCapability) {
        return nullptr;
    }

    previewProfile_ = outputCapability->GetPreviewProfiles();
    if (previewProfile_.empty()) {
        return nullptr;
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
}

void SecureCameraSessionUnitTest::SetUpTestCase(void) {}

void SecureCameraSessionUnitTest::TearDownTestCase(void) {}

void SecureCameraSessionUnitTest::SetUp()
{
    NativeAuthorization();
    mockCameraHostManager_ = new MockHCameraHostManager(nullptr);
    mockCameraDevice_ = mockCameraHostManager_->cameraDevice;
    cameraManager_ = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager_));
}

void SecureCameraSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("SecureCameraSessionUnitTest::TearDown");
}

void SecureCameraSessionUnitTest::NativeAuthorization()
{
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
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    MEDIA_DEBUG_LOG("SecureCameraSessionUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
* Feature: Framework
* Function: Test normal branch that is add secure output flag
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test normal branch that is add secure output flag
*/
HWTEST_F(SecureCameraSessionUnitTest, secure_camera_session_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);

            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(true, &secureSeqId);
            EXPECT_EQ(intResult, 0);
            EXPECT_NE(secureSeqId, 0);

            sptr<CaptureOutput> preview = CreatePreviewOutput();
            ASSERT_NE(preview, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
            ASSERT_NE(info, nullptr);
            info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SECURE), previewProfile_);
            EXPECT_EQ(secureSession->AddOutput(preview), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview), 0);
            EXPECT_EQ(secureSession->CommitConfig(), 0);

            secureSession->Release();
            EXPECT_EQ(camInput->Close(), 0);
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test normal branch that is add secure output flag
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test normal branch that is add secure output flag
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            EXPECT_NE(secureSeqId, 0);

            sptr<CaptureOutput> preview = CreatePreviewOutput();
            ASSERT_NE(preview, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
            ASSERT_NE(info, nullptr);
            info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SECURE), previewProfile_);
            EXPECT_EQ(secureSession->AddOutput(preview), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview), 0);
            EXPECT_EQ(secureSession->CommitConfig(), 0);
            secureSession->Release();
            EXPECT_EQ(camInput->Close(), 0);
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that is add secure output flag twice
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that is add secure output flag twice
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            EXPECT_NE(secureSeqId, 0);

            sptr<CaptureOutput> preview1 = CreatePreviewOutput();
            ASSERT_NE(preview1, nullptr);
            sptr<CaptureOutput> preview2 = CreatePreviewOutput();
            ASSERT_NE(preview2, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            EXPECT_EQ(secureSession->AddOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddOutput(preview2), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview2), CAMERA_OPERATION_NOT_ALLOWED);
            EXPECT_EQ(secureSession->CommitConfig(), 0);
            secureSession->Release();
            EXPECT_EQ(camInput->Close(), 0);
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that is add secure output flag twice
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that is add secure output flag twice
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            EXPECT_NE(secureSeqId, 0);

            sptr<CaptureOutput> preview1 = CreatePreviewOutput();
            ASSERT_NE(preview1, nullptr);
            sptr<CaptureOutput> preview2 = CreatePreviewOutput();
            ASSERT_NE(preview2, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
            ASSERT_NE(info, nullptr);
            info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SECURE), previewProfile_);
            EXPECT_EQ(secureSession->AddOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddOutput(preview2), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview2), CAMERA_OPERATION_NOT_ALLOWED);
            EXPECT_EQ(secureSession->CommitConfig(), 0);
            secureSession->Release();
            EXPECT_EQ(camInput->Close(), 0);
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that secure output is added after commiting
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that secure output is added after commiting
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            EXPECT_NE(secureSeqId, 0);

            sptr<CaptureOutput> preview = CreatePreviewOutput();
            ASSERT_NE(preview, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
            ASSERT_NE(info, nullptr);
            info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SECURE), previewProfile_);
            EXPECT_EQ(secureSession->AddOutput(preview), 0);
            EXPECT_EQ(secureSession->CommitConfig(), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview), CAMERA_OPERATION_NOT_ALLOWED);
            secureSession->Release();
            EXPECT_EQ(camInput->Close(), 0);
            break;
        }
    }
}

/*
 * Feature: Framework
 * Function: Test SecureCameraSession AddSecureOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddSecureOutput for just call.
 */
HWTEST_F(SecureCameraSessionUnitTest, secure_camera_session_function_unittest_001, TestSize.Level0)
{
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
    ASSERT_NE(captureSession, nullptr);
    sptr<SecureCameraSession> secureCameraSession =
        static_cast<SecureCameraSession*>(captureSession.GetRefPtr());
    ASSERT_NE(secureCameraSession, nullptr);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(secureCameraSession->AddSecureOutput(output), CAMERA_OPERATION_NOT_ALLOWED);
}
}
}