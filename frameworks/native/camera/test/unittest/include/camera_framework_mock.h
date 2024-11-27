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

#ifndef CAMERA_FRAMEWORK_MOCK_H
#define CAMERA_FRAMEWORK_MOCK_H

#include "camera_framework_utils.h"
#include "gtest/gtest.h"
#include "hcamera_service.h"
#include "portrait_session.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "camera_log.h"
#include "camera_manager.h"
#include "gmock/gmock.h"
#include "slow_motion_session.h"

using ::testing::A;
using ::testing::Return;
using ::testing::Mock;
using ::testing::InSequence;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
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
            static const int32_t ABILITY_FINISH = -1;
            vector.emplace_back(cameraFormat);
            vector.emplace_back(streamWidth);
            vector.emplace_back(streamHeight);
            vector.emplace_back(fixedFrameRate);
            vector.emplace_back(minFrameRate);
            vector.emplace_back(maxFrameRate);
            vector.insert(vector.end(), streamAbilities.begin(), streamAbilities.end());
            vector.emplace_back(ABILITY_FINISH);
        }
    };

    struct StreamConfig {
        int32_t streamType;
        std::vector<StreamFormatConfig> streamFormatConfigs;

        void IntoVector(std::vector<int32_t>& vector) const
        {
            static const int32_t STREAM_FINISH = -1;
            vector.emplace_back(streamType);
            for (auto& formatConfig : streamFormatConfigs) {
                formatConfig.IntoVector(vector);
            }
            vector.emplace_back(STREAM_FINISH);
        }
    };

    struct ModeConfig {
        int32_t modeName;
        std::vector<StreamConfig> streams = {};
        void IntoVector(std::vector<int32_t>& vector) const
        {
            static const int32_t MODE_FINISH = -1;
            vector.emplace_back(modeName);
            for (auto& stream : streams) {
                stream.IntoVector(vector);
            }
            vector.emplace_back(MODE_FINISH);
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

    const ModeConfig DEFAULT_MODE_CONFIG = { CameraFrameworkUtils::DEFAULT_MODE, {
        { CameraFrameworkUtils::PREVIEW_STREAM, { { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0 } } },
        { CameraFrameworkUtils::VIDEO_STREAM, { { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0 } } },
        { CameraFrameworkUtils::PHOTO_STREAM, { { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0 } } } } };

    const ModeConfig PHOTO_MODE_CONFIG = { CameraFrameworkUtils::PHOTO_MODE,
        {
            { CameraFrameworkUtils::PREVIEW_STREAM,
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
            { CameraFrameworkUtils::PHOTO_STREAM,
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

    const ModeConfig VIDEO_MODE_CONFIG = { CameraFrameworkUtils::VIDEO_MODE,
        {
            { CameraFrameworkUtils::PREVIEW_STREAM,
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
            { CameraFrameworkUtils::VIDEO_STREAM,
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
            { CameraFrameworkUtils::PHOTO_STREAM,
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

    const ModeConfig PORTRAIT_MODE_CONFIG = { CameraFrameworkUtils::PORTRAIT_MODE, {
        { CameraFrameworkUtils::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } },
        { CameraFrameworkUtils::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } },
        { CameraFrameworkUtils::PHOTO_STREAM, {
            { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } } } };

    const ModeConfig NIGHT_MODE_CONFIG = { CameraFrameworkUtils::NIGHT_MODE, {
        { CameraFrameworkUtils::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } },
        { CameraFrameworkUtils::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } },
        { CameraFrameworkUtils::PHOTO_STREAM, {
            { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } } } };

    const ModeConfig SCAN_MODE_CONFIG = { CameraFrameworkUtils::SCAN_MODE, {
        { CameraFrameworkUtils::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 480, 0, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } },
        { CameraFrameworkUtils::VIDEO_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 640, 360, 30, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR } } } },
        { CameraFrameworkUtils::PHOTO_STREAM, {
            { OHOS_CAMERA_FORMAT_JPEG, 1280, 960, 0, 0, 0, {
                CameraFrameworkUtils::ABILITY_ID_ONE,
                CameraFrameworkUtils::ABILITY_ID_TWO,
                CameraFrameworkUtils::ABILITY_ID_THREE,
                CameraFrameworkUtils::ABILITY_ID_FOUR, } } } } } };

    const ModeConfig SLOW_MODE_CONFIG = { CameraFrameworkUtils::SLOW_MODE, {
        { CameraFrameworkUtils::PREVIEW_STREAM, {
            { OHOS_CAMERA_FORMAT_YCRCB_420_SP, 1920, 1080, 0, 0, 0} } },
        { CameraFrameworkUtils::VIDEO_STREAM, {
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

    explicit MockHCameraHostManager(std::shared_ptr<StatusCallback> statusCallback)
        : HCameraHostManager(statusCallback)
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
                0, 0, CameraFrameworkUtils::PREVIEW_DEFAULT_WIDTH, CameraFrameworkUtils::PREVIEW_DEFAULT_HEIGHT
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

class MockCameraManager : public CameraManager {
public:
    MOCK_METHOD0(GetIsFoldable, bool());
    MOCK_METHOD0(GetFoldStatus, FoldStatus());
    ~MockCameraManager() {}
};

class FakeHCameraService : public HCameraService {
public:
    explicit FakeHCameraService(sptr<HCameraHostManager> hostManager) : HCameraService(hostManager)
    {
        SetServiceStatus(CameraServiceStatus::SERVICE_READY);
        ON_CALL(*this, SetMuteModeByDataShareHelper(_)).WillByDefault(Return(CAMERA_ALLOC_ERROR));
    }
    ~FakeHCameraService() {}
    MOCK_METHOD1(SetMuteModeByDataShareHelper, int32_t(bool muteMode));
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

class TestSlowMotionStateCallback : public SlowMotionStateCallback {
public:
    void OnSlowMotionState(const SlowMotionState state)
    {
        MEDIA_INFO_LOG("TestSlowMotionStateCallback OnSlowMotionState.");
    }
};

} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_MOCK_H
