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

#ifndef OHOS_CAMERA_H_STREAM_REPEAT_H
#define OHOS_CAMERA_H_STREAM_REPEAT_H
#include "icamera_recorder.h"
#define EXPORT_API __attribute__((visibility("default")))

#include <cstdint>
#include <functional>
#include <iostream>
#include <refbase.h>

#include <set>
#include <string>

#include "camera_metadata_info.h"
#include "sp_holder.h"
#include "hstream_common.h"
#include "icamera_ipc_checker.h"
#include "istream_repeat_callback.h"
#include "stream_repeat_stub.h"
#include "v1_0/istream_operator.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::BufferProducerSequenceable;
enum class RepeatStreamType {
    PREVIEW,
    VIDEO,
    SKETCH,
    LIVEPHOTO,
    MOVIE_FILE,
    MOVIE_FILE_CINEMATIC_VIDEO,
    MOVIE_FILE_RAW_VIDEO,
    LIVEPHOTO_XTSTYLE_RAW,
    COMPOSITION,
};

enum class RepeatStreamStatus {
    STOPED,
    STARTED
};
#define CAMERA_ROTATION_TYPE_BASE 4
#define CAMERA_API_VERSION_BASE 14
class EXPORT_API HStreamRepeat : public StreamRepeatStub, public HStreamCommon, public ICameraIpcChecker {
public:
    class StreamRepeatDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit StreamRepeatDeathRecipient(const wptr<HStreamRepeat> &streamRepeat)
            : streamRepeat_(streamRepeat) {}
        virtual ~StreamRepeatDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        wptr<HStreamRepeat> streamRepeat_;
    };

    HStreamRepeat(
        sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height, RepeatStreamType type);
    ~HStreamRepeat();

    int32_t LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_5& streamInfo) override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t Start() override;
    int32_t Start(std::shared_ptr<OHOS::Camera::CameraMetadata> settings, bool isUpdateSeetings = false);
    int32_t Stop() override;
    int32_t SetCallback(const sptr<IStreamRepeatCallback>& callback) override;
    int32_t UnSetCallback() override;

    int32_t OnFrameStarted();
    int32_t OnFrameEnded(int32_t frameCount);
    int32_t OnFrameError(int32_t errorType);
    int32_t OnSketchStatusChanged(SketchStatus status);
    int32_t OnDeferredVideoEnhancementInfo(CaptureEndedInfoExt captureEndedInfo);
    int32_t AddDeferredSurface(const sptr<OHOS::IBufferProducer>& producer) override;
    int32_t RemoveDeferredSurface() override;
    int32_t ForkSketchStreamRepeat(
        int32_t width, int32_t height, sptr<IRemoteObject>& sketchStream, float sketchRatio) override;
    int32_t RemoveSketchStreamRepeat() override;
    int32_t EnableSecure(bool isEnable = false) override;
    int32_t EnableStitching(bool isEnable = false) override;
    int32_t UpdateSketchRatio(float sketchRatio) override;
    sptr<HStreamRepeat> GetSketchStream();
    void SetCompositionStream(sptr<HStreamRepeat> compositionStream);
    sptr<HStreamRepeat> GetCompositionStream();
    RepeatStreamType GetRepeatStreamType();
    void SetPreyProducer(sptr<OHOS::IBufferProducer> preyProducer);
    void SetDepthProducer(sptr<OHOS::IBufferProducer> depthProducer);
    void SetMovieDebugProducer(sptr<OHOS::IBufferProducer> movieDebugProducer);
    void SetRawDebugProducer(sptr<OHOS::IBufferProducer> rawDebugProducer);
    void SetMetaProducer(sptr<OHOS::IBufferProducer> metaProducer);
    void SetMovingPhotoStartCallback(std::function<void()> callback);
    void DumpStreamInfo(CameraInfoDumper& infoDumper) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate) override;
    int32_t SetMirror(bool isEnable) override;
    int32_t GetMirror(bool& isEnable) override;
    int32_t SetBandwidthCompression(bool isEnable) override;
    int32_t SetPreviewRotation(std::string &deviceClass);
    bool SetMirrorForLivePhoto(bool isEnable, int32_t mode);
    void SetStreamTransform(int displayRotation = -1);
    void SetUsedAsPosition(camera_position_enum_t cameraPosition);
    int32_t AttachMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType) override;
    // 兼容老接口，业务可能和SetMetaProducer 重复需要梳理SetMetaProducer逻辑重新整理，videoMetaType 参考 VideoMetaType
    void SetMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType);
    int32_t SetCameraRotation(bool isEnable, int32_t rotation) override;
    int32_t SetCameraApi(uint32_t apiCompatibleVersion) override;
    std::vector<int32_t> GetFrameRateRange();
    int32_t OnFramePaused();
    int32_t OnFrameResumed();
    int32_t GetMaxFps();
    int32_t GetMuxerRotation(int32_t motionRotation);
    void SetRecorderUserMeta(std::string key, std::string val);
    void SetRecorderUserMeta(std::string key, std::vector<uint8_t> val);
    sptr<ICameraRecorder> GetCameraRecorder();
    void SetCameraRecorder(sptr<ICameraRecorder> recorder);
    inline void SetRepeatStreamType(RepeatStreamType type)
    {
        repeatStreamType_ = type;
    }
    int32_t SetOutputSettings(const MovieSettings& movieSettings) override;
    int32_t GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes) override;
    int32_t UnlinkInput() override;
    bool IsLivephotoStream();
    int64_t GetFirstFrameTimestamp();
    int32_t GetDetectedObjectLifecycleBuffer(std::vector<uint8_t>& buffer);
    MovieSettings movieSettings_ {VideoCodecType::VIDEO_ENCODE_TYPE_AVC, 0, false, {0.0, 0.0, 0.0}, false, 30000000};
    int32_t SetCurrentMode(int32_t mode);

private:
    void DataSpaceLimit2Full(StreamInfo_V1_5& streamInfo);
    void SetVideoStreamInfo(StreamInfo_V1_5& streamInfo);
    void SetPreviewStreamInfo(StreamInfo_V1_5& streamInfo);
    void SetPreviewExtendedStreamInfoForSecure(StreamInfo_V1_5& streamInfo);
    void SetPreviewExtendedStreamInfoForStitching(StreamInfo_V1_5& streamInfo);
    void SetPreviewExtendedStreamInfoForComposition(StreamInfo_V1_5& streamInfo);
    void SetMovieFileStreamInfo(StreamInfo_V1_5& streamInfo);
    void SetMovieFileRawVideoStreamInfo(StreamInfo_V1_5& streamInfo);
    void SetSketchStreamInfo(StreamInfo_V1_5& streamInfo);
    void SetCompositionStreamInfo(StreamInfo_V1_5& streamInfo);
    void OpenVideoDfxSwitch(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void StartSketchStream(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateSketchStatus(SketchStatus status);
    void ProcessFixedTransform(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition);
    void ProcessCameraSetRotation(int32_t& sensorOrientation);
    void ProcessVerticalCameraPosition(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition);
    void ProcessFixedDiffDeviceTransform(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition);
    void ProcessCameraPosition(int32_t& streamRotation, camera_position_enum_t& cameraPosition);
    int32_t HandleCameraTransform(int32_t& streamRotation, bool isFrontCamera);
    void UpdateVideoSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings, uint8_t mirror = 0);
    void UpdateFrameRateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateFrameMuteSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                 std::shared_ptr<OHOS::Camera::CameraMetadata> &dynamicSetting);
    void UpdateFrameMechSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                 std::shared_ptr<OHOS::Camera::CameraMetadata> &dynamicSetting);
    void SyncTransformToSketch();
    void UpdateHalRoateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateStreamSupplementaryInfoSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateBandwidthCompressionSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void RemoveStreamOperatorDeathRecipient();
#ifdef NOTIFICATION_ENABLE
    void UpdateBeautySettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void CancelNotification();
    bool IsNeedBeautyNotification();
#endif
    void InitWhiteList();
    bool CheckInWhiteList();
    bool CheckVideoModeForSystemApp(int32_t sceneMode);
    bool IsLive();
    void UpdateLiveSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void SetFrameRate(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);

    RepeatStreamType repeatStreamType_;
    sptr<IStreamRepeatCallback> streamRepeatCallback_;
    std::mutex callbackLock_;
    std::mutex sketchStreamLock_; // Guard sketchStreamRepeat_
    std::mutex compositionStreamLock_;
    std::mutex streamStartStopLock_;
    sptr<HStreamRepeat> sketchStreamRepeat_;
    sptr<HStreamRepeat> compositionStreamRepeat_;
    wptr<HStreamRepeat> parentStreamRepeat_;
    float sketchRatio_ = -1.0f;
    SketchStatus sketchStatus_ = SketchStatus::STOPED;
    RepeatStreamStatus repeatStreamStatus_ = RepeatStreamStatus::STOPED;
    bool mEnableSecure = false;
    bool mEnableStitching = false;
    bool enableMirror_ = false;
    bool enableStreamRotate_ = false;
    bool enableCameraRotation_ = false;
    int32_t setCameraRotation_ = 0;
    uint32_t apiCompatibleVersion_ = 0;
    std::string deviceClass_ = "phone";
    sptr<OHOS::IBufferProducer> metaProducer_;
    std::mutex movingPhotoCallbackLock_;
    std::function<void()> startMovingPhotoCallback_;
    std::vector<int32_t> streamFrameRateRange_ = {};
    std::set<std::string> whiteList_;
    SpHolder<sptr<BufferProducerSequenceable>> metaSurfaceBufferQueueHolder;
    camera_position_enum_t cameraUsedAsPosition_ = OHOS_CAMERA_POSITION_OTHER;
    SpHolder<sptr<OHOS::IBufferProducer>> preyProducer_;
    SpHolder<sptr<OHOS::IBufferProducer>> depthProducer_;
    SpHolder<sptr<OHOS::IBufferProducer>> movieDebugProducer_;
    SpHolder<sptr<OHOS::IBufferProducer>> rawDebugProducer_;
    SpHolder<sptr<ICameraRecorder>> recorder_;
    SpHolder<sptr<StreamRepeatDeathRecipient>> streamRepeatDeathRecipient_;
    bool enableBandwidthCompression_ = false;
    int32_t currentMode_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_REPEAT_H
