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
#define EXPORT_API __attribute__((visibility("default")))

#include <cstdint>
#include <functional>
#include <iostream>
#include <refbase.h>

#include "camera_metadata_info.h"
#include "hstream_common.h"
#include "stream_repeat_stub.h"
#include "istream_repeat_callback.h"
#include "v1_0/istream_operator.h"
#include "icamera_ipc_checker.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::BufferProducerSequenceable;
enum class RepeatStreamType {
    PREVIEW,
    VIDEO,
    SKETCH,
    LIVEPHOTO
};

enum class RepeatStreamStatus {
    STOPED,
    STARTED
};
#define CAMERA_API_VERSION_BASE 14
class EXPORT_API HStreamRepeat : public StreamRepeatStub, public HStreamCommon, public ICameraIpcChecker {
public:
    HStreamRepeat(
        sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height, RepeatStreamType type);
    ~HStreamRepeat();

    int32_t LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_1& streamInfo) override;
    void SetVideoStreamInfo(StreamInfo_V1_1& streamInfo);
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
    int32_t ForkSketchStreamRepeat(
        int32_t width, int32_t height, sptr<IRemoteObject>& sketchStream, float sketchRatio) override;
    int32_t RemoveSketchStreamRepeat() override;
    int32_t EnableSecure(bool isEnable = false) override;
    int32_t UpdateSketchRatio(float sketchRatio) override;
    sptr<HStreamRepeat> GetSketchStream();
    RepeatStreamType GetRepeatStreamType();
    void SetMetaProducer(sptr<OHOS::IBufferProducer> metaProducer);
    void SetMovingPhotoStartCallback(std::function<void()> callback);
    void DumpStreamInfo(CameraInfoDumper& infoDumper) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate) override;
    int32_t SetMirror(bool isEnable) override;
    int32_t GetMirror(bool& isEnable) override;
    bool SetMirrorForLivePhoto(bool isEnable, int32_t mode);
    int32_t SetPreviewRotation(std::string &deviceClass);
    void SetStreamTransform(int disPlayRotation = -1);
    void SetUsedAsPosition(camera_position_enum_t cameraPosition);
    int32_t AttachMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType) override;
    int32_t SetCameraRotation(bool isEnable, int32_t rotation) override;
    int32_t SetCameraApi(uint32_t apiCompatibleVersion) override;
    std::vector<int32_t> GetFrameRateRange();

private:
    void OpenVideoDfxSwitch(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void StartSketchStream(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateSketchStatus(SketchStatus status);
    void ProcessVerticalCameraPosition(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition);
    int32_t HandleCameraTransform(int32_t& sensorOrientation, bool isFrontCamera);
    void ApplyTransformBasedOnRotation(int32_t streamRotation,
        const sptr<OHOS::IBufferProducer>& producer, bool isFrontCamera);
    void ProcessFixedTransform(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition);
    void ProcessFixedDiffDeviceTransform(camera_position_enum_t& cameraPosition);
    void ProcessCameraPosition(int32_t& streamRotation, camera_position_enum_t& cameraPosition);
    void ProcessCameraSetRotation(int32_t& streamRotation, camera_position_enum_t& cameraPosition);
    void UpdateVideoSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings, uint8_t mirror = 0);
    void UpdateFrameRateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateFrameMuteSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                 std::shared_ptr<OHOS::Camera::CameraMetadata> &dynamicSetting);
    void SyncTransformToSketch();
    void UpdateHalRoateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
#ifdef NOTIFICATION_ENABLE
    void UpdateBeautySettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void CancelNotification();
    bool IsNeedBeautyNotification();
#endif

    RepeatStreamType repeatStreamType_;
    sptr<IStreamRepeatCallback> streamRepeatCallback_;
    std::mutex callbackLock_;
    std::mutex sketchStreamLock_; // Guard sketchStreamRepeat_
    std::mutex streamStartStopLock_;
    sptr<HStreamRepeat> sketchStreamRepeat_;
    wptr<HStreamRepeat> parentStreamRepeat_;
    float sketchRatio_ = -1.0f;
    SketchStatus sketchStatus_ = SketchStatus::STOPED;
    RepeatStreamStatus repeatStreamStatus_ = RepeatStreamStatus::STOPED;
    bool mEnableSecure = false;
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
    sptr<BufferProducerSequenceable> metaSurfaceBufferQueue_;
    camera_position_enum_t cameraUsedAsPosition_ = OHOS_CAMERA_POSITION_OTHER;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_REPEAT_H
