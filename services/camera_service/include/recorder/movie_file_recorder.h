/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef MOVIE_FILE_RECORDER_H
#define MOVIE_FILE_RECORDER_H

#include "camera_sensor_plugin.h"
#include "camera_server_photo_proxy.h"
#include "camera_recorder_stub.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "photo_asset_proxy.h"
#include "surface.h"
#include "sp_holder.h"
#include "recorder_engine_proxy.h"

namespace OHOS {
namespace CameraStandard {

class EXPORT_API MovieFileRecorder : public CameraRecorderStub, public ICameraIpcChecker {
public:
    MovieFileRecorder();
    virtual ~MovieFileRecorder();

    // implement ICameraRecorder
    int32_t Prepare() override;
    int32_t Start() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Stop() override;
    int32_t Stop(bool needWait) override;
    int32_t Reset() override;
    int32_t Release() override;
    int32_t SetRotation(int32_t rotation) override;
    int32_t SetOutputSettings(const MovieSettings& movieSettings) override;
    int32_t SetRecorderCallback(const sptr<ICameraRecorderCallback>& callback) override;
    int32_t GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters) override;
    int32_t SetVideoFilter(const std::string& filter, const std::string& filterParam) override;
    int32_t EnableMirror(bool isEnable) override;
    int32_t SetUserMeta(const std::string& key, const std::string& val) override;
    int32_t SetUserMeta(const std::string& key, const std::vector<uint8_t>& val) override;
    int32_t UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType) override;
    int32_t EnableVirtualAperture(bool isVirtualApertureEnabled) override;
    int32_t GetFirstFrameTimestamp(int64_t& firstFrameTimeStamp) override;
    int32_t SetMetadataStream(const sptr<IStreamMetadata>& stream) override;
    int32_t GetDetectedObjectLifecycleBuffer(std::vector<uint8_t>& buffer) override;
    // implement ICameraIpcChecker
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    // public APIs for HCaptureSession
    int32_t Init();
    void SetMovieFrameSize(int32_t width, int32_t height);
    void SetRawFrameSize(int32_t width, int32_t height);
    void SetMovieStream(sptr<HStreamRepeat> stream);
    void SetRawStream(sptr<HStreamRepeat> stream);
    sptr<Surface> GetRawSurface();
    sptr<Surface> GetDepthSurface();
    sptr<Surface> GetPreySurface();
    sptr<Surface> GetMetaSurface();
    sptr<Surface> GetMovieDebugSurface();
    sptr<Surface> GetRawDebugSurface();
    sptr<Surface> GetImageEffectSurface();
    // for recorder engine
    int32_t GetMuxerRotation();
    void SetFirstFrameTimestamp(int64_t firstTimestamp);
    void EnableDetectedObjectLifecycleReport(bool isEnable, int64_t timestamp);
    bool IsMovieStreamHdr();
private:

    int32_t StartStreams();
    int32_t StopStreams();
    int32_t ReleaseStreams();

    void RegisterSensorRotationCallback();
    void UnregisterSensorRotationCallback();
    static void SensorRotationCallbackImpl(const OHOS::Rosen::MotionSensorEvent &motionData);
    bool IsHdr(ColorSpace colorSpace);

    bool isMirrorEnabled_ { false };
    
    SpHolder<sptr<HStreamRepeat>> movieStream_;
    SpHolder<sptr<HStreamRepeat>> rawStream_;
    SpHolder<sptr<HStreamMetadata>> metadataStream_;
    SpHolder<sptr<ICameraRecorderCallback>> appCallback_;
    
    EngineMovieSettings movieSettings_ {
        EngineVideoCodecType::VIDEO_ENCODE_TYPE_AVC, 0, false, {0.0, 0.0, 0.0}, false, 30000000};
    SpHolder<std::shared_ptr<RecorderEngineProxy>> recorderEngineProxy_;
    sptr<RecorderIntf> recorderProxy_;
};
}
}
#endif
