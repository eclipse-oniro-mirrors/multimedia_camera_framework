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

#ifndef OHOS_CAMERA_H_STREAM_OPERATOR_H
#define OHOS_CAMERA_H_STREAM_OPERATOR_H
#define EXPORT_API __attribute__((visibility("default")))

#include <atomic>
#include <cstdint>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <refbase.h>
#include <unordered_map>
#include <unordered_set>
#include "camera_util.h"
#include "fixed_size_list.h"
#include "hcamera_device.h"
#include "hcapture_session_stub.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "camera_photo_proxy.h"
#include "moving_photo/moving_photo_surface_wrapper.h"
#include "surface.h"
#include "v1_0/istream_operator.h"
#include "v1_1/istream_operator.h"
#include "v1_2/istream_operator.h"
#include "v1_3/istream_operator_callback.h"
#include "hcamera_restore_param.h"
#include "iconsumer_surface.h"
#include "blocking_queue.h"
#include "audio_capturer.h"
#include "audio_info.h"
#include "avcodec_task_manager.h"
#include "moving_photo_video_cache.h"
#include "drain_manager.h"
#include "audio_capturer_session.h"
#include "safe_map.h"
#ifdef CAMERA_USE_SENSOR
#include "sensor_agent.h"
#include "sensor_agent_type.h"
#endif
namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::CaptureEndedInfo;
using OHOS::HDI::Camera::V1_0::CaptureErrorInfo;
using namespace AudioStandard;
using namespace std::chrono;
using namespace DeferredProcessing;
using namespace Media;
class PermissionStatusChangeCb;
class CameraUseStateChangeCb;
class DisplayRotationListener;
class CameraServerPhotoProxy;

class StreamContainer {
public:
    StreamContainer() {};
    virtual ~StreamContainer() = default;

    bool AddStream(sptr<HStreamCommon> stream);
    bool RemoveStream(sptr<HStreamCommon> stream);
    sptr<HStreamCommon> GetStream(int32_t streamId);
    sptr<HStreamCommon> GetHdiStream(int32_t streamId);
    void Clear();
    size_t Size();

    std::list<sptr<HStreamCommon>> GetStreams(const StreamType streamType);
    std::list<sptr<HStreamCommon>> GetAllStreams();

private:
    std::mutex streamsLock_;
    std::map<const StreamType, std::list<sptr<HStreamCommon>>> streams_;
};

class SessionDrainImageCallback;
using MetaElementType = std::pair<int64_t, sptr<SurfaceBuffer>>;
class MovingPhotoListener : public MovingPhotoSurfaceWrapper::SurfaceBufferListener {
public:
    explicit MovingPhotoListener(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper, sptr<Surface> metaSurface,
        shared_ptr<FixedSizeList<MetaElementType>> metaCache, uint32_t preCacheFrameCount,
        uint32_t postCacheFrameCount);
    ~MovingPhotoListener() override;
    void OnBufferArrival(sptr<SurfaceBuffer> buffer, int64_t timestamp, GraphicTransformType transform) override;
    void DrainOutImage(sptr<SessionDrainImageCallback> drainImageCallback);
    void RemoveDrainImageManager(sptr<SessionDrainImageCallback> drainImageCallback);
    void StopDrainOut();
    void ClearCache(uint64_t timestamp);
    void SetClearFlag();

private:
    sptr<MovingPhotoSurfaceWrapper> movingPhotoSurfaceWrapper_;
    sptr<Surface> metaSurface_;
    shared_ptr<FixedSizeList<MetaElementType>> metaCache_;
    BlockingQueue<sptr<FrameRecord>> recorderBufferQueue_;
    SafeMap<sptr<SessionDrainImageCallback>, sptr<DrainImageManager>> callbackMap_;
    std::atomic<bool> isNeededClear_ { false };
    std::atomic<bool> isNeededPop_ { false };
    int64_t shutterTime_;
    uint64_t postCacheFrameCount_;
};

class MovingPhotoMetaListener : public IBufferConsumerListener {
public:
    explicit MovingPhotoMetaListener(sptr<Surface> surface, shared_ptr<FixedSizeList<MetaElementType>> metaCache);
    ~MovingPhotoMetaListener();
    void OnBufferAvailable() override;
private:
    sptr<Surface> surface_;
    shared_ptr<FixedSizeList<MetaElementType>> metaCache_;
};

class SessionDrainImageCallback : public DrainImageCallback {
public:
    explicit SessionDrainImageCallback(std::vector<sptr<FrameRecord>>& frameCacheList,
                                       wptr<MovingPhotoListener> listener,
                                       wptr<MovingPhotoVideoCache> cache,
                                       uint64_t timestamp,
                                       int32_t rotation,
                                       int32_t captureId);
    ~SessionDrainImageCallback();
    void OnDrainImage(sptr<FrameRecord> frame) override;
    void OnDrainImageFinish(bool isFinished) override;

private:
    std::mutex mutex_;
    std::vector<sptr<FrameRecord>> frameCacheList_;
    wptr<MovingPhotoListener> listener_;
    wptr<MovingPhotoVideoCache> videoCache_;
    uint64_t timestamp_;
    int32_t rotation_;
    int32_t captureId_;
};

class CameraInfoDumper;

class EXPORT_API HStreamOperator : public OHOS::HDI::Camera::V1_3::IStreamOperatorCallback {
public:
    static sptr<HStreamOperator> NewInstance(const uint32_t callerToken, int32_t opMode);
    HStreamOperator();
    explicit HStreamOperator(const uint32_t callingTokenId, int32_t opMode);
    virtual ~HStreamOperator();
    int32_t AddOutput(StreamType streamType, sptr<IStreamCommon> stream);
    int32_t Stop();
    int32_t Release();
    int32_t EnableMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        bool isEnable, int32_t sensorOritation);
    int32_t GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    std::list<sptr<HStreamCommon>> GetAllStreams();
    int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig);
    int32_t CreateMediaLibrary(sptr<CameraPhotoProxy>& photoProxy, std::string& uri, int32_t& cameraShotType,
        std::string& burstKey, int64_t timestamp);
    int32_t CreateMediaLibrary(std::shared_ptr<PictureIntf> picture, sptr<CameraPhotoProxy> &photoProxy,
        std::string &uri, int32_t &cameraShotType, std::string& burstKey, int64_t timestamp);
    void SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> cameraPhotoProxy, int32_t &cameraShotType,
        bool &isBursting, std::string &burstKey);
    int32_t LinkInputAndOutputs(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings, int32_t opMode);
    const sptr<HStreamCommon> GetStreamByStreamID(int32_t streamId);
    const sptr<HStreamCommon> GetHdiStreamByStreamID(int32_t streamId);
    void SetSensorRotation(int32_t rotationValue, int32_t sensorOrientation, int32_t cameraPosition);
    void StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId);
    void StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId);
    void GetOutputStatus(int32_t &status);
    int32_t SetPreviewRotation(std::string &deviceClass);
    void ReleaseStreams();
    void StopMovingPhoto();
    int32_t GetActiveColorSpace(ColorSpace& colorSpace);
    int32_t SetColorSpace(ColorSpace colorSpace, bool isNeedUpdate);
    void SetColorSpaceForStreams();
    int32_t CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace);
    int32_t StartPreviewStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        camera_position_enum_t cameraPosition);

    int32_t CreateStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos);
    int32_t CommitStreams(const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode);
    int32_t ReleaseStreams(std::vector<int32_t>& releaseStreamIds);
    int32_t GetStreamsSize();
    int32_t CreateAndCommitStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode);
    int32_t UpdateStreams(std::vector<StreamInfo_V1_1>& streamInfos);
    int32_t UpdateStreamInfos(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream);
    int32_t RemoveOutputStream(sptr<HStreamCommon> stream);

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override;
    int32_t OnCaptureStarted_V1_2(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos) override;
    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override;
    int32_t OnCaptureEndedExt(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos) override;
    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override;
    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnResult(int32_t streamId, const std::vector<uint8_t>& result) override;
    int32_t UnlinkInputAndOutputs();
    int32_t UnlinkOfflineInputAndOutputs();
    void RegisterDisplayListener(sptr<HStreamRepeat> repeat);
    void UnRegisterDisplayListener(sptr<HStreamRepeat> repeat);
    void ClearSketchRepeatStream();
    void ExpandSketchRepeatStream();
    void ExpandMovingPhotoRepeatStream();
    void ClearMovingPhotoRepeatStream();
    void GetStreamOperator();
    bool IsOfflineCapture();
    inline int32_t GetPid()
    {
        return static_cast<int32_t>(pid_);
    }
    inline void ResetHdiStreamId()
    {
        hdiStreamIdGenerator_ = HDI_STREAM_ID_INIT;
    }
    inline void SetCameraDevice(sptr<HCameraDevice> device)
    {
        std::lock_guard<std::mutex> lock(cameraDeviceLock_);
        cameraDevice_ = device;
    }

    inline void SetStreamOperatorId(int32_t& streamOperatorId)
    {
        streamOperatorId_ = streamOperatorId;
    }
    void StartMovingPhotoStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t GetOfflineOutptSize();
    int32_t GetAllOutptSize();

    uint32_t preCacheFrameCount_ = CACHE_FRAME_COUNT;
    uint32_t postCacheFrameCount_ = CACHE_FRAME_COUNT;
    sptr<AvcodecTaskManager> taskManager_;
    std::vector<int32_t> GetFrameRateRange();

private:
    int32_t Initialize(const uint32_t callerToken, int32_t opMode);
    string lastDisplayName_ = "";
    string lastBurstPrefix_ = "";
    int32_t saveIndex = 0;
    int32_t streamOperatorId_ = -1;
    volatile bool isMovingPhotoMirror_ = false;
    volatile bool isSetMotionPhoto_ = false;
    std::mutex livePhotoStreamLock_; // Guard livePhotoStreamRepeat_
    std::mutex opMutex_; // Lock the operations updateSettings_, streamOperator_, and hdiCameraDevice
    sptr<HStreamRepeat> livePhotoStreamRepeat_;
    std::atomic<int32_t> hdiStreamIdGenerator_ = HDI_STREAM_ID_INIT;
    int32_t deviceSensorOritation_ = 0;

    inline int32_t GenerateHdiStreamId()
    {
        return hdiStreamIdGenerator_.fetch_add(1);
    }

    string CreateDisplayName();
    string CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId);
    int32_t AddOutputStream(sptr<HStreamCommon> stream);
    
    int32_t CreateMovingPhotoStreamRepeat(int32_t format, int32_t width, int32_t height,
        sptr<OHOS::IBufferProducer> producer);
    void CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    void RestartStreams(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void StartMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        sptr<HStreamRepeat>& curStreamRepeat);
    void ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice);
    bool InitAudioCapture();
    bool StartAudioCapture();
    void ProcessAudioBuffer();
    void StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId);
    void UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    int32_t GetMovingPhotoBufferDuration();
    void GetMovingPhotoStartAndEndTime();
    void ConfigPayload(uint32_t pid, uint32_t tid, const char *bundleName, int32_t qosLevel,
        std::unordered_map<std::string, std::string> &mapPayload);
    std::shared_ptr<PhotoAssetIntf> ProcessPhotoProxy(int32_t captureId, std::shared_ptr<PictureIntf> picturePtr,
        bool isBursting, sptr<CameraServerPhotoProxy> cameraPhotoProxy, std::string& uri);
    void InitDefaultColortSpace(SceneMode opMode);

#ifdef CAMERA_USE_SENSOR
    std::mutex sensorLock_;
    bool isRegisterSensorSuccess_ = false;
    void RegisterSensorCallback();
    void UnRegisterSensorCallback();
    static void GravityDataCallbackImpl(SensorEvent* event);
    static int32_t CalcSensorRotation(int32_t sensorDegree);
    static int32_t CalcRotationDegree(GravityData data);
#endif
    // Make sure device thread safe,set device by {SetCameraDevice}, get device by {GetCameraDevice}
    std::mutex cameraDeviceLock_;
    std::mutex cbMutex_;
    sptr<HCameraDevice> cameraDevice_;
    StreamContainer streamContainer_;
    StreamContainer streamContainerOffline_;
#ifdef CAMERA_USE_SENSOR
    SensorUser user = { "", nullptr, nullptr };
#endif
    pid_t pid_;
    uid_t uid_;
    uint32_t callerToken_;
    int32_t opMode_;
    ColorSpace currColorSpace_ = ColorSpace::COLOR_SPACE_UNKNOWN;
    bool isSessionStarted_ = false;
    bool enableStreamRotate_ = false;
    bool isDynamicConfiged_ = false;
    std::string deviceClass_ = "phone";
    std::mutex movingPhotoStatusLock_; // Guard movingPhotoStatus
    sptr<MovingPhotoListener> livephotoListener_;
    sptr<MovingPhotoMetaListener> livephotoMetaListener_;
    sptr<AudioCapturerSession> audioCapturerSession_;
    sptr<Surface> metaSurface_ = nullptr;
    sptr<MovingPhotoVideoCache> videoCache_;
    std::mutex displayListenerLock_;
    sptr<DisplayRotationListener> displayListener_;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator_;
    bool isOfflineStreamOperator_ =  false;
    int32_t mlastCaptureId = 0;
    int32_t sensorRotation_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_OPERATOR_H
