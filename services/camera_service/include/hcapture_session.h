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

#ifndef OHOS_CAMERA_H_CAPTURE_SESSION_H
#define OHOS_CAMERA_H_CAPTURE_SESSION_H
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
#include "camera_rotate_strategy_parser.h"
#include "camera_util.h"
#include "camera_dynamic_loader.h"
#include "fixed_size_list.h"
#include "hcamera_device.h"
#include "hcapture_session_stub.h"
#include "hstream_capture.h"
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
namespace OHOS::Media {
    class Picture;
}
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

static const int32_t STREAM_NOT_FOUNT = -1;

enum class CaptureSessionReleaseType : int32_t {
    RELEASE_TYPE_CLIENT = 0,
    RELEASE_TYPE_CLIENT_DIED,
    RELEASE_TYPE_SECURE,
    RELEASE_TYPE_OBJ_DIED,
};

class StateMachine {
public:
    explicit StateMachine();
    virtual ~StateMachine() = default;
    bool CheckTransfer(CaptureSessionState targetState);
    bool Transfer(CaptureSessionState targetState);

    inline CaptureSessionState GetCurrentState()
    {
        std::lock_guard<std::recursive_mutex> lock(sessionStateLock_);
        return currentState_;
    }

    inline void StateGuard(const std::function<void(const CaptureSessionState)>& fun)
    {
        std::lock_guard<std::recursive_mutex> lock(sessionStateLock_);
        fun(currentState_);
    }

    inline bool IsStateNoLock(CaptureSessionState targetState)
    {
        return currentState_ == targetState;
    }

private:
    std::vector<CaptureSessionState> stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_STATE_MAX)];
    std::recursive_mutex sessionStateLock_;
    CaptureSessionState currentState_ = CaptureSessionState::SESSION_INIT;
};

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

class StreamOperatorCallback : public OHOS::HDI::Camera::V1_3::IStreamOperatorCallback {
public:
    StreamOperatorCallback() = default;
    virtual ~StreamOperatorCallback() = default;

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

    virtual const sptr<HStreamCommon> GetStreamByStreamID(int32_t streamId) = 0;
    virtual const sptr<HStreamCommon> GetHdiStreamByStreamID(int32_t streamId) = 0;
    virtual void StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId,
        int32_t sensorRotationVaule) = 0;

private:
    std::mutex cbMutex_;
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

class EXPORT_API HCaptureSession : public HCaptureSessionStub, public StreamOperatorCallback {
public:
    static sptr<HCaptureSession> NewInstance(const uint32_t callerToken, int32_t opMode);
    HCaptureSession();
    explicit HCaptureSession(const uint32_t callingTokenId, int32_t opMode);
    virtual ~HCaptureSession();

    int32_t BeginConfig() override;
    int32_t CommitConfig() override;

    int32_t CanAddInput(sptr<ICameraDeviceService> cameraDevice, bool& result) override;
    int32_t AddInput(sptr<ICameraDeviceService> cameraDevice) override;
    int32_t AddOutput(StreamType streamType, sptr<IStreamCommon> stream) override;

    int32_t RemoveInput(sptr<ICameraDeviceService> cameraDevice) override;
    int32_t RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream) override;

    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t Release(CaptureSessionReleaseType type);

    static void DestroyStubObjectForPid(pid_t pid);
    int32_t SetCallback(sptr<ICaptureSessionCallback>& callback) override;

    int32_t GetSessionState(CaptureSessionState& sessionState) override;
    int32_t GetActiveColorSpace(ColorSpace& colorSpace) override;
    int32_t SetColorSpace(ColorSpace colorSpace, ColorSpace captureColorSpace, bool isNeedUpdate) override;
    bool QueryFpsAndZoomRatio(float& currentFps, float& currentZoomRatio);
    bool QueryZoomPerformance(std::vector<float>& crossZoomAndTime, int32_t operationMode);
    bool QueryZoomBezierValue(std::vector<float>& zoomBezierValue);
    int32_t SetSmoothZoom(
        int32_t smoothZoomType, int32_t operationMode, float targetZoomRatio, float& duration) override;
    int32_t EnableMovingPhoto(bool isEnable) override;
    pid_t GetPid();
    int32_t GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    int32_t GetopMode();

    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig) override;
    int32_t CreateMediaLibrary(sptr<CameraPhotoProxy>& photoProxy,
        std::string& uri, int32_t& cameraShotType, std::string& burstKey, int64_t timestamp) override;
    int32_t CreateMediaLibrary(std::unique_ptr<Media::Picture> picture, sptr<CameraPhotoProxy> &photoProxy,
        std::string &uri, int32_t &cameraShotType, std::string& burstKey, int64_t timestamp) override;
    void SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> cameraPhotoProxy, int32_t &cameraShotType,
        bool &isBursting, std::string &burstKey);
    const sptr<HStreamCommon> GetStreamByStreamID(int32_t streamId) override;
    int32_t SetFeatureMode(int32_t featureMode) override;
    const sptr<HStreamCommon> GetHdiStreamByStreamID(int32_t streamId) override;
    void StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId,
        int32_t sensorRotationValue) override;
    void StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId);
    void GetOutputStatus(int32_t &status);
    int32_t SetPreviewRotation(std::string &deviceClass) override;

    void DumpSessionInfo(CameraInfoDumper& infoDumper);
    static void DumpSessions(CameraInfoDumper& infoDumper);
    static void DumpCameraSessionSummary(CameraInfoDumper& infoDumper);
    void ReleaseStreams();
    void StopMovingPhoto();

    static void OpenMediaLib();
    static void DelayCloseMediaLib();
    static std::optional<uint32_t> closeTimerId_;
    static std::mutex g_mediaTaskLock_;
    std::atomic<bool> isNeedMediaLib = false;
    uint32_t preCacheFrameCount_ = CACHE_FRAME_COUNT;
    uint32_t postCacheFrameCount_ = CACHE_FRAME_COUNT;
    void SetCameraRotateStrategyInfos(std::vector<CameraRotateStrategyInfo> infos);
    std::vector<CameraRotateStrategyInfo> GetCameraRotateStrategyInfos();
    void UpdateCameraRotateAngleAndZoom(std::vector<CameraRotateStrategyInfo> &infos,
        std::vector<int32_t> &frameRateRange);

private:
    int32_t Initialize(const uint32_t callerToken, int32_t opMode);
    string lastDisplayName_ = "";
    string lastBurstPrefix_ = "";
    int32_t saveIndex = 0;
    volatile bool isMovingPhotoMirror_ = false;
    volatile bool isSetMotionPhoto_ = false;
    std::mutex livePhotoStreamLock_; // Guard livePhotoStreamRepeat_
    sptr<HStreamRepeat> livePhotoStreamRepeat_;
    inline void SetCameraDevice(sptr<HCameraDevice> device)
    {
        std::lock_guard<std::mutex> lock(cameraDeviceLock_);
        cameraDevice_ = device;
    }

    inline const sptr<HCameraDevice> GetCameraDevice()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceLock_);
        return cameraDevice_;
    }
    string CreateDisplayName(const std::string& suffix);
    string CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId);
    int32_t ValidateSessionInputs();
    int32_t ValidateSessionOutputs();
    int32_t ValidateSession();
    int32_t AddOutputStream(sptr<HStreamCommon> stream);
    int32_t RemoveOutputStream(sptr<HStreamCommon> stream);
    int32_t LinkInputAndOutputs();
    int32_t UnlinkInputAndOutputs();

    void ClearSketchRepeatStream();
    void ExpandSketchRepeatStream();
    void ExpandMovingPhotoRepeatStream();
    void ClearMovingPhotoRepeatStream();
    int32_t CreateMovingPhotoStreamRepeat(int32_t format, int32_t width, int32_t height,
        sptr<OHOS::IBufferProducer> producer);
    int32_t CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace);
    void CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    void RestartStreams();
    int32_t UpdateStreamInfos();
    void SetColorSpaceForStreams();

    void ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice);
    void StartMovingPhotoStream();
    bool InitAudioCapture();
    bool StartAudioCapture();
    void ProcessAudioBuffer();
    void StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId);
    int32_t StartPreviewStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        camera_position_enum_t cameraPosition);
    void UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    int32_t GetSensorOritation();
    int32_t GetMovingPhotoBufferDuration();
    void GetMovingPhotoStartAndEndTime();
    void StartMovingPhoto(sptr<HStreamRepeat>& curStreamRepeat);

    std::string GetSessionState();
    void DynamicConfigStream();
    bool IsNeedDynamicConfig();
    void RegisterDisplayListener(sptr<HStreamRepeat> repeat);
    void UnRegisterDisplayListener(sptr<HStreamRepeat> repeat);
    StateMachine stateMachine_;

    #ifdef CAMERA_USE_SENSOR
        std::mutex sensorLock_;
        bool isRegisterSensorSuccess_ = false;
        void RegisterSensorCallback();
        void UnRegisterSensorCallback();
        static void GravityDataCallbackImpl(SensorEvent *event);
        static int32_t CalcSensorRotation(int32_t sensorDegree);
        static int32_t CalcRotationDegree(GravityData data);
    #endif
    // Make sure device thread safe,set device by {SetCameraDevice}, get device by {GetCameraDevice}
    std::mutex cameraDeviceLock_;
    sptr<HCameraDevice> cameraDevice_;
    StreamContainer streamContainer_;
    #ifdef CAMERA_USE_SENSOR
        SensorUser user = {"", nullptr, nullptr};
    #endif
    pid_t pid_;
    uid_t uid_;
    uint32_t callerToken_;
    int32_t opMode_;
    int32_t featureMode_;
    ColorSpace currColorSpace_ = ColorSpace::COLOR_SPACE_UNKNOWN;
    ColorSpace currCaptureColorSpace_ = ColorSpace::COLOR_SPACE_UNKNOWN;
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
    sptr<AvcodecTaskManager> taskManager_;
    std::mutex displayListenerLock_;
    sptr<DisplayRotationListener> displayListener_;
    std::mutex cameraRotateStrategyInfosLock_;
    std::vector<CameraRotateStrategyInfo> cameraRotateStrategyInfos_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAPTURE_SESSION_H
