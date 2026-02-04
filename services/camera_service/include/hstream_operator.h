/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "sp_holder.h"
#include "camera_util.h"
#include "hcamera_device.h"
#include "capture_session_stub.h"
#include "session/capture_scene_const.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "hstream_capture.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "camera_photo_proxy.h"
#include "v1_0/istream_operator.h"
#include "v1_1/istream_operator.h"
#include "v1_2/istream_operator.h"
#include "v1_5/istream_operator.h"
#include "v1_3/istream_operator_callback.h"
#include "v1_5/istream_operator_callback.h"
#ifdef CAMERA_MOVING_PHOTO
#include "moving_photo_proxy.h"
#else
#include "output/camera_output_capability.h"
#endif
#include "safe_map.h"
#include "display_manager.h"
#include "photo_asset_interface.h"
#include "display_manager_lite.h"
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
using namespace std::chrono;
using namespace DeferredProcessing;
using namespace Media;
constexpr uint32_t OPERATOR_DEFAULT_ENCODER_THREAD_NUMBER = 1;
class PermissionStatusChangeCb;
class CameraUseStateChangeCb;
class CameraServerPhotoProxy;
#ifdef CAMERA_MOVING_PHOTO
class AvcodecTaskManagerIntf;
class AudioCapturerSessionIntf;
class MovingPhotoVideoCacheIntf;
#endif

bool IsHdr(ColorSpace colorSpace);

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

class CameraInfoDumper;

class EXPORT_API HStreamOperator : public OHOS::HDI::Camera::V1_5::IStreamOperatorCallback {
public:
    static sptr<HStreamOperator> NewInstance(const uint32_t callerToken, int32_t opMode);
    HStreamOperator();
    explicit HStreamOperator(const uint32_t callingTokenId, int32_t opMode);
    virtual ~HStreamOperator();
    int32_t AddOutput(StreamType streamType, sptr<IStreamCommon> stream);
    int32_t Stop();
    int32_t Release();
#ifdef CAMERA_MOVING_PHOTO
    int32_t EnableMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        bool isEnable, int32_t sensorOritation);
    int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig);
    void StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId);
    void ReleaseMovingphotoStreams();
    void ReleaseTargetMovingphotoStream(VideoType type);
    void StopMovingPhoto(VideoType type = VideoType::ORIGIN_VIDEO);
    void ExpandXtStyleMovingPhotoRepeatStream();
    void ExpandMovingPhotoRepeatStream(VideoType type);
    void ClearMovingPhotoRepeatStream(VideoType type = VideoType::ORIGIN_VIDEO);
    inline bool IsLivephotoStreamExist()
    {
        return movingPhotoStreamStruct_.streamRepeat != nullptr;
    }
    
    void StartMovingPhotoStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredVideoEnhanceFlag, std::string videoId);
#endif
    int32_t GetCurrentStreamInfos(std::vector<StreamInfo_V1_5>& streamInfos);
    std::list<sptr<HStreamCommon>> GetAllStreams();
    int32_t CreateMediaLibrary(sptr<CameraServerPhotoProxy>& photoProxy, std::string& uri, int32_t& cameraShotType,
        std::string& burstKey, int64_t timestamp);
    int32_t CreateMediaLibrary(std::shared_ptr<PictureIntf> picture, sptr<CameraServerPhotoProxy> &photoProxy,
        std::string &uri, int32_t &cameraShotType, std::string& burstKey, int64_t timestamp);
    void SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> photoProxy, int32_t &cameraShotType,
        bool &isBursting, std::string &burstKey);
    int32_t LinkInputAndOutputs(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings, int32_t opMode);
    const sptr<HStreamCommon> GetStreamByStreamID(int32_t streamId);
    const sptr<HStreamCommon> GetHdiStreamByStreamID(int32_t streamId);
    void GetOutputStatus(int32_t &status);
    int32_t SetPreviewRotation(const std::string &deviceClass);
    void ReleaseStreams();
    int32_t GetActiveColorSpace(ColorSpace& colorSpace);
    int32_t SetColorSpace(ColorSpace colorSpace, bool isNeedUpdate);
    void SetColorSpaceForStreams();
    int32_t VerifyCaptureModeColorSpace(ColorSpace colorSpace);
    int32_t CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace);
    int32_t StartPreviewStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        camera_position_enum_t cameraPosition);
    int32_t UpdateSettingForFocusTrackingMech(bool isEnableMech);
    int32_t CreateStreams(std::vector<HDI::Camera::V1_5::StreamInfo_V1_5>& streamInfos);
    int32_t CommitStreams(const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode);
    int32_t ReleaseStreams(std::vector<int32_t>& releaseStreamIds);
    int32_t GetStreamsSize();
    int32_t CreateAndCommitStreams(std::vector<HDI::Camera::V1_5::StreamInfo_V1_5>& streamInfos,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode);
    int32_t UpdateStreams(std::vector<StreamInfo_V1_5>& streamInfos);
    int32_t UpdateStreamInfos(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream);
    int32_t RemoveOutputStream(sptr<HStreamCommon> stream);

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override;
    int32_t OnCaptureStarted_V1_2(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos) override;
    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override;
    int32_t OnCaptureEndedExt(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos) override;
    int32_t OnCaptureEndedExt_V1_4(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_5::CaptureEndedInfoExt_v1_4>& infos) override;
    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override;
    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnResult(int32_t streamId, const std::vector<uint8_t>& result) override;
    int32_t OnCapturePaused(int32_t captureId, const std::vector<int32_t>& streamIds) override;
    int32_t OnCaptureResumed(int32_t captureId, const std::vector<int32_t>& streamIds) override;
    int32_t UnlinkInputAndOutputs();
    int32_t UnlinkOfflineInputAndOutputs();
    void ClearSketchRepeatStream();
    void ClearCompositionRepeatStream();
    void ExpandSketchRepeatStream();
    void ExpandCompositionRepeatStream();
    std::vector<sptr<HStreamRepeat>> GetCompositionStreams();

    void GetStreamOperator();
    bool IsOfflineCapture();
    bool GetDeferredImageDeliveryEnabled();
    bool GetDeviceAbilityByMeta(uint32_t item, camera_metadata_item_t* metadataItem);
    ColorStylePhotoType GetSupportRedoXtStyle();
    void ChangeListenerXtstyleType();
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
        if (device == nullptr && !IsOfflineCapture()) {
            ResetHDIStreamOperator();
        }
    }

    inline void SetStreamOperatorId(int32_t& streamOperatorId)
    {
        streamOperatorId_ = streamOperatorId;
    }

    inline sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> GetHDIStreamOperator()
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        return streamOperator_;
    }

    inline void ResetHDIStreamOperator()
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        streamOperator_ = nullptr;
    }

    inline void SetXtStyleStatus(bool status)
    {
        isXtStyleEnabled_ = status;
    }

    inline bool GetXtStyleStatus()
    {
        MEDIA_INFO_LOG("xtStyleStatus: %{public}d", isXtStyleEnabled_);
        return isXtStyleEnabled_;
    }
    int32_t GetOfflineOutptSize();

    std::vector<int32_t> GetFrameRateRange();
    void UpdateOrientationBaseGravity(int32_t rotationValue, int32_t sensorOrientation,
        int32_t cameraPosition, int32_t& rotation);
    void SetMechCallback(std::function<void(int32_t,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>&)> callback);
    std::mutex mechCallbackLock_;
    std::function<void(int32_t, const std::shared_ptr<OHOS::Camera::CameraMetadata>&)> mechCallback_;
    int32_t GetSensorRotation();
#ifdef CAMERA_USE_SENSOR
    void RegisterSensorCallback();
#endif

    class DisplayRotationListener : public Rosen::DisplayManagerLite::IDisplayListener {
    public:
        explicit DisplayRotationListener() {};
        virtual ~DisplayRotationListener() = default;
        void OnCreate(Rosen::DisplayId) override {}
        void OnDestroy(Rosen::DisplayId) override {}
        void OnChange(Rosen::DisplayId displayId) override;

        void AddHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream);

        void RemoveHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream);

    public:
        std::list<sptr<HStreamRepeat>> repeatStreamList_;
        std::mutex mStreamManagerLock_;
    };

private:
    std::vector<Size> GetSupportedRecommendedPictureSize();
    bool IsSupportedCompositionStream();
    Size FindNearestRatioSize(Size toFitSize, const std::vector<Size>& supportedSizes);

    sptr<HStreamRepeat> FindPreviewStreamRepeat();
    void AdjustStreamInfosByMode(std::vector<HDI::Camera::V1_5::StreamInfo_V1_5>& streamInfos, int32_t operationMode);
    int32_t Initialize(const uint32_t callerToken, int32_t opMode);
    void RegisterDisplayListener(sptr<HStreamRepeat> repeat);
    void UnRegisterDisplayListener(sptr<HStreamRepeat> repeat);
    void SetBasicInfo(sptr<HStreamCommon> stream);
    string lastDisplayName_ = "";
    string lastBurstPrefix_ = "";
    int32_t saveIndex = 0;
    int32_t streamOperatorId_ = -1;
#ifdef CAMERA_MOVING_PHOTO
    volatile bool isMovingPhotoMirror_ = false;
    int32_t CreateMovingPhotoStreamRepeat(int32_t format, int32_t width, int32_t height, VideoType videoType);
    void StartMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
        sptr<HStreamRepeat>& curStreamRepeat);
    int32_t GetMovingPhotoBufferDuration();
    void GetMovingPhotoStartAndEndTime();
    SpHolder<sptr<MovingPhotoManagerProxy>> movingPhotoManagerProxy_;
    struct MovingPhotoStreamStruct {
        sptr<HStreamRepeat> streamRepeat = nullptr;
        sptr<Surface> videoSurface = nullptr;
        sptr<Surface> metaSurface = nullptr;
    };
    inline MovingPhotoStreamStruct &GetMovingPhotoStreamStruct(VideoType videoType)
    {
        return videoType == XT_ORIGIN_VIDEO ? xtStyleMovingPhotoStreamStruct_ : movingPhotoStreamStruct_;
    }
    inline RepeatStreamType GetRepeatStreamType(VideoType videoType)
    {
        return videoType == XT_ORIGIN_VIDEO ? RepeatStreamType::LIVEPHOTO_XTSTYLE_RAW : RepeatStreamType::LIVEPHOTO;
    }
    MovingPhotoStreamStruct movingPhotoStreamStruct_;
    MovingPhotoStreamStruct xtStyleMovingPhotoStreamStruct_;
    void UnloadMovingPhoto();
#endif
    volatile bool isSetMotionPhoto_ = false;
    std::mutex livePhotoStreamLock_; // Guard livePhotoStreamRepeat_
    std::mutex releaseOperatorLock_;
    std::mutex streamOperatorLock_;
    std::mutex opMutex_; // Lock the operations updateSettings_, streamOperator_, and hdiCameraDevice
    std::atomic<int32_t> hdiStreamIdGenerator_ = HDI_STREAM_ID_INIT;
    int32_t deviceSensorOritation_ = 0;
    ColorStylePhotoType supportXtStyleRedoFlag_ = ColorStylePhotoType::UNSET;
    bool isXtStyleEnabled_ = false;
    std::mutex lastDisplayNameMutex_;
    std::string GetLastDisplayName();
    void SetLastDisplayName(std::string& lastDisplayName);
    inline int32_t GenerateHdiStreamId()
    {
        return hdiStreamIdGenerator_.fetch_add(1);
    }

    string CreateDisplayName(const std::string& suffix);
    string CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId);
    int32_t AddOutputStream(sptr<HStreamCommon> stream);
    void CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_5>& streamInfos);
    void RestartStreams(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    int32_t GetSensorOritation();
    bool IsIpsRotateSupported();
    void ProcessRepeatStream(const sptr<HStreamRepeat>& repeatStream, int32_t captureId,
        const OHOS::HDI::Camera::V1_5::CaptureEndedInfoExt_v1_4& captureInfo);

    std::shared_ptr<PhotoAssetIntf> ProcessPhotoProxy(int32_t captureId, std::shared_ptr<PictureIntf> picturePtr,
        bool isBursting, sptr<CameraServerPhotoProxy> cameraPhotoProxy, std::string& uri);
    void InitDefaultColortSpace(SceneMode opMode);

#ifdef CAMERA_USE_SENSOR
    std::mutex sensorLock_;
    bool isRegisterSensorSuccess_ = false;
    void UnRegisterSensorCallback();
    static void SensorRotationCallbackImpl(const OHOS::Rosen::MotionSensorEvent &motionData);
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
    std::mutex movieFileStatusLock_;
    std::mutex displayListenerLock_;
    sptr<DisplayRotationListener> displayListener_;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator_ = nullptr;
    bool isOfflineStreamOperator_ =  false;
    int32_t mlastCaptureId = 0;

    std::map<int32_t, bool> curMotionPhotoStatus_;
    std::mutex motionPhotoStatusLock_;
    std::map<int32_t, std::pair<int32_t, int32_t>> lifecycleMap_;
    std::vector<uint8_t> mechExtraSettings_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_OPERATOR_H
