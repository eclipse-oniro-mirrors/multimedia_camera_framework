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

#ifndef OHOS_CAMERA_H_CAPTURE_SESSION_H
#define OHOS_CAMERA_H_CAPTURE_SESSION_H
#include "camera_datashare_helper.h"
#include "icapture_session_callback.h"
#include <cstdint>
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
#include "hcamera_device.h"
#include "capture_session_stub.h"
#include "hstream_repeat.h"
#include "hstream_operator.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "camera_photo_proxy.h"
#include "iconsumer_surface.h"
#include "blocking_queue.h"
#ifdef CAMERA_MOVING_PHOTO
#include "moving_photo_proxy.h"
#endif
#include "safe_map.h"
#ifdef CAMERA_USE_SENSOR
#include "sensor_agent.h"
#include "sensor_agent_type.h"
#endif

namespace OHOS {
namespace CameraStandard {

enum class CaptureSessionReleaseType : int32_t {
    RELEASE_TYPE_CLIENT = 0,
    RELEASE_TYPE_CLIENT_DIED,
    RELEASE_TYPE_SECURE,
    RELEASE_TYPE_OBJ_DIED,
};

enum class MechDeliveryState : int32_t {
    NOT_ENABLED = 0,
    NEED_ENABLE,
    ENABLED,
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
using MetaElementType = std::pair<int64_t, sptr<SurfaceBuffer>>;
using UpdateControlCenterCallback = std::function<void(bool)>;

class CameraInfoDumper;
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
class MovieFileRecorder;
#endif
#ifdef CAMERA_MOVIE_FILE
class HCameraMovieFileOutput;
#endif

class EXPORT_API HCaptureSession : public CaptureSessionStub, public IHCameraCloseListener, public ICameraIpcChecker {
public:
    static CamServiceError NewInstance(const uint32_t callerToken, int32_t opMode, sptr<HCaptureSession>& outSession);
    virtual ~HCaptureSession();

    int32_t BeginConfig() override;
    int32_t CommitConfig() override;
    void DynamicConfigCommit();

    int32_t CanAddInput(const sptr<ICameraDeviceService>& cameraDevice, bool& result) override;
    int32_t AddInput(const sptr<ICameraDeviceService>& cameraDevice) override;
    int32_t AddOutput(StreamType streamType, const sptr<IRemoteObject>& stream) override;
    int32_t AddMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput, int32_t opMode) override;
    int32_t RemoveMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput) override;

    int32_t RemoveInput(const sptr<ICameraDeviceService>& cameraDevice) override;
    int32_t RemoveOutput(StreamType streamType, const sptr<IRemoteObject>& stream) override;

    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t Release(CaptureSessionReleaseType type);

    static void DestroyStubObjectForPid(pid_t pid);
    int32_t SetCallback(const sptr<ICaptureSessionCallback>& callback) override;
    int32_t UnSetCallback() override;

    int32_t SetPressureCallback(const sptr<IPressureStatusCallback>& callback) override;
    int32_t UnSetPressureCallback() override;
    void SetPressureStatus(PressureStatus status);
    int32_t SetControlCenterEffectStatusCallback(const sptr<IControlCenterEffectStatusCallback>& callback) override;
    int32_t UnSetControlCenterEffectStatusCallback() override;
    void SetControlCenterEffectCallbackStatus(ControlCenterStatusInfo statusInfo);
    int32_t SetCameraSwitchRequestCallback(const sptr<ICameraSwitchSessionCallback> &callback) override;
    int32_t UnSetCameraSwitchRequestCallback() override;

    int32_t GetSessionState(CaptureSessionState& sessionState) override;
    int32_t GetActiveColorSpace(int32_t& curColorSpace) override;
    int32_t SetColorSpace(int32_t curColorSpace, bool isNeedUpdate) override;
    bool QueryFpsAndZoomRatio(
        float &currentFps, float &currentZoomRatio, std::vector<float> &crossZoomAndTime, int32_t operationMode);
    bool QueryZoomPerformance(
        std::vector<float> &crossZoomAndTime, int32_t operationMode, const camera_metadata_item_t &zoomItem);
    int32_t GetRangeId(float& zoomRatio, std::vector<float>& crossZoom);
    float GetCrossWaitTimeFromWide(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId);
    float GetCrossWaitTimeFromMain(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId);
    float GetCrossWaitTimeFrom2X(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId);
    float GetCrossWaitTimeFromTele(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId);
    float GetCrossWaitTimeFromTele2(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId);
    float GetCrossWaitTime(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId, int32_t currentRangeId);
    void GetCrossZoomAndTime(std::vector<float>& crossZoomAndTime,
        std::vector<float>& crossZoom, std::vector<std::vector<float>>& crossTime);
    bool QueryZoomBezierValue(std::vector<float>& zoomBezierValue);
    int32_t SetSmoothZoom(
        int32_t smoothZoomType, int32_t operationMode, float targetZoomRatio, float& duration) override;
    bool supportHalCalSmoothZoom(float targetZoomRatio);
    void AddZoomAndTimeArray(
        std::vector<uint32_t> &zoomAndTimeArray, std::vector<float> array, float frameIntervalMs, float waitTime);
    int32_t EnableMovingPhoto(bool isEnable) override;
    int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig) override;
#ifdef CAMERA_MOVING_PHOTO
    void SetMovingPhotoStatus(bool status);
    bool GetMovingPhotoStatus();
#endif
    pid_t GetPid();
    int32_t GetSessionId();
    int32_t GetCurrentStreamInfos(std::vector<StreamInfo_V1_5>& streamInfos);
    int32_t GetopMode();
    int32_t EnableKeyFrameReport(bool isKeyFrameReportEnabled) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    int32_t SetFeatureMode(int32_t featureMode) override;
    void GetOutputStatus(int32_t &status);
    int32_t SetPreviewRotation(const std::string &deviceClass) override;
    int32_t SetCommitConfigFlag(bool isNeedCommitting) override;
    int32_t CreateRecorder(const sptr<IRemoteObject>& stream, sptr<ICameraRecorder>& recorder) override;
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    int32_t CreateRecorder4CinematicVideo(sptr<IStreamCommon> stream, sptr<ICameraRecorder> &movieRecorder);
#endif
    int32_t SetXtStyleStatus(bool status) override;
#ifdef CAMERA_USE_SENSOR
    int32_t GetSensorRotationOnce(int32_t& sensorRotation) override;
#endif

    void DumpSessionInfo(CameraInfoDumper& infoDumper);
    static void DumpSessions(CameraInfoDumper& infoDumper);
    static void DumpCameraSessionSummary(CameraInfoDumper& infoDumper);
    void ReleaseStreams();
    bool isEqual(float zoomPointA, float zoomPointB);

    int32_t GetVirtualApertureMetadata(std::vector<float>& virtualApertureMetadata) override;
    int32_t GetVirtualApertureValue(float& value) override;
    int32_t SetVirtualApertureValue(float value, bool needPersist) override;

    int32_t GetBeautyMetadata(std::vector<int32_t>& beautyApertureMetadata) override;
    int32_t GetBeautyRange(std::vector<int32_t>& range, int32_t type) override;
    int32_t GetBeautyValue(int32_t type, int32_t& value) override;
    int32_t SetBeautyValue(int32_t type, int32_t value, bool needPersist) override;

    void SetControlCenterPrecondition(bool precondition);

    std::string GetBundleForControlCenter();
    void SetBundleForControlCenter(std::string bundleName);

    inline void SetStreamOperator(wptr<HStreamOperator> hStreamOperator)
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        hStreamOperator_ = hStreamOperator;
        auto hStreamOperatorSptr = hStreamOperator_.promote();
        if (hStreamOperatorSptr != nullptr) {
            hStreamOperatorSptr->SetCameraDevice(cameraDevice_);
        }
    }

    inline sptr<HStreamOperator> GetStreamOperator()
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        return hStreamOperator_.promote();
    }

    void SetCameraRotateStrategyInfos(std::vector<CameraRotateStrategyInfo> infos);
    std::vector<CameraRotateStrategyInfo> GetCameraRotateStrategyInfos();

    void BeforeDeviceClose() override;

    void OnSessionPreempt();
    void UpdateHookBasicInfo(std::map<int32_t, std::string> ParameterMap);

    void SetUserId(int32_t userId);
    int32_t GetUserId();
    int32_t EnableMechDelivery(bool isEnableMech);
    void SetMechDeliveryState(MechDeliveryState state);
    void SetUpdateControlCenterCallback(UpdateControlCenterCallback cb);
    bool GetCaptureSessionInfo(CaptureSessionInfo& sessionInfo);
    inline const sptr<HCameraDevice> GetCameraSwirchDevice()
    {
        return GetCameraDevice();
    }
    void SetCameraSwitchDevice(sptr<HCameraDevice> device);
    inline sptr<ICameraSwitchSessionCallback> GetAppCameraSwitchCallback()
    {
        return icameraSwitchSessionCallback_;
    }
    int32_t GetAppCameraSwitchSessionId()
    {
        return appCameraSwitchSessionId;
    }

    int32_t GetNotRegisterCameraSwitchSessionId()
    {
        return appNotRegisterCameraSwitchSessionId;
    }

private:
    void InitDefaultColortSpace(SceneMode opMode);
    explicit HCaptureSession(const uint32_t callingTokenId, int32_t opMode);
    void UpdateBasicInfoForStream(std::map<int32_t, std::string> ParameterMap,
        sptr<OHOS::IBufferProducer> previewProducer, sptr<OHOS::IBufferProducer> videoProducer,
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void DealPluginCode(std::map<int32_t, std::string> ParameterMap,
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings, int32_t code, int32_t value);
    string lastDisplayName_ = "";
    string lastBurstPrefix_ = "";
    int32_t saveIndex = 0;
    bool isNeedCommitting_ = false;
    std::shared_ptr<CameraDataShareHelper> cameraDataShareHelper_;
    void SetCameraDevice(sptr<HCameraDevice> device);
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
    int32_t RemoveOutputStream(sptr<HStreamCommon> stream);
    int32_t LinkInputAndOutputs();
    int32_t UnlinkInputAndOutputs();

    void ClearSketchRepeatStream();
    void ClearCompositionRepeatStream();
    void ExpandSketchRepeatStream();
    void ExpandCompositionRepeatStream();
    int32_t GetCompositionStream(sptr<IRemoteObject>& compositionStreamRemote) override;
#ifdef CAMERA_MOVING_PHOTO
    void ExpandMovingPhotoRepeatStream();
    void ExpandXtStyleMovingPhotoRepeatStream();
    void ClearMovingPhotoRepeatStream();
    bool isMovingPhotoEnabled_ = false;
    std::mutex movingPhotoStatusMutex_;
#endif
    int32_t SetVirtualApertureToDataShareHelper(float value);
    int32_t GetVirtualApertureFromDataShareHelper(float &value);

    int32_t SetBeautyToDataShareHelper(int32_t value);
    int32_t GetBeautyFromDataShareHelper(int32_t &value);


    void ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice);
    void UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void UpdateCameraControl(bool isStart);
    int32_t GetSensorOritation();

    std::string GetSessionState();
    void DynamicConfigStream();
    bool IsNeedDynamicConfig();

    int32_t SetHasFitedRotation(bool isHasFitedRotation) override;
    void InitialHStreamOperator();
    void UpdateSettingForSpecialBundle();
    int32_t UpdateSettingForFocusTrackingMech(bool isEnableMech);
    void UpdateSettingForFocusTrackingMechBeforeStart(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void SetDeviceMechCallback();
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    void ConfigRawVideoStream(sptr<HStreamRepeat>& rawVideoStreamRepeat, const sptr<MovieFileRecorder>& recorder);
#endif
    StateMachine stateMachine_;
    sptr<IPressureStatusCallback> innerPressureCallback_;
    sptr<IControlCenterEffectStatusCallback> innerControlCenterEffectCallback_;
    sptr<ICameraSwitchSessionCallback> icameraSwitchSessionCallback_;
    int32_t  appCameraSwitchSessionId = 0;
    int32_t appNotRegisterCameraSwitchSessionId = 0;
    std::mutex innerPressureCallbackLock_;
    std::mutex innerControlCenterEffectCallbackLock_;
    std::mutex updateControlCenterCallbackLock_;
    std::mutex icameraSwitchSessionCallbackLock_;
    bool isBeautyActive = false;
    bool isApertureActive = false;
    float biggestAperture = 0;
    bool controlCenterPrecondition = true;
    std::string bundleForControlCenter_;
    bool isCameraSessionStart = false;
    
#ifdef CAMERA_USE_SENSOR
    std::mutex sensorLock_;
    bool isRegisterSensorSuccess_ = false;
    void RegisterSensorCallback();
    void UnregisterSensorCallback();
    static void GravityDataCallbackImpl(SensorEvent* event);
    static int32_t CalcSensorRotation(int32_t sensorDegree);
    static int32_t CalcRotationDegree(GravityData data);
#endif

    std::string GetConcurrentCameraIds(pid_t pid);
    int32_t AddOutputInner(StreamType streamType, const sptr<IStreamCommon>& stream);
    int32_t RemoveOutputInner(StreamType streamType, const sptr<IStreamCommon>& stream);

    uint32_t GetEquivalentFocus();
    std::vector<OutputInfo> GetOutputInfos();
    void OnCaptureSessionConfiged();
    void OnCaptureSessionCameraSwitchConfiged(bool isStart);
    void OnZoomInfoChange(const ZoomInfo& zoomInfo);
    void OnSessionStatusChange(bool status);

    std::mutex cbMutex_;
    // Make sure device thread safe,set device by {SetCameraDevice}, get device by {GetCameraDevice}
    std::mutex cameraDeviceLock_;
    std::mutex streamOperatorLock_;
    sptr<HCameraDevice> cameraDevice_;
#ifdef CAMERA_USE_SENSOR
    SensorUser user = { "", nullptr, nullptr };
#endif
    pid_t pid_ = 0;
    uid_t uid_ = 0;
    int32_t sessionId_ = 0;
    uint32_t callerToken_ = 0;
    int32_t opMode_ = 0;
    int32_t featureMode_ = 0;
    bool isSessionStarted_ = false;
    bool isDynamicConfiged_ = false;
    std::string deviceClass_ = "phone";
    wptr<HStreamOperator> hStreamOperator_ = nullptr;
    std::mutex cameraRotateStrategyInfosLock_;
    std::vector<CameraRotateStrategyInfo> cameraRotateStrategyInfos_;
    bool isHasFitedRotation_ = false;
    bool isXtStyleEnabled_ = false;
    std::mutex xtStyleStatusMutex_;
    std::string bundleName_ = "";
    std::mutex cameraRotateUpdateBasicInfo_;
    int32_t userId_ = 0;
    std::mutex mechDeliveryStateLock_;
    MechDeliveryState mechDeliveryState_ = MechDeliveryState::NOT_ENABLED;
    UpdateControlCenterCallback updateControlCenterCallback_;
#ifdef CAMERA_MOVIE_FILE
    wptr<HCameraMovieFileOutput> weakCameraMovieFileOutput_;
#endif
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAPTURE_SESSION_H
