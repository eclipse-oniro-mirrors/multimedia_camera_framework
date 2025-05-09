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
#include "hcamera_device.h"
#include "hcapture_session_stub.h"
#include "hstream_repeat.h"
#include "hstream_operator.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "camera_photo_proxy.h"
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
using MetaElementType = std::pair<int64_t, sptr<SurfaceBuffer>>;

class CameraInfoDumper;

class EXPORT_API HCaptureSession : public HCaptureSessionStub, public IHCameraCloseListener {
public:
    static CamServiceError NewInstance(const uint32_t callerToken, int32_t opMode, sptr<HCaptureSession>& outSession);
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
    int32_t UnSetCallback() override;

    int32_t GetSessionState(CaptureSessionState& sessionState) override;
    int32_t GetActiveColorSpace(ColorSpace& colorSpace) override;
    int32_t SetColorSpace(ColorSpace colorSpace, bool isNeedUpdate) override;
    bool QueryFpsAndZoomRatio(
        float &currentFps, float &currentZoomRatio, std::vector<float> &crossZoomAndTime, int32_t operationMode);
    bool QueryZoomPerformance(
        std::vector<float> &crossZoomAndTime, int32_t operationMode, const camera_metadata_item_t &zoomItem);
    int32_t GetRangeId(float& zoomRatio, std::vector<float>& crossZoom);
    float GetCrossWaitTime(std::vector<std::vector<float>>& crossTime, int32_t targetRangeId, int32_t currentRangeId);
    void GetCrossZoomAndTime(std::vector<float>& crossZoomAndTime,
        std::vector<float>& crossZoom, std::vector<std::vector<float>>& crossTime);
    bool QueryZoomBezierValue(std::vector<float>& zoomBezierValue);
    int32_t SetSmoothZoom(
        int32_t smoothZoomType, int32_t operationMode, float targetZoomRatio, float& duration) override;
    void AddZoomAndTimeArray(
        std::vector<uint32_t> &zoomAndTimeArray, std::vector<float> array, float frameIntervalMs, float waitTime);
    int32_t EnableMovingPhoto(bool isEnable) override;
    pid_t GetPid();
    int32_t GetSessionId();
    int32_t GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    int32_t GetopMode();

    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig) override;
    std::shared_ptr<PhotoAssetIntf> ProcessPhotoProxy(int32_t captureId,
        std::shared_ptr<PictureIntf> picturePtr, bool isBursting,
        sptr<CameraServerPhotoProxy> cameraPhotoProxy, std::string &uri);
    int32_t SetFeatureMode(int32_t featureMode) override;
    void GetOutputStatus(int32_t &status);
    int32_t SetPreviewRotation(std::string &deviceClass) override;
    int32_t SetCommitConfigFlag(bool isNeedCommitting) override;

    void DumpSessionInfo(CameraInfoDumper& infoDumper);
    static void DumpSessions(CameraInfoDumper& infoDumper);
    static void DumpCameraSessionSummary(CameraInfoDumper& infoDumper);
    void ReleaseStreams();
    bool isEqual(float zoomPointA, float zoomPointB);
    inline void SetStreamOperator(wptr<HStreamOperator> hStreamOperator)
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        if (hStreamOperator == nullptr) {
            return;
        }
        hStreamOperator_ = hStreamOperator;
        auto hStreamOperatorSptr = hStreamOperator_.promote();
        if (hStreamOperatorSptr != nullptr) {
            hStreamOperatorSptr->SetCameraDevice(cameraDevice_);
        }
    }

    inline sptr<HStreamOperator> GetStreamOperator()
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        if (hStreamOperator_ == nullptr) {
            return nullptr;
        }
        return hStreamOperator_.promote();
    }

    void ConfigPayload(uint32_t pid, uint32_t tid, const char *bundleName, int32_t qosLevel,
        std::unordered_map<std::string, std::string> &mapPayload);
    void SetCameraRotateStrategyInfos(std::vector<CameraRotateStrategyInfo> infos);
    std::vector<CameraRotateStrategyInfo> GetCameraRotateStrategyInfos();
    void UpdateCameraRotateAngleAndZoom(std::vector<CameraRotateStrategyInfo> &infos,
        std::vector<int32_t> &frameRateRange);

    void BeforeDeviceClose() override;

    void OnSessionPreempt();
    void UpdateHookBasicInfo(std::map<int32_t, std::string> ParameterMap);

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
    void SetCameraDevice(sptr<HCameraDevice> device);
    inline const sptr<HCameraDevice> GetCameraDevice()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceLock_);
        return cameraDevice_;
    }
    string CreateDisplayName();
    string CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId);
    int32_t ValidateSessionInputs();
    int32_t ValidateSessionOutputs();
    int32_t ValidateSession();
    int32_t RemoveOutputStream(sptr<HStreamCommon> stream);
    int32_t LinkInputAndOutputs();
    int32_t UnlinkInputAndOutputs();

    void ClearSketchRepeatStream();
    void ExpandSketchRepeatStream();
    void ExpandMovingPhotoRepeatStream();

    void ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice);
    void UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void StartMovingPhoto(sptr<HStreamRepeat>& curStreamRepeat);
    int32_t GetSensorOritation();
    std::string GetSessionState();

    void DynamicConfigStream();
    bool IsNeedDynamicConfig();
    int32_t SetHasFitedRotation(bool isHasFitedRotation) override;
    void InitialHStreamOperator();
    void UpdateSettingForSpecialBundle();
    void ClearMovingPhotoRepeatStream();
    StateMachine stateMachine_;

    #ifdef CAMERA_USE_SENSOR
        std::mutex sensorLock_;
        bool isRegisterSensorSuccess_ = false;
        void RegisterSensorCallback();
        void UnregisterSensorCallback();
        static void GravityDataCallbackImpl(SensorEvent *event);
        static int32_t CalcSensorRotation(int32_t sensorDegree);
        static int32_t CalcRotationDegree(GravityData data);
    #endif

    std::string GetConcurrentCameraIds(pid_t pid);

    std::mutex cbMutex_;

    // Make sure device thread safe,set device by {SetCameraDevice}, get device by {GetCameraDevice}
    std::mutex cameraDeviceLock_;
    std::mutex streamOperatorLock_;
    sptr<HCameraDevice> cameraDevice_;

    StreamContainer streamContainer_;
    #ifdef CAMERA_USE_SENSOR
        SensorUser user;
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
    std::string bundleName_ = "";
     std::mutex cameraRotateUpdateBasicInfo_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAPTURE_SESSION_H
