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

#include <cstdint>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <refbase.h>
#include <unordered_map>

#include "accesstoken_kit.h"
#include "camera_util.h"
#include "hcamera_device.h"
#include "hcapture_session_stub.h"
#include "hstream_capture.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "perm_state_change_callback_customize.h"
#include "privacy_kit.h"
#include "state_customized_cbk.h"
#include "v1_0/istream_operator.h"
#include "v1_1/istream_operator.h"
#include "v1_2/istream_operator.h"
#include "v1_3/istream_operator_callback.h"
#include "hcamera_restore_param.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::CaptureEndedInfo;
using OHOS::HDI::Camera::V1_0::CaptureErrorInfo;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
class PermissionStatusChangeCb;
class CameraUseStateChangeCb;

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
    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override;
    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;

    virtual const sptr<HStreamCommon> GetStreamByStreamID(int32_t streamId) = 0;

    virtual const sptr<HStreamCommon> GetHdiStreamByStreamID(int32_t streamId) = 0;

private:
    std::mutex cbMutex_;
};

class HCaptureSession : public HCaptureSessionStub, public StreamOperatorCallback {
public:
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
    int32_t SetSmoothZoom(int32_t smoothZoomType, int32_t operationMode, float targetZoomRatio,
        float &duration) override;

    static void dumpSessions(std::string& dumpString);
    void dumpSessionInfo(std::string& dumpString);
    static void CameraSessionSummary(std::string& dumpString);
    pid_t GetPid();
    int32_t GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    int32_t GetopMode();

    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    const sptr<HStreamCommon> GetStreamByStreamID(int32_t streamId) override;
    const sptr<HStreamCommon> GetHdiStreamByStreamID(int32_t streamId) override;
    int32_t SetFeatureMode(int32_t featureMode) override;

private:
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

    int32_t ValidateSessionInputs();
    int32_t ValidateSessionOutputs();
    int32_t AddOutputStream(sptr<HStreamCommon> stream);
    int32_t RemoveOutputStream(sptr<HStreamCommon> stream);
    int32_t LinkInputAndOutputs();
    int32_t UnlinkInputAndOutputs();

    void ReleaseStreams();
    void RegisterPermissionCallback(const uint32_t callingTokenId, const std::string permissionName);
    void UnregisterPermissionCallback(const uint32_t callingTokenId);
    void StartUsingPermissionCallback(const uint32_t callingTokenId, const std::string permissionName);
    void StopUsingPermissionCallback(const uint32_t callingTokenId, const std::string permissionName);

    void ClearSketchRepeatStream();
    void ExpandSketchRepeatStream();
    int32_t CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace);
    void CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos);
    void RestartStreams();
    int32_t UpdateStreamInfos();
    void SetColorSpaceForStreams();

    void ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice);

    std::string GetSessionState();

    StateMachine stateMachine_;

    // Make sure device thread safe,set device by {SetCameraDevice}, get device by {GetCameraDevice}
    std::mutex cameraDeviceLock_;
    sptr<HCameraDevice> cameraDevice_;

    StreamContainer streamContainer_;

    pid_t pid_;
    uid_t uid_;
    uint32_t callerToken_;
    std::shared_ptr<PermissionStatusChangeCb> callbackPtr_;
    std::shared_ptr<CameraUseStateChangeCb> cameraUseCallbackPtr_;
    int32_t opMode_;
    int32_t featureMode_;
    ColorSpace currColorSpace_ = ColorSpace::COLOR_SPACE_UNKNOWN;
    ColorSpace currCaptureColorSpace_ = ColorSpace::COLOR_SPACE_UNKNOWN;
    bool isSessionStarted_ = false;
};

class PermissionStatusChangeCb : public Security::AccessToken::PermStateChangeCallbackCustomize {
public:
    explicit PermissionStatusChangeCb(
        wptr<HCaptureSession> session, const Security::AccessToken::PermStateChangeScope& scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo), captureSession_(session)
    {}
    virtual ~PermissionStatusChangeCb() = default;
    void PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result) override;

private:
    wptr<HCaptureSession> captureSession_;
};

class CameraUseStateChangeCb : public Security::AccessToken::StateCustomizedCbk {
public:
    explicit CameraUseStateChangeCb(wptr<HCaptureSession> session) : captureSession_(session) {}
    virtual ~CameraUseStateChangeCb() = default;
    void StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing) override;

private:
    wptr<HCaptureSession> captureSession_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAPTURE_SESSION_H
