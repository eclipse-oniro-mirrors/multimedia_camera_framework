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

#include "hcapture_session.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <sched.h>
#include <stdint.h>
#include <string>
#include <sync_fence.h>
#include <utility>
#include <vector>

#include "avcodec_task_manager.h"
#include "base_types.h"
#include "blocking_queue.h"
#include "camera_info_dumper.h"
#include "camera_log.h"
#include "camera_report_dfx_uitls.h"
#include "camera_report_uitls.h"
#include "camera_server_photo_proxy.h"
#include "camera_util.h"
#include "datetime_ex.h"
#include "deferred_processing_service.h"
#include "display/composer/v1_1/display_composer_type.h"
#include "display_manager.h"
#include "fixed_size_list.h"
#include "hcamera_restore_param.h"
#include "hcamera_service.h"
#include "hcamera_session_manager.h"
#include "hstream_capture.h"
#include "hstream_common.h"
#include "hstream_depth_data.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "iconsumer_surface.h"
#include "image_type.h"
#include "imech_session.h"
#include "ipc_skeleton.h"
#include "istream_common.h"
#include "photo_asset_interface.h"
#include "photo_asset_proxy.h"
#include "picture_interface.h"
#include "moving_photo/moving_photo_surface_wrapper.h"
#include "moving_photo_video_cache.h"
#include "parameters.h"
#include "refbase.h"
#include "res_sched_client.h"
#include "res_type.h"
#include "smooth_zoom.h"
#include "surface.h"
#include "surface_buffer.h"
#include "v1_0/types.h"
#include "hstream_operator_manager.h"
#include "camera_xcollie.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif

using namespace OHOS::AAFwk;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;

namespace {
constexpr int32_t WIDE_CAMERA_ZOOM_RANGE = 0;
constexpr int32_t MAIN_CAMERA_ZOOM_RANGE = 1;
constexpr int32_t TWO_X_EXIT_TELE_ZOOM_RANGE = 2;
constexpr int32_t TELE_CAMERA_ZOOM_RANGE = 3;
constexpr int32_t WIDE_MAIN_ZOOM_PER = 0;
constexpr int32_t TELE_MAIN_ZOOM_PER = 1;
constexpr int32_t TELE_2X_ZOOM_PER = 2;
constexpr int32_t WIDE_TELE_ZOOM_PER = 3;
constexpr int32_t ZOOM_IN_PER = 0;
constexpr int32_t ZOOM_OUT_PERF = 1;
constexpr int32_t ZOOM_BEZIER_VALUE_COUNT = 5;
constexpr int32_t SPECIAL_BUNDLE_FPS = 15;
constexpr int32_t SPECIAL_BUNDLE_ROTATE = 0;
static const int32_t SESSIONID_BEGIN = 1;
static const int32_t SESSIONID_MAX = INT32_MAX - 1000;
static std::atomic<int32_t> g_currentSessionId = SESSIONID_BEGIN;

static int32_t GenerateSessionId()
{
    int newId = g_currentSessionId++;
    if (newId > SESSIONID_MAX) {
        g_currentSessionId = SESSIONID_BEGIN;
    }
    return newId;
}
}  // namespace

static const std::map<CaptureSessionState, std::string> SESSION_STATE_STRING_MAP = {
    { CaptureSessionState::SESSION_INIT, "Init" },
    { CaptureSessionState::SESSION_CONFIG_INPROGRESS, "Config_In-progress" },
    { CaptureSessionState::SESSION_CONFIG_COMMITTED, "Committed" },
    { CaptureSessionState::SESSION_RELEASED, "Released" }, { CaptureSessionState::SESSION_STARTED, "Started" }
};

CamServiceError HCaptureSession::NewInstance(
    const uint32_t callerToken, int32_t opMode, sptr<HCaptureSession>& outSession)
{
    CamServiceError errCode = CAMERA_OK;
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, opMode);
    CHECK_ERROR_RETURN_RET(session == nullptr, CAMERA_ALLOC_ERROR);

    auto &sessionManager = HCameraSessionManager::GetInstance();
    MEDIA_DEBUG_LOG("HCaptureSession::NewInstance start, total "
                    "session:(%{public}zu), current pid(%{public}d).",
        sessionManager.GetTotalSessionSize(),
        session->pid_);
    if (sessionManager.AddSession(session) == CAMERA_SESSION_MAX_INSTANCE_NUMBER_REACHED) {
        MEDIA_WARNING_LOG("HCaptureSession::HCaptureSession maximum session limit reached. ");
    }
    // Avoid multithread leak session, PreemptOverflowSessions need to call after AddSession, ignore
    // CAMERA_SESSION_MAX_INSTANCE_NUMBER_REACHED.
    sessionManager.PreemptOverflowSessions(IPCSkeleton::GetCallingPid());
    outSession = session;
    MEDIA_INFO_LOG("HCaptureSession::NewInstance end, sessionId: %{public}d, "
                   "total session:(%{public}zu). current opMode_= %{public}d "
                   "errorCode:%{public}d",
        outSession->sessionId_,
        sessionManager.GetTotalSessionSize(),
        opMode,
        errCode);
    return errCode;
}

void HCaptureSession::OnSessionPreempt()
{
    auto disconnectDevice = GetCameraDevice();
    CHECK_EXECUTE(disconnectDevice != nullptr, disconnectDevice->OnError(HDI::Camera::V1_0::DEVICE_PREEMPT, 0));
    MEDIA_ERR_LOG("HCaptureSession::HCaptureSession maximum session limit reached. "
                  "Releasing the earliest session.");
    Release();
}

HCaptureSession::HCaptureSession(const uint32_t callingTokenId, int32_t opMode)
{
    pid_ = IPCSkeleton::GetCallingPid();
    uid_ = static_cast<uint32_t>(IPCSkeleton::GetCallingUid());
    sessionId_ = GenerateSessionId();
    callerToken_ = callingTokenId;
    opMode_ = opMode;
    InitialHStreamOperator();
}

HCaptureSession::~HCaptureSession()
{
    CAMERA_SYNC_TRACE;
    Release(CaptureSessionReleaseType::RELEASE_TYPE_OBJ_DIED);
}

pid_t HCaptureSession::GetPid()
{
    return pid_;
}

int32_t HCaptureSession::GetSessionId()
{
    return sessionId_;
}

int32_t HCaptureSession::GetopMode()
{
    CHECK_ERROR_RETURN_RET(featureMode_, featureMode_);
    return opMode_;
}

int32_t HCaptureSession::GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos)
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_INVALID_ARG,
        "hStreamOperator_ is null");
    return hStreamOperatorSptr->GetCurrentStreamInfos(streamInfos);
}


void HCaptureSession::DynamicConfigStream()
{
    isDynamicConfiged_ = false;
    MEDIA_INFO_LOG("HCaptureSession::DynamicConfigStream enter. currentState = "
                   "%{public}s, sessionID: %{public}d",
        GetSessionState().c_str(),
        GetSessionId());
    auto currentState = stateMachine_.GetCurrentState();
    if (currentState == CaptureSessionState::SESSION_STARTED) {
        isDynamicConfiged_ = CheckSystemApp();  // System applications support dynamic config stream.
        MEDIA_INFO_LOG("HCaptureSession::DynamicConfigStream support dynamic "
                       "stream config, sessionID: %{public}d",
            GetSessionId());
    }
}

bool HCaptureSession::IsNeedDynamicConfig()
{
    return isDynamicConfiged_;
}

int32_t HCaptureSession::SetHasFitedRotation(bool isHasFitedRotation)
{
    isHasFitedRotation_ = isHasFitedRotation;
    return CAMERA_OK;
}

int32_t HCaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    int32_t errCode;
    MEDIA_INFO_LOG("HCaptureSession::BeginConfig prepare execute, sessionID: %{public}d", GetSessionId());
    InitialHStreamOperator();
    stateMachine_.StateGuard([&errCode, this](const CaptureSessionState state) {
        DynamicConfigStream();
        bool isStateValid = stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_INPROGRESS);
        if (!isStateValid) {
            MEDIA_ERR_LOG("HCaptureSession::BeginConfig in invalid state %{public}d, "
                          ", sessionID: %{public}d",
                state,
                GetSessionId());
            errCode = CAMERA_INVALID_STATE;
            isDynamicConfiged_ = false;
            return;
        }
        auto hStreamOperatorSptr = GetStreamOperator();
        CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperator_ is null");
        if (!IsNeedDynamicConfig() && (hStreamOperatorSptr->GetOfflineOutptSize() == 0)) {
            UnlinkInputAndOutputs();
            ClearSketchRepeatStream();
            ClearMovingPhotoRepeatStream();
        }
    });
    if (errCode == CAMERA_OK) {
        MEDIA_INFO_LOG("HCaptureSession::BeginConfig execute success, sessionID: %{public}d", GetSessionId());
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::BeginConfig, sessionID: " + std::to_string(GetSessionId()),
            errCode, false, CameraReportUtils::GetCallerInfo());
    }
    return errCode;
}

int32_t HCaptureSession::CanAddInput(const sptr<ICameraDeviceService>& cameraDevice, bool& result)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    result = false;
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::CanAddInput Need to call BeginConfig "
                          "before adding input, sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if ((GetCameraDevice() != nullptr)) {
            MEDIA_ERR_LOG("HCaptureSession::CanAddInput Only one input is supported, "
                          "sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_SESSION_CFG;
            return;
        }
        sptr<HCameraDevice> hCameraDevice = static_cast<HCameraDevice*>(cameraDevice.GetRefPtr());
        auto deviceSession = hCameraDevice->GetStreamOperatorCallback();
        if (deviceSession != nullptr) {
            errorCode = CAMERA_OPERATION_NOT_ALLOWED;
            return;
        }
    });
    if (errorCode == CAMERA_OK) {
        result = true;
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::CanAddInput, sessionID: %d", GetSessionId()));
    }
    return errorCode;
}

int32_t HCaptureSession::AddInput(const sptr<ICameraDeviceService>& cameraDevice)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    if (cameraDevice == nullptr) {
        errorCode = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCaptureSession::AddInput cameraDevice is null, sessionID: %{public}d", GetSessionId());
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddInput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    MEDIA_INFO_LOG("HCaptureSession::AddInput prepare execute, sessionID: %{public}d", GetSessionId());
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::AddInput Need to call BeginConfig before "
                          "adding input, sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if ((GetCameraDevice() != nullptr)) {
            MEDIA_ERR_LOG("HCaptureSession::AddInput Only one input is supported, "
                          "sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_SESSION_CFG;
            return;
        }
        sptr<HCameraDevice> hCameraDevice = static_cast<HCameraDevice*>(cameraDevice.GetRefPtr());
        MEDIA_INFO_LOG("HCaptureSession::AddInput device:%{public}s", hCameraDevice->GetCameraId().c_str());
        SetCameraDevice(hCameraDevice);
        hCameraDevice->DispatchDefaultSettingToHdi();
        auto thisPtr = wptr<HCaptureSession>(this);
        hCameraDevice->SetZoomInfoCallback([thisPtr]() {
            auto ptr = thisPtr.promote();
            if (ptr != nullptr) {
                ptr->OnCameraAppInfo();
            }
        });
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddInput, sessionID: %d", GetSessionId()));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddInput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("HCaptureSession::AddInput execute success, sessionID: %{public}d", GetSessionId());
    return errorCode;
}

void HCaptureSession::BeforeDeviceClose()
{
    MEDIA_INFO_LOG("HCaptureSession::BeforeDeviceClose UnlinkInputAndOutputs");
    UnlinkInputAndOutputs();
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(
        hStreamOperatorSptr == nullptr, "HCaptureSession::BeforeDeviceClose hStreamOperatorSptr is null");
    if (!hStreamOperatorSptr->IsOfflineCapture()) {
        hStreamOperatorSptr->Release();
    }
}

class DisplayRotationListener : public OHOS::Rosen::DisplayManager::IDisplayListener {
public:
    explicit DisplayRotationListener() {};
    virtual ~DisplayRotationListener() = default;
    void OnCreate(OHOS::Rosen::DisplayId) override {}
    void OnDestroy(OHOS::Rosen::DisplayId) override {}
    void OnChange(OHOS::Rosen::DisplayId displayId) override
    {
        sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
        if (display == nullptr) {
            MEDIA_INFO_LOG("Get display info failed, display:%{public}" PRIu64 "", displayId);
            display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
            CHECK_ERROR_RETURN_LOG(display == nullptr, "Get display info failed, display is nullptr");
        }
        {
            Rosen::Rotation currentRotation = display->GetRotation();
            std::lock_guard<std::mutex> lock(mStreamManagerLock_);
            for (auto& repeatStream : repeatStreamList_) {
                CHECK_EXECUTE(repeatStream, repeatStream->SetStreamTransform(static_cast<int>(currentRotation)));
            }
        }
    }

    void AddHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream)
    {
        std::lock_guard<std::mutex> lock(mStreamManagerLock_);
        CHECK_EXECUTE(repeatStream, repeatStreamList_.push_back(repeatStream));
    }

    void RemoveHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream)
    {
        std::lock_guard<std::mutex> lock(mStreamManagerLock_);
        if (repeatStream) {
            repeatStreamList_.erase(
                std::remove(repeatStreamList_.begin(), repeatStreamList_.end(), repeatStream), repeatStreamList_.end());
        }
    }

public:
    std::list<sptr<HStreamRepeat>> repeatStreamList_;
    std::mutex mStreamManagerLock_;
};

int32_t HCaptureSession::SetPreviewRotation(const std::string &deviceClass)
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_INVALID_ARG,
        "hStreamOperator_ is null");
    hStreamOperatorSptr->SetPreviewRotation(deviceClass);
    return CAMERA_OK;
}

void HCaptureSession::InitialHStreamOperator()
{
    auto hStreamOperatorTemp = GetStreamOperator();
    if (hStreamOperatorTemp == nullptr) {
        sptr<HStreamOperator> hStreamOperator = HStreamOperator::NewInstance(callerToken_, opMode_);
        SetStreamOperator(hStreamOperator);
        HStreamOperatorManager::GetInstance()->AddStreamOperator(hStreamOperator); // 鍗曚緥绠＄悊streamoperator 寰呮壘鍞竴key
    }
}

int32_t HCaptureSession::AddOutput(StreamType streamType, const sptr<IRemoteObject>& remoteObj)
{
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, CAMERA_INVALID_ARG, "HCaptureSession remoteObj is null");
    sptr<IStreamCommon> stream = nullptr;
    if (streamType == StreamType::CAPTURE) {
        stream = iface_cast<IStreamCapture>(remoteObj);
    } else if (streamType == StreamType::REPEAT) {
        stream = iface_cast<IStreamRepeat>(remoteObj);
    }  else if (streamType == StreamType::METADATA) {
        stream = iface_cast<IStreamMetadata>(remoteObj);
    } else if (streamType == StreamType::DEPTH) {
        stream = iface_cast<IStreamDepthData>(remoteObj);
    }
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CAMERA_INVALID_ARG, "HCaptureSession stream is null");
    return AddOutputInner(streamType, stream);
}

int32_t HCaptureSession::AddOutputInner(StreamType streamType, const sptr<IStreamCommon>& stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutput stream is null, sessionID: %{public}d", GetSessionId());
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    stateMachine_.StateGuard([this, &errorCode, streamType, &stream](const CaptureSessionState currentState) {
        InitialHStreamOperator();
        auto hStreamOperatorSptr = GetStreamOperator();
        CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperator_ is null");
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::AddOutput Need to call BeginConfig "
                          "before adding output, sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        errorCode = hStreamOperatorSptr->AddOutput(streamType, stream);
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(
            CreateMsg("CaptureSession::AddOutput with %d, sessionID: %{public}d", streamType, GetSessionId()));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("CaptureSession::AddOutput with with %{public}d, rc = "
                   "%{public}d, sessionID: %{public}d",
        streamType,
        errorCode,
        GetSessionId());
    return errorCode;
}

int32_t HCaptureSession::RemoveInput(const sptr<ICameraDeviceService>& cameraDevice)
{
    int32_t errorCode = CAMERA_OK;
    if (cameraDevice == nullptr) {
        errorCode = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCaptureSession::RemoveInput cameraDevice is null, "
                      "sessionID: %{public}d",
            GetSessionId());
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveInput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveInput prepare execute, sessionID: %{public}d", GetSessionId());
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::RemoveInput Need to call BeginConfig "
                          "before removing input, sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if (IsNeedDynamicConfig()) {
            UnlinkInputAndOutputs();
            ClearSketchRepeatStream();
            ClearMovingPhotoRepeatStream();
        }
        auto currentDevice = GetCameraDevice();
        if (currentDevice != nullptr && cameraDevice->AsObject() == currentDevice->AsObject()) {
            // Do not close device while remove input!
            MEDIA_INFO_LOG(
                "HCaptureSession::RemoveInput camera id is %{public}s", currentDevice->GetCameraId().c_str());
            currentDevice->ResetDeviceSettings();
            SetCameraDevice(nullptr);
            currentDevice->SetStreamOperatorCallback(nullptr);
        } else {
            MEDIA_ERR_LOG("HCaptureSession::RemoveInput Invalid camera device, "
                          "sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_SESSION_CFG;
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveInput, sessionID: %d", GetSessionId()));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveInput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveInput execute success, sessionID: %{public}d", GetSessionId());
    return errorCode;
}

int32_t HCaptureSession::RemoveOutputStream(sptr<HStreamCommon> stream)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(
        stream == nullptr, CAMERA_INVALID_ARG, "HCaptureSession::RemoveOutputStream stream is null");
    MEDIA_INFO_LOG("HCaptureSession::RemoveOutputStream,streamType:%{public}d, streamId:%{public}d",
        stream->GetStreamType(), stream->GetFwkStreamId());
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_INVALID_ARG,
        "hStreamOperatorSptr is null");
    int32_t errorCode = hStreamOperatorSptr->RemoveOutputStream(stream);
    CHECK_ERROR_RETURN_RET_LOG(errorCode != CAMERA_OK, CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::RemoveOutputStream Invalid output");
    return CAMERA_OK;
}

int32_t HCaptureSession::RemoveOutput(StreamType streamType, const sptr<IRemoteObject>& remoteObj)
{
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, CAMERA_INVALID_ARG, "HCaptureSession remoteObj is null");
    sptr<IStreamCommon> stream = nullptr;
    if (streamType == StreamType::CAPTURE) {
        stream = iface_cast<IStreamCapture>(remoteObj);
    } else if (streamType == StreamType::REPEAT) {
        stream = iface_cast<IStreamRepeat>(remoteObj);
    }  else if (streamType == StreamType::METADATA) {
        stream = iface_cast<IStreamMetadata>(remoteObj);
    } else if (streamType == StreamType::DEPTH) {
        stream = iface_cast<IStreamDepthData>(remoteObj);
    }
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CAMERA_INVALID_ARG, "HCaptureSession remoteObj is null");
    return RemoveOutputInner(streamType, stream);
}

int32_t HCaptureSession::RemoveOutputInner(StreamType streamType, const sptr<IStreamCommon>& stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutput stream is null, sessionID: %{public}d", GetSessionId());
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveOutput prepare execute, sessionID: %{public}d", GetSessionId());
    stateMachine_.StateGuard([this, &errorCode, streamType, &stream](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::RemoveOutput Need to call BeginConfig "
                          "before removing output, sessionID: %{public}d",
                GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        auto hStreamOperatorSptr = GetStreamOperator();
        CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperatorSptr is null");
        errorCode = hStreamOperatorSptr->RemoveOutput(streamType, stream);
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(
            CreateMsg("CaptureSession::RemoveOutput with %d, sessionID: %d", streamType, GetSessionId()));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveOutput execute success, sessionID: %{public}d", GetSessionId());
    return errorCode;
}

int32_t HCaptureSession::ValidateSessionInputs()
{
    CHECK_ERROR_RETURN_RET_LOG(GetCameraDevice() == nullptr,
        CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::ValidateSessionInputs No inputs "
        "present, sessionID: %{public}d",
        GetSessionId());
    return CAMERA_OK;
}

int32_t HCaptureSession::ValidateSessionOutputs()
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG((hStreamOperatorSptr == nullptr || hStreamOperatorSptr->GetStreamsSize() == 0),
        CAMERA_INVALID_SESSION_CFG, "HCaptureSession::ValidateSessionOutputs No outputs present");
    return CAMERA_OK;
}

int32_t HCaptureSession::LinkInputAndOutputs()
{
    int32_t rc;
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::ValidateSessionOutputs No outputs present");
    auto device = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(device == nullptr, CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::LinkInputAndOutputs device is null");
    auto settings = device->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET_LOG(settings == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCaptureSession::LinkInputAndOutputs deviceAbility is null");
    CHECK_ERROR_RETURN_RET_LOG(!IsValidMode(opMode_, settings), CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::LinkInputAndOutputs IsValidMode false");
    rc = hStreamOperatorSptr->LinkInputAndOutputs(settings, GetopMode());
    MEDIA_INFO_LOG("HCaptureSession::LinkInputAndOutputs execute success");
    return rc;
}

int32_t HCaptureSession::UnlinkInputAndOutputs()
{
    CAMERA_SYNC_TRACE;
    int32_t rc = CAMERA_UNKNOWN_ERROR;
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr,  rc,
        "HCaptureSession::ValidateSessionOutputs No outputs present");
    rc = hStreamOperatorSptr->UnlinkInputAndOutputs();
        // HDI release streams, do not clear streamContainer_
    return rc;
}

void HCaptureSession::ExpandSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HCaptureSession::ExpandSketchRepeatStream(), "
        "sessionID: %{public}d", GetSessionId());
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr,
        "HCaptureSession::ValidateSessionOutputs No outputs present");
    hStreamOperatorSptr->ExpandSketchRepeatStream();
    MEDIA_DEBUG_LOG("Exit HCaptureSession::ExpandSketchRepeatStream()");
}

void HCaptureSession::ExpandMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream enter, sessionID: %{public}d", GetSessionId());
    if (!GetCameraDevice()->CheckMovingPhotoSupported(GetopMode())) {
        MEDIA_DEBUG_LOG("movingPhoto is not supported, sessionID: %{public}d", GetSessionId());
        return;
    }
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr,
        "HCaptureSession::ValidateSessionOutputs No outputs present");
    hStreamOperatorSptr->ExpandMovingPhotoRepeatStream();
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream Exit");
}

void HCaptureSession::ClearSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HCaptureSession::ClearSketchRepeatStream(), sessionID: %{public}d", GetSessionId());

    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperator is nullptr");
    return hStreamOperatorSptr->ClearSketchRepeatStream();
}

void HCaptureSession::ClearMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter HCaptureSession::ClearMovingPhotoRepeatStream(), "
                    "sessionID: %{public}d",
        GetSessionId());
    // Already added session lock in BeginConfig()
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperator is nullptr");
    return hStreamOperatorSptr->ClearMovingPhotoRepeatStream();
}

int32_t HCaptureSession::ValidateSession()
{
    int32_t errorCode = CAMERA_OK;
    errorCode = ValidateSessionInputs();
    CHECK_ERROR_RETURN_RET(errorCode != CAMERA_OK, errorCode);
    errorCode = ValidateSessionOutputs();
    return errorCode;
}

int32_t HCaptureSession::SetCommitConfigFlag(bool isNeedCommitting)
{
    isNeedCommitting_ = isNeedCommitting;
    return CAMERA_OK;
}

int32_t HCaptureSession::CommitConfigWithValidation()
{
    auto device = GetCameraDevice();
    if (device == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. "
                      "camera device is null, sessionID: %{public}d", GetSessionId());
        return CAMERA_INVALID_STATE;
    }
    const int32_t secureMode = 15;
    uint64_t secureSeqId = 0L;
    device->GetSecureCameraSeq(&secureSeqId);
    if (((GetopMode() == secureMode) ^ (secureSeqId != 0))) {
        MEDIA_ERR_LOG("secureCamera is not allowed commit mode = %{public}d, "
                      "sessionID: %{public}d.", GetopMode(), GetSessionId());
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    MEDIA_INFO_LOG("HCaptureSession::CommitConfig, sessionID: %{public}d, "
                    "secureSeqId = %{public}" PRIu64 "", GetSessionId(), secureSeqId);
    int ret = LinkInputAndOutputs();
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. rc: %{public}d", ret);
        return ret;
    }

    stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
    return CAMERA_OK;
}

int32_t HCaptureSession::CommitConfig()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCaptureSession::CommitConfig begin, sessionID: %{public}d", GetSessionId());
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
        CHECK_ERROR_RETURN_LOG(!isTransferSupport, "HCaptureSession::CommitConfig() Need to call BeginConfig "
            "before committing configuration, sessionID: %{public}d", GetSessionId());
        if (isNeedCommitting_) {
            stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
            return;
        }
        auto hStreamOperatorSptr = GetStreamOperator();
        CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperator is nullptr");
        hStreamOperatorSptr->GetStreamOperator();
        errorCode = ValidateSession();
        CHECK_ERROR_RETURN(errorCode != CAMERA_OK);
        if (!IsNeedDynamicConfig()) {
            ExpandMovingPhotoRepeatStream(); // expand moving photo always
            ExpandSketchRepeatStream();
        }
        errorCode = CommitConfigWithValidation();
    });
    CHECK_EXECUTE(errorCode != CAMERA_OK, CameraReportUtils::ReportCameraError(
        "HCaptureSession::CommitConfig, sessionID: " + std::to_string(GetSessionId()),
        errorCode, false, CameraReportUtils::GetCallerInfo()));
    MEDIA_INFO_LOG("HCaptureSession::CommitConfig end, sessionID: %{public}d", GetSessionId());
    return errorCode;
}

int32_t HCaptureSession::GetActiveColorSpace(int32_t& curColorSpace)
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_OK, "hStreamOperator is nullptr");
    ColorSpace colorSpace;
    hStreamOperatorSptr->GetActiveColorSpace(colorSpace);
    curColorSpace = static_cast<int32_t>(colorSpace);
    return CAMERA_OK;
}

int32_t HCaptureSession::SetColorSpace(int32_t curColorSpace, bool isNeedUpdate)
{
    int32_t result = CAMERA_OK;
    ColorSpace colorSpace = static_cast<ColorSpace>(curColorSpace);
    stateMachine_.StateGuard(
        [&result, this, &colorSpace, &isNeedUpdate](CaptureSessionState currentState) {
            MEDIA_INFO_LOG("HCaptureSession::SetColorSpace() ColorSpace : %{public}d", colorSpace);
            if (!(currentState == CaptureSessionState::SESSION_CONFIG_INPROGRESS ||
                    currentState == CaptureSessionState::SESSION_CONFIG_COMMITTED)) {
                MEDIA_ERR_LOG("HCaptureSession::SetColorSpace(), Invalid session state: "
                              "%{public}d, sessionID: %{public}d",
                    currentState,
                    GetSessionId());
                result = CAMERA_INVALID_STATE;
                return;
            }

            auto hStreamOperatorSptr = GetStreamOperator();
            CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperator is nullptr");
            result = hStreamOperatorSptr->SetColorSpace(colorSpace, isNeedUpdate);
            if (isNeedUpdate &&  result != CAMERA_OK) {
                return;
            }
            if (isNeedUpdate) {
                auto device = GetCameraDevice();
                CHECK_ERROR_RETURN_LOG(device == nullptr, "HCaptureSession::SetColorSpace device is null");
                std::shared_ptr<OHOS::Camera::CameraMetadata> settings = device->CloneCachedSettings();
                MEDIA_INFO_LOG("HCaptureSession::SetColorSpace() CloneCachedSettings");
                DumpMetadata(settings);
                result = hStreamOperatorSptr->UpdateStreamInfos(settings);
            }
        });
    return result;
}

int32_t HCaptureSession::GetSessionState(CaptureSessionState& sessionState)
{
    sessionState = stateMachine_.GetCurrentState();
    return CAMERA_OK;
}

bool HCaptureSession::QueryFpsAndZoomRatio(
    float &currentFps, float &currentZoomRatio, std::vector<float> &crossZoomAndTime, int32_t operationMode)
{
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, false, "HCaptureSession::QueryFpsAndZoomRatio() cameraDevice is null");
    // LCOV_EXCL_START
    int32_t DEFAULT_ITEMS = 3;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint32_t count = 1;
    uint32_t fps = 30;
    uint32_t zoomRatio = 100;
    uint32_t arrayCount = 154;
    std::vector<uint32_t> vctZoomRatio;
    vctZoomRatio.resize(arrayCount, 0);
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_FPS, &fps, count);
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &zoomRatio, count);
    metaIn->addEntry(OHOS_STATUS_CAMERA_ZOOM_PERFORMANCE, vctZoomRatio.data(), arrayCount);
    cameraDevice->GetStatus(metaIn, metaOut);
    camera_metadata_item_t item;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &item);
    CHECK_ERROR_RETURN_RET_LOG(retFindMeta == CAM_META_ITEM_NOT_FOUND || item.count == 0, false,
        "HCaptureSession::QueryFpsAndZoomRatio() current zoom not found, sessionID: %{public}d", GetSessionId());
    if (retFindMeta == CAM_META_SUCCESS) {
        currentZoomRatio = static_cast<float>(item.data.ui32[0]);
        MEDIA_INFO_LOG("HCaptureSession::QueryFpsAndZoomRatio() current zoom "
                       "%{public}d, sessionID: %{public}d.", item.data.ui32[0], GetSessionId());
    }
    retFindMeta = OHOS::Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_FPS, &item);
    CHECK_ERROR_RETURN_RET_LOG(retFindMeta == CAM_META_ITEM_NOT_FOUND || item.count == 0, false,
        "HCaptureSession::QueryFpsAndZoomRatio() current fps not found, sessionID: %{public}d", GetSessionId());
    if (retFindMeta == CAM_META_SUCCESS) {
        currentFps = static_cast<float>(item.data.ui32[0]);
        MEDIA_INFO_LOG("HCaptureSession::QueryFpsAndZoomRatio() current fps "
            "%{public}d, sessionID: %{public}d.", item.data.ui32[0], GetSessionId());
    }
    retFindMeta = OHOS::Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_ZOOM_PERFORMANCE, &item);
    CHECK_ERROR_RETURN_RET_LOG(retFindMeta == CAM_META_ITEM_NOT_FOUND || item.count == 0, false,
        "HCaptureSession::QueryFpsAndZoomRatio() current PERFORMANCE not found, sessionID: %{public}d",
        GetSessionId());
    if (retFindMeta == CAM_META_SUCCESS) {
        MEDIA_INFO_LOG("HCaptureSession::QueryFpsAndZoomRatio() zoom performance count %{public}d,"
            "sessionID: %{public}d.", item.count, GetSessionId());
        QueryZoomPerformance(crossZoomAndTime, operationMode, item);
    }
    return true;
    // LCOV_EXCL_STOP
}

bool HCaptureSession::QueryZoomPerformance(
    std::vector<float> &crossZoomAndTime, int32_t operationMode, const camera_metadata_item_t &zoomItem)
{
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, false, "HCaptureSession::QueryZoomPerformance() cameraDevice is null");
    // query zoom performance. begin
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance() zoom performance count %{public}d.", zoomItem.count);
    for (int i = 0; i < static_cast<int>(zoomItem.count); i++) {
        MEDIA_DEBUG_LOG(
            "HCaptureSession::QueryZoomPerformance() zoom performance value %{public}d.", zoomItem.data.ui32[i]);
    }
    int dataLenPerPoint = 3;
    int headLenPerMode = 2;
    MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance() operationMode %{public}d, "
                    "sessionID: %{public}d.",
        static_cast<OHOS::HDI::Camera::V1_3::OperationMode>(operationMode),
        GetSessionId());
    for (int i = 0; i < static_cast<int>(zoomItem.count);) {
        int sceneMode = static_cast<int>(zoomItem.data.ui32[i]);
        int zoomPointsNum = static_cast<int>(zoomItem.data.ui32[i + 1]);
        if (static_cast<OHOS::HDI::Camera::V1_3::OperationMode>(operationMode) == sceneMode) {
            for (int j = 0; j < dataLenPerPoint * zoomPointsNum; j++) {
                crossZoomAndTime.push_back(zoomItem.data.ui32[i + headLenPerMode + j]);
                MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance()    crossZoomAndTime "
                                "%{public}d, sessionID: %{public}d.",
                    static_cast<int>(zoomItem.data.ui32[i + headLenPerMode + j]),
                    GetSessionId());
            }
            break;
        } else {
            i = i + 1 + zoomPointsNum * dataLenPerPoint + 1;
        }
    }
    return true;
}

int32_t HCaptureSession::GetSensorOritation()
{
    auto cameraDevice = GetCameraDevice();
    int32_t sensorOrientation = 0;
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr,
        sensorOrientation,
        "HCaptureSession::GetSensorOritation() "
        "cameraDevice is null, sessionID: %{public}d",
        GetSessionId());
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET(ability == nullptr, sensorOrientation);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, sensorOrientation,
        "HCaptureSession::GetSensorOritation get sensor orientation failed");
    sensorOrientation = item.data.i32[0];
    MEDIA_INFO_LOG("HCaptureSession::GetSensorOritation sensor orientation "
                   "%{public}d, sessionID: %{public}d",
        sensorOrientation,
        GetSessionId());
    return sensorOrientation;
}

int32_t HCaptureSession::GetRangeId(float& zoomRatio, std::vector<float>& crossZoom)
{
    int32_t rangId = 0;
    for (; rangId < static_cast<int>(crossZoom.size()); rangId++) {
        CHECK_ERROR_RETURN_RET(zoomRatio < crossZoom[rangId], rangId);
    }
    return rangId;
}

bool HCaptureSession::isEqual(float zoomPointA, float zoomPointB)
{
    float epsilon = 0.00001f;
    return fabs(zoomPointA - zoomPointB) < epsilon;
}

void HCaptureSession::GetCrossZoomAndTime(
    std::vector<float>& crossZoomAndTime, std::vector<float>& crossZoom, std::vector<std::vector<float>>& crossTime)
{
    int dataLenPerPoint = 3;
    for (int i = 0; i < static_cast<int>(crossZoomAndTime.size()); i = i + dataLenPerPoint) {
        if (crossZoomAndTime[i] != 0) {
            crossZoom.push_back(crossZoomAndTime[i]);
        }
        crossTime[i / dataLenPerPoint][ZOOM_IN_PER] = crossZoomAndTime[i + ZOOM_IN_PER + 1];
        crossTime[i / dataLenPerPoint][ZOOM_OUT_PERF] = crossZoomAndTime[i + ZOOM_OUT_PERF + 1];
    }
}

float HCaptureSession::GetCrossWaitTime(
    std::vector<std::vector<float>>& crossTime, int32_t targetRangeId, int32_t currentRangeId)
{
    float waitTime = 0.0; // 100 199 370 获取maxWaitTime
    switch (currentRangeId) {
        case WIDE_CAMERA_ZOOM_RANGE:
            if (targetRangeId == TELE_CAMERA_ZOOM_RANGE) {
                waitTime = crossTime[WIDE_TELE_ZOOM_PER][ZOOM_IN_PER];
            } else {
                waitTime = crossTime[WIDE_MAIN_ZOOM_PER][ZOOM_IN_PER];
            }
            break;
        case MAIN_CAMERA_ZOOM_RANGE:
            if (targetRangeId == TELE_CAMERA_ZOOM_RANGE) {
                waitTime = crossTime[TELE_MAIN_ZOOM_PER][ZOOM_IN_PER];
            } else if (targetRangeId == WIDE_CAMERA_ZOOM_RANGE) {
                waitTime = crossTime[WIDE_MAIN_ZOOM_PER][ZOOM_OUT_PERF];
            }
            break;
        case TWO_X_EXIT_TELE_ZOOM_RANGE:
            if (targetRangeId == TELE_CAMERA_ZOOM_RANGE) {
                waitTime = crossTime[TELE_2X_ZOOM_PER][ZOOM_IN_PER];
            } else if (targetRangeId == WIDE_CAMERA_ZOOM_RANGE) {
                waitTime = crossTime[WIDE_MAIN_ZOOM_PER][ZOOM_OUT_PERF];
            } else {
                MEDIA_DEBUG_LOG("HCaptureSession::GetCrossWaitTime pass");
            }
            break;
        case TELE_CAMERA_ZOOM_RANGE:
            if (targetRangeId == WIDE_CAMERA_ZOOM_RANGE) {
                waitTime = crossTime[WIDE_TELE_ZOOM_PER][ZOOM_OUT_PERF];
            } else if (targetRangeId == TWO_X_EXIT_TELE_ZOOM_RANGE) {
                waitTime = crossTime[TELE_2X_ZOOM_PER][ZOOM_OUT_PERF];
            } else {
                waitTime = crossTime[TELE_MAIN_ZOOM_PER][ZOOM_OUT_PERF];
            }
            break;
    }
    MEDIA_DEBUG_LOG("HCaptureSession::GetCrossWaitTime waitTime %{public}f, "
                    "targetRangeId %{public}d,"
                    " currentRangeId %{public}d, sessionID: %{public}d",
        waitTime,
        targetRangeId,
        currentRangeId,
        GetSessionId());
    return waitTime;
}

bool HCaptureSession::QueryZoomBezierValue(std::vector<float> &zoomBezierValue)
{
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, false, "HCaptureSession::QueryZoomBezierValue() cameraDevice is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    camera_metadata_item_t bezierItem;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_ZOOM_BEZIER_CURVC_POINT, &bezierItem);
    CHECK_ERROR_RETURN_RET_LOG(retFindMeta == CAM_META_ITEM_NOT_FOUND, false,
        "HCaptureSession::QueryZoomBezierValue() current bezierValue not found");
    for (int i = 0; i < static_cast<int>(bezierItem.count); i++) {
        zoomBezierValue.push_back(bezierItem.data.f[i]);
        MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomBezierValue()  bezierValue %{public}f.",
            static_cast<float>(bezierItem.data.f[i]));
    }
    return true;
}

int32_t HCaptureSession::SetSmoothZoom(
    int32_t smoothZoomType, int32_t operationMode, float targetZoomRatio, float& duration)
{
    constexpr int32_t ZOOM_RATIO_MULTIPLE = 100;
    const int32_t MAX_FPS = 60;
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCaptureSession::SetSmoothZoom device is null, sessionID: %{public}d", GetSessionId());
    float currentFps = 30.0f;
    float currentZoomRatio = 1.0f;
    int32_t targetRangeId = 0;
    int32_t currentRangeId = 0;
    std::vector<float> crossZoomAndTime {};
    std::vector<float> zoomBezierValue {};
    QueryFpsAndZoomRatio(currentFps, currentZoomRatio, crossZoomAndTime, operationMode);
    currentFps = currentFps > MAX_FPS ? MAX_FPS : currentFps;
    std::vector<float> mCrossZoom {};
    int32_t waitCount = 4;
    int32_t zoomInOutCount = 2;
    std::vector<std::vector<float>> crossTime(waitCount, std::vector<float>(zoomInOutCount, 0.0f)); // 生成4x2二维数组
    GetCrossZoomAndTime(crossZoomAndTime, mCrossZoom, crossTime);
    float frameIntervalMs = 1000.0 / currentFps;
    targetZoomRatio = targetZoomRatio * ZOOM_RATIO_MULTIPLE;
    targetRangeId = GetRangeId(targetZoomRatio, mCrossZoom);
    currentRangeId = GetRangeId(currentZoomRatio, mCrossZoom);
    float waitMs = GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    bool retHaveBezierValue = QueryZoomBezierValue(zoomBezierValue);
    auto zoomAlgorithm = SmoothZoom::GetZoomAlgorithm(static_cast<SmoothZoomType>(smoothZoomType));
    if (retHaveBezierValue && zoomBezierValue.size() == ZOOM_BEZIER_VALUE_COUNT) {
        zoomAlgorithm->SetBezierValue(zoomBezierValue);
    }
    auto array = zoomAlgorithm->GetZoomArray(currentZoomRatio, targetZoomRatio, frameIntervalMs);
    CHECK_ERROR_RETURN_RET_LOG(array.empty(), CAMERA_UNKNOWN_ERROR, "HCaptureSession::SetSmoothZoom array is empty");
    if (currentZoomRatio < targetZoomRatio) {
        std::sort(mCrossZoom.begin(), mCrossZoom.end());
    } else {
        std::sort(mCrossZoom.begin(), mCrossZoom.end(), std::greater<float>());
    }
    float waitTime = 0.0f;
    waitTime = CalculateWaitTime(mCrossZoom, currentZoomRatio, targetZoomRatio, waitMs, frameIntervalMs, array);
    std::vector<uint32_t> zoomAndTimeArray {};
    for (int i = 0; i < static_cast<int>(array.size()); i++) {
        zoomAndTimeArray.push_back(static_cast<uint32_t>(array[i]));
        zoomAndTimeArray.push_back(static_cast<uint32_t>(i * frameIntervalMs + waitTime));
        MEDIA_DEBUG_LOG("HCaptureSession::SetSmoothZoom() zoom %{public}d, waitMs %{public}d.",
            static_cast<uint32_t>(array[i]), static_cast<uint32_t>(i * frameIntervalMs + waitTime));
    }
    duration = (static_cast<int>(array.size()) - 1) * frameIntervalMs + waitTime;
    MEDIA_DEBUG_LOG("HCaptureSession::SetSmoothZoom() duration %{public}f, "
                    "sessionID: %{public}d", duration, GetSessionId());
    ProcessMetaZoomArray(zoomAndTimeArray, cameraDevice);
    return CAMERA_OK;
}

float HCaptureSession::CalculateWaitTime(const std::vector<float>& mCrossZoom,
                                         float currentZoomRatio, float targetZoomRatio,
                                         float waitMs, float frameIntervalMs,
                                         const std::vector<float>& array)
{
    float waitTime = 0.0f;
    for (int i = 0; i < static_cast<int>(mCrossZoom.size()); i++) {
        float crossZoom = mCrossZoom[i];
        MEDIA_DEBUG_LOG("HCaptureSession::CalculateWaitTime crossZoomIterator is:  %{public}f.", crossZoom);
        if ((crossZoom - currentZoomRatio) * (crossZoom - targetZoomRatio) > 0 || isEqual(crossZoom, 199.0f)) {
            MEDIA_DEBUG_LOG("HCaptureSession::CalculateWaitTime skip zoomCross is:  %{public}f.", crossZoom);
            continue;
        }
        if (std::fabs(currentZoomRatio - crossZoom) <= std::numeric_limits<float>::epsilon() &&
            currentZoomRatio > targetZoomRatio) {
            waitTime = waitMs;
        }
        for (int j = 0; j < static_cast<int>(array.size()); j++) {
            if (static_cast<int>(array[j] - crossZoom) * static_cast<int>(array[0] - crossZoom) <= 0) {
                waitTime = waitMs - frameIntervalMs * j;
                waitTime = waitTime >= 0 ? waitTime : 0;
                MEDIA_DEBUG_LOG("HCaptureSession::CalculateWaitTime crossZoom is: %{public}f, waitTime is: %{public}f",
                    crossZoom, waitTime);
                break;
            }
        }
    }
    return waitTime;
}

void HCaptureSession::ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaZoomArray = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    uint32_t zoomCount = static_cast<uint32_t>(zoomAndTimeArray.size());
    MEDIA_INFO_LOG("HCaptureSession::ProcessMetaZoomArray() zoomArray size: "
                   "%{public}zu, zoomCount: %{public}u, sessionID: %{public}d",
        zoomAndTimeArray.size(),
        zoomCount,
        GetSessionId());
    metaZoomArray->addEntry(OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, zoomAndTimeArray.data(), zoomCount);
    cameraDevice->UpdateSettingOnce(metaZoomArray);
}

int32_t HCaptureSession::EnableMovingPhoto(bool isEnable)
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_OK, "hStreamOperatorSptr is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
    auto cameraDevice = GetCameraDevice();
    if (cameraDevice != nullptr) {
        settings = cameraDevice->CloneCachedSettings();
    }
    hStreamOperatorSptr->EnableMovingPhoto(settings, isEnable, GetSensorOritation());
    return CAMERA_OK;
}

std::string HCaptureSession::GetConcurrentCameraIds(pid_t pid)
{
    std::string concurrencyString = "Concurrency cameras:[";
    std::list<sptr<HCaptureSession>> sessionList = HCameraSessionManager::GetInstance().GetGroupSessions(pid);
    for (auto entry : sessionList) {
        if (!entry->isSessionStarted_) {
            continue;
        }
        auto device = entry->GetCameraDevice();
        if (device == nullptr) {
            continue;
        }
        concurrencyString.append(device->GetCameraId() + "    ");
    }
    concurrencyString.append("]");
    return concurrencyString;
}

int32_t HCaptureSession::Start()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    MEDIA_INFO_LOG("HCaptureSession::Start prepare execute, sessionID: %{public}d", GetSessionId());
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_STARTED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Start() Need to call after "
                          "committing configuration, sessionID: %{public}d", GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
        auto cameraDevice = GetCameraDevice();
        uint8_t usedAsPositionU8 = OHOS_CAMERA_POSITION_OTHER;
        MEDIA_INFO_LOG("HCaptureSession::Start usedAsPositionU8 default = "
                       "%{public}d, sessionID: %{public}d", usedAsPositionU8, GetSessionId());
        if (cameraDevice != nullptr) {
            settings = cameraDevice->CloneCachedSettings();
            usedAsPositionU8 = cameraDevice->GetUsedAsPosition();
            MEDIA_INFO_LOG("HCaptureSession::Start usedAsPositionU8 set "
                           "%{public}d, sessionID: %{public}d", usedAsPositionU8, GetSessionId());
            DumpMetadata(settings);
            UpdateMuteSetting(cameraDevice->GetDeviceMuteMode(), settings);
            UpdateSettingForFocusTrackingMechBeforeStart(settings);
        }
        camera_position_enum_t cameraPosition = static_cast<camera_position_enum_t>(usedAsPositionU8);
        auto hStreamOperatorSptr = GetStreamOperator();
        CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperatorSptr is null");
        UpdateSettingForSpecialBundle();
        errorCode = hStreamOperatorSptr->StartPreviewStream(settings, cameraPosition);
        CHECK_EXECUTE(errorCode == CAMERA_OK, isSessionStarted_ = true);
        stateMachine_.Transfer(CaptureSessionState::SESSION_STARTED);
        {
            std::lock_guard<std::mutex> lock(mechDeliveryStateLock_);
            if (mechDeliveryState_ == MechDeliveryState::NEED_ENABLE) {
                hStreamOperatorSptr->UpdateSettingForFocusTrackingMech(true);
                mechDeliveryState_ = MechDeliveryState::ENABLED;
            }
        }
        OnCameraAppInfo();
    });
    MEDIA_INFO_LOG("HCaptureSession::Start execute success, sessionID: %{public}d", GetSessionId());
    MEDIA_INFO_LOG("%{public}s", GetConcurrentCameraIds(pid_).c_str());
    return errorCode;
}

void HCaptureSession::UpdateSettingForSpecialBundle()
{
    OHOS::Rosen::FoldStatus foldstatus = OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus();
    OHOS::Rosen::FoldDisplayMode displayMode = OHOS::Rosen::DisplayManager::GetInstance().GetFoldDisplayMode();
    auto hStreamOperatorSptr = GetStreamOperator();
    bool isValidDisplayStatus = (foldstatus == OHOS::Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_EXPAND) &&
        (displayMode == OHOS::Rosen::FoldDisplayMode::GLOBAL_FULL);
    bool isExeUpdate = hStreamOperatorSptr != nullptr &&
        (foldstatus == OHOS::Rosen::FoldStatus::FOLDED || isValidDisplayStatus) && !isHasFitedRotation_;
    if (isExeUpdate) {
        auto frameRateRange = hStreamOperatorSptr->GetFrameRateRange();
        auto cameraDevice = GetCameraDevice();
        CHECK_ERROR_RETURN(cameraDevice == nullptr);
        cameraDevice->UpdateCameraRotateAngleAndZoom(frameRateRange);
        int32_t cameraPosition = cameraDevice->GetCameraPosition();
        CHECK_ERROR_RETURN(cameraPosition == OHOS_CAMERA_POSITION_FRONT);
        int uid = IPCSkeleton::GetCallingUid();
        CHECK_EXECUTE(bundleName_ == "", bundleName_ = GetClientBundle(uid));
        std::string specialBundle = system::GetParameter("const.camera.folded_lens_change", "default");
        CHECK_ERROR_RETURN(specialBundle != bundleName_ || frameRateRange.empty() ||
            frameRateRange[0] != SPECIAL_BUNDLE_FPS);
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings =
            std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
        int32_t rotateDegree = SPECIAL_BUNDLE_ROTATE;
        MEDIA_INFO_LOG("HCaptureSession::UpdateSettingForSpecialBundle rotateDegree: %{public}d.", rotateDegree);
        settings->addEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateDegree, 1);
        cameraDevice->UpdateSettingOnce(settings);
    }
}

void HCaptureSession::UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    int32_t count = 1;
    uint8_t mode = muteMode ? OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK : OHOS_CAMERA_MUTE_MODE_OFF;
    settings->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
}

int32_t HCaptureSession::Stop()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    MEDIA_INFO_LOG("HCaptureSession::Stop prepare execute, sessionID: %{public}d", GetSessionId());
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Stop() Need to call after Start, "
                          "sessionID: %{public}d", GetSessionId());
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        auto hStreamOperatorSptr = GetStreamOperator();
        if (hStreamOperatorSptr == nullptr) {
            MEDIA_ERR_LOG("hStreamOperatorSptr is null");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        errorCode = hStreamOperatorSptr->Stop();
        if (errorCode == CAMERA_OK) {
            isSessionStarted_ = false;
        }
        stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
        OnCameraAppInfo();
    });
    MEDIA_INFO_LOG("HCaptureSession::Stop execute success, sessionID: %{public}d", GetSessionId());
    return errorCode;
}

int32_t HCaptureSession::Release(CaptureSessionReleaseType type)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    int32_t sid = GetSessionId();
    MEDIA_INFO_LOG("HCaptureSession::Release prepare execute, release type "
                   "is:%{public}d pid(%{public}d), sessionID: %{public}d", type, pid_, GetSessionId());
    // Check release without lock first
    CHECK_ERROR_RETURN_RET_LOG(stateMachine_.IsStateNoLock(CaptureSessionState::SESSION_RELEASED),
        CAMERA_INVALID_STATE,
        "HCaptureSession::Release error, session is already released!");

    stateMachine_.StateGuard([&errorCode, this, type](CaptureSessionState currentState) {
        MEDIA_INFO_LOG("HCaptureSession::Release pid(%{public}d). release type is:%{public}d", pid_, type);
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_RELEASED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Release error, this session is already released!");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        // Clear current session
        if (type != CaptureSessionReleaseType::RELEASE_TYPE_OBJ_DIED) {
            HCameraSessionManager::GetInstance().RemoveSession(this);
            MEDIA_DEBUG_LOG("HCaptureSession::Release clear pid left sessions(%{public}zu).",
                HCameraSessionManager::GetInstance().GetTotalSessionSize());
        }
        auto hStreamOperatorSptr = GetStreamOperator();
        CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperatorSptr is null");
        // stop movingPhoto
        hStreamOperatorSptr->StopMovingPhoto();

        // Clear outputs
        hStreamOperatorSptr->ReleaseStreams();

        // Clear inputs
        auto cameraDevice = GetCameraDevice();
        if (cameraDevice != nullptr) {
            cameraDevice->Release();
            SetCameraDevice(nullptr);
        }

        if ((hStreamOperatorSptr->GetAllOutptSize()) == 0) {
            hStreamOperatorSptr->Release();
        }
        sptr<ICaptureSessionCallback> emptyCallback = nullptr;
        SetCallback(emptyCallback);
        sptr<IPressureStatusCallback> emptyPressureCallback = nullptr;
        SetPressureCallback(emptyPressureCallback);
        stateMachine_.Transfer(CaptureSessionState::SESSION_RELEASED);
        isSessionStarted_ = false;
    });
    MEDIA_INFO_LOG("HCaptureSession::Release execute success, sessionID: %{public}d", sid);
    return errorCode;
}

int32_t HCaptureSession::Release()
{
    MEDIA_INFO_LOG("HCaptureSession::Release(), sessionID: %{public}d", GetSessionId());
    CameraReportUtils::GetInstance().SetModeChangePerfStartInfo(opMode_, CameraReportUtils::GetCallerInfo());
    return Release(CaptureSessionReleaseType::RELEASE_TYPE_CLIENT);
}

int32_t HCaptureSession::OperatePermissionCheck(uint32_t interfaceCode)
{
    CHECK_ERROR_RETURN_RET_LOG(stateMachine_.GetCurrentState() == CaptureSessionState::SESSION_RELEASED,
        CAMERA_INVALID_STATE,
        "HCaptureSession::OperatePermissionCheck session is released");
    switch (static_cast<ICaptureSessionIpcCode>(interfaceCode)) {
        case ICaptureSessionIpcCode::COMMAND_START: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            CHECK_ERROR_RETURN_RET_LOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HCaptureSession::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                "is %{public}d", callerToken_, callerToken);
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    int32_t errCode = OperatePermissionCheck(code);
    CHECK_ERROR_RETURN_RET_LOG(errCode != CAMERA_OK, errCode, "HCaptureSession::OperatePermissionCheck fail");

    switch (static_cast<ICaptureSessionIpcCode>(code)) {
        case ICaptureSessionIpcCode::COMMAND_SET_FEATURE_MODE: {
            CHECK_ERROR_RETURN_RET_LOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCaptureSession::CheckSystemApp fail");
            break;
        }
        case ICaptureSessionIpcCode::COMMAND_RELEASE: {
            CameraXCollie cameraXCollie("hcaptureSessionStub::Release");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}
int32_t HCaptureSession::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

void HCaptureSession::DestroyStubObjectForPid(pid_t pid)
{
    auto& sessionManager = HCameraSessionManager::GetInstance();
    MEDIA_DEBUG_LOG("camera stub session groups(%{public}zu) pid(%{public}d).", sessionManager.GetGroupCount(), pid);
    auto sessions = sessionManager.GetGroupSessions(pid);
    for (auto& session : sessions) {
        session->Release(CaptureSessionReleaseType::RELEASE_TYPE_CLIENT_DIED);
    }
    sessionManager.RemoveGroup(pid);
    MEDIA_DEBUG_LOG("camera stub session groups(%{public}zu).", sessionManager.GetGroupCount());
}

int32_t HCaptureSession::SetCallback(const sptr<ICaptureSessionCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_WARNING_LOG("HCaptureSession::SetCallback callback is null, we "
                          "should clear the callback, sessionID: %{public}d",
            GetSessionId());
    }
    // Not implement yet.
    return CAMERA_OK;
}

int32_t HCaptureSession::UnSetCallback()
{
    // Not implement yet.
    return CAMERA_OK;
}

int32_t HCaptureSession::SetPressureCallback(const sptr<IPressureStatusCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_WARNING_LOG("HCaptureSession::SetPressureCallback callback is null, we "
                          "should clear the callback, sessionID: %{public}d",
            GetSessionId());
    }
    innerPressureCallback_ = callback;

    return CAMERA_OK;
}

int32_t HCaptureSession::UnSetPressureCallback()
{
    innerPressureCallback_ = nullptr;
    return CAMERA_OK;
}

void HCaptureSession::SetPressureStatus(PressureStatus status)
{
    MEDIA_INFO_LOG("HCaptureSession::SetPressureStatus(), status: %{public}d", status);
    CHECK_ERROR_RETURN_LOG(innerPressureCallback_ == nullptr, "innerPressureCallback is null.");
    innerPressureCallback_->OnPressureStatusChanged(status);
}

std::string HCaptureSession::GetSessionState()
{
    auto currentState = stateMachine_.GetCurrentState();
    std::map<CaptureSessionState, std::string>::const_iterator iter = SESSION_STATE_STRING_MAP.find(currentState);
    CHECK_ERROR_RETURN_RET(iter != SESSION_STATE_STRING_MAP.end(), iter->second);
    return std::to_string(static_cast<uint32_t>(currentState));
}

void HCaptureSession::DumpCameraSessionSummary(CameraInfoDumper& infoDumper)
{
    infoDumper.Msg("Number of Camera sessions:[" +
                   std::to_string(HCameraSessionManager::GetInstance().GetTotalSessionSize()) + "]");
}

void HCaptureSession::DumpSessions(CameraInfoDumper& infoDumper)
{
    auto totalSession = HCameraSessionManager::GetInstance().GetTotalSession();
    uint32_t index = 0;
    for (auto& session : totalSession) {
        infoDumper.Title("Camera Sessions[" + std::to_string(index++) + "] Info:");
        session->DumpSessionInfo(infoDumper);
    }
}

void HCaptureSession::DumpSessionInfo(CameraInfoDumper& infoDumper)
{
    infoDumper.Msg("Client pid:[" + std::to_string(pid_) + "]    Client uid:[" + std::to_string(uid_) + "]");
    infoDumper.Msg("session state:[" + GetSessionState() + "]");
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperatorSptr is null");
    for (auto& stream : hStreamOperatorSptr->GetAllStreams()) {
        infoDumper.Push();
        stream->DumpStreamInfo(infoDumper);
        infoDumper.Pop();
    }
}

int32_t HCaptureSession::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(hStreamOperatorSptr == nullptr, CAMERA_OK, "hStreamOperatorSptr is null");
    hStreamOperatorSptr->EnableMovingPhotoMirror(isMirror, isConfig);
    return CAMERA_OK;
}

void HCaptureSession::GetOutputStatus(int32_t& status)
{
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperatorSptr is null");
    hStreamOperatorSptr->GetOutputStatus(status);
}

void HCaptureSession::SetCameraDevice(sptr<HCameraDevice> device)
{
    std::lock_guard<std::mutex> lock(cameraDeviceLock_);
    if (cameraDevice_ != nullptr) {
        cameraDevice_->SetCameraCloseListener(nullptr);
    }
    if (device != nullptr) {
        device->SetCameraCloseListener(this);
    }
    cameraDevice_ = device;

    auto hStreamOperatorSptr = GetStreamOperator();
    if (hStreamOperatorSptr != nullptr) {
        hStreamOperatorSptr->SetCameraDevice(device);
    }
}

std::string HCaptureSession::CreateDisplayName(const std::string& suffix)
{
    struct tm currentTime;
    std::string formattedTime = "";
    if (GetSystemCurrentTime(&currentTime)) {
        std::stringstream ss;
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1) << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_mday << connector << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_hour << std::setw(otherWidth) << std::setfill(placeholder)
           << currentTime.tm_min << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_ERR_LOG("Failed to get current time.sessionID: %{public}d", GetSessionId());
    }
    if (lastDisplayName_ == formattedTime) {
        saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(saveIndex);
        MEDIA_INFO_LOG(
            "CreateDisplayName is %{private}s, sessionID: %{public}d", formattedTime.c_str(), GetSessionId());
        return formattedTime;
    }
    lastDisplayName_ = formattedTime;
    saveIndex = 0;
    MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

std::string HCaptureSession::CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId)
{
    struct tm currentTime;
    std::string formattedTime = "";
    std::stringstream ss;
    // a group of burst capture use the same prefix
    if (imageSeqId == 1) {
        CHECK_ERROR_RETURN_RET_LOG(!GetSystemCurrentTime(&currentTime), formattedTime, "Failed to get current time.");
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1) << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_mday << connector << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_hour << std::setw(otherWidth) << std::setfill(placeholder)
           << currentTime.tm_min << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec
           << connector << burstTag;
        lastBurstPrefix_ = ss.str();
        ss << std::setw(burstWidth) << std::setfill(placeholder) << seqId;
    } else {
        ss << lastBurstPrefix_ << std::setw(burstWidth) << std::setfill(placeholder) << seqId;
    }
    MEDIA_DEBUG_LOG("burst prefix is %{private}s, sessionID: %{public}d", lastBurstPrefix_.c_str(), GetSessionId());

    if (seqId == 1) {
        ss << coverTag;
    }
    formattedTime = ss.str();
    MEDIA_INFO_LOG(
        "CreateBurstDisplayName is %{private}s, sessionID: %{public}d", formattedTime.c_str(), GetSessionId());
    return formattedTime;
}

int32_t HCaptureSession::SetFeatureMode(int32_t featureMode)
{
    MEDIA_INFO_LOG("SetFeatureMode is called!sessionID: %{public}d", GetSessionId());
    featureMode_ = featureMode;
    return CAMERA_OK;
}

StateMachine::StateMachine()
{
    stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_INIT)] = {
        CaptureSessionState::SESSION_CONFIG_INPROGRESS, CaptureSessionState::SESSION_RELEASED
    };

    stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_CONFIG_INPROGRESS)] = {
        CaptureSessionState::SESSION_CONFIG_COMMITTED, CaptureSessionState::SESSION_RELEASED
    };

    stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_CONFIG_COMMITTED)] = {
        CaptureSessionState::SESSION_CONFIG_INPROGRESS, CaptureSessionState::SESSION_STARTED,
        CaptureSessionState::SESSION_RELEASED
    };

    stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_STARTED)] = {
        CaptureSessionState::SESSION_CONFIG_INPROGRESS, CaptureSessionState::SESSION_CONFIG_COMMITTED,
        CaptureSessionState::SESSION_RELEASED
    };

    stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_RELEASED)] = {};
}

bool StateMachine::CheckTransfer(CaptureSessionState targetState)
{
    std::lock_guard<std::recursive_mutex> lock(sessionStateLock_);
    return any_of(stateTransferMap_[static_cast<uint32_t>(currentState_)].begin(),
        stateTransferMap_[static_cast<uint32_t>(currentState_)].end(),
        [&targetState](const auto& state) { return state == targetState; });
}

bool StateMachine::Transfer(CaptureSessionState targetState)
{
    std::lock_guard<std::recursive_mutex> lock(sessionStateLock_);
    if (CheckTransfer(targetState)) {
        currentState_ = targetState;
        return true;
    }
    return false;
}

#ifdef HOOK_CAMERA_OPERATOR
void HCaptureSession::UpdateHookBasicInfo(ParameterMap parameterMap)
{
    std::lock_guard<std::mutex> lock(cameraRotateUpdateBasicInfo_);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    auto hStreamOperatorSptr = GetStreamOperator();
    CHECK_ERROR_RETURN_LOG(hStreamOperatorSptr == nullptr, "hStreamOperatorSptr is null");
    MEDIA_INFO_LOG("UpdateHookBasicInfo size %{public}zu", parameterMap.size());
    auto streams = hStreamOperatorSptr->GetAllStreams();
    for (auto& stream : streams) {
        if (stream->GetStreamType() != StreamType::REPEAT) {
            continue;
        }
        sptr<OHOS::IBufferProducer> previewProducer = nullptr;
        sptr<OHOS::IBufferProducer> videoProducer = nullptr;
        auto curStreamRepeat = CastStream<HStreamRepeat>(stream);
        if (curStreamRepeat->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
            previewProducer = curStreamRepeat->GetStreamProducer();
        }
        if (curStreamRepeat->GetRepeatStreamType() == RepeatStreamType::VIDEO) {
            videoProducer = curStreamRepeat->GetStreamProducer();
        }
        UpdateBasicInfoForStream(parameterMap, previewProducer, videoProducer, settings);
        continue;
    }
    auto cameraDevive = GetCameraDevice();
    CHECK_ERROR_RETURN_LOG(cameraDevive == nullptr, "cameraDevive is null.");
    cameraDevive->UpdateSettingOnce(settings);
}

void HCaptureSession::UpdateBasicInfoForStream(ParameterMap ParameterMap, sptr<OHOS::IBufferProducer> previewProducer,
    sptr<OHOS::IBufferProducer> videoProducer, std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    for (const auto& pair : ParameterMap) {
        int32_t code = pair.first;
        MEDIA_DEBUG_LOG("UpdateBasicInfoForStream code is %{public}d, value is %{public}s",
            code, (pair.second).c_str());
        if (code != PLUGIN_SURFACE_APP_FWK_TYPE && !isIntegerRegex(pair.second)) {
            continue;
        }
        switch (code) {
            case PLUGIN_PREVIEW_FORMAT: {
                CHECK_EXECUTE(previewProducer != nullptr,
                    previewProducer->SetTransform(static_cast<OHOS::GraphicTransformType>(std::stoi(pair.second))));
                break;
            }
            case PLUGIN_SURFACE_FRAME_GRAVITY: {
                CHECK_EXECUTE(previewProducer != nullptr,
                    previewProducer->SetFrameGravity(std::stoi(pair.second)));
                break;
            }
            case PLUGIN_SURFACE_FIXED_ROTATION:{
                CHECK_EXECUTE(previewProducer != nullptr,
                    previewProducer->SetFixedRotation(std::stoi(pair.second)));
                break;
            }
            case PLUGIN_SURFACE_APP_FWK_TYPE: {
                CHECK_EXECUTE(videoProducer != nullptr, videoProducer->SetSurfaceAppFrameworkType(pair.second));
                break;
            }
            case PLUGIN_VIDEO_SURFACE_TRANSFORM: {
                CHECK_EXECUTE(videoProducer != nullptr,
                    videoProducer->SetTransform(static_cast<OHOS::GraphicTransformType>(std::stoi(pair.second))));
                break;
            }
            default: {
                DealPluginCode(ParameterMap, settings, code, std::stoi(pair.second));
                break;
            }
        }
    }
}

void HCaptureSession::DealPluginCode(ParameterMap ParameterMap, std::shared_ptr<OHOS::Camera::CameraMetadata> settings,
    int32_t code, int32_t value)
{
    switch (code) {
        case PLUGIN_CAMERA_HAL_ROTATE_ANGLE: {
            int32_t rotateAngle = value;
            CHECK_EXECUTE(rotateAngle >= 0, settings->addEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateAngle, 1));
            break;
        }
        case PLUGIN_CAPTURE_MIRROR:
        case PLUGIN_VIDEO_MIRROR: {
            uint8_t mirror = static_cast<uint8_t>(value);
            CHECK_EXECUTE((mirror == 0 || mirror == 1), settings->addEntry(OHOS_CONTROL_CAPTURE_MIRROR,
                &mirror, 1));
            break;
        }
        case PLUGIN_JPEG_ORIENTATION: {
            int32_t jpegOrientation = value;
            CHECK_EXECUTE(jpegOrientation >= 0, settings->addEntry(OHOS_JPEG_ORIENTATION, &jpegOrientation, 1));
            break;
        }
        default:
            break;
    }
}
#endif

void HCaptureSession::SetUserId(int32_t userId)
{
    userId_ = userId;
}

int32_t HCaptureSession::GetUserId()
{
    return userId_;
}

void HCaptureSession::SetMechDeliveryState(MechDeliveryState state)
{
    std::lock_guard<std::mutex> lock(mechDeliveryStateLock_);
    mechDeliveryState_ = state;
}

MechDeliveryState HCaptureSession::GetMechDeliveryState()
{
    std::lock_guard<std::mutex> lock(mechDeliveryStateLock_);
    return mechDeliveryState_;
}

void HCaptureSession::UpdateSettingForFocusTrackingMechBeforeStart(std::shared_ptr<OHOS::Camera::CameraMetadata>&
    settings)
{
    MEDIA_DEBUG_LOG("HCaptureSession::UpdateSettingForFocusTrackingMechBeforeStart is called");
    std::lock_guard<std::mutex> lock(mechDeliveryStateLock_);
    if (mechDeliveryState_ == MechDeliveryState::NEED_ENABLE) {
        MEDIA_DEBUG_LOG("start EnableMechDelivery");
        int32_t count = 1;
        uint8_t value = OHOS_CAMERA_MECH_MODE_ON;
        settings->addEntry(OHOS_CONTROL_FOCUS_TRACKING_MECH, &value, count);
    }
}

int32_t HCaptureSession::UpdateSettingForFocusTrackingMech(bool isEnableMech)
{
    MEDIA_DEBUG_LOG("HCaptureSession::UpdateSettingForFocusTrackingMech is called, isEnableMech: %{public}d",
        isEnableMech);
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::UpdateSettingForFocusTrackingMech device is null");

    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    bool status = false;
    int32_t ret;
    int32_t count = 1;
    uint8_t value = isEnableMech? OHOS_CAMERA_MECH_MODE_ON : OHOS_CAMERA_MECH_MODE_OFF;
    camera_metadata_item_t item;

    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_FOCUS_TRACKING_MECH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_FOCUS_TRACKING_MECH, &value, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_FOCUS_TRACKING_MECH, &value, count);
    }
    ret = cameraDevice->UpdateSetting(changedMetadata);
    CHECK_ERROR_RETURN_RET_LOG(!status || ret != CAMERA_OK, CAMERA_UNKNOWN_ERROR,
        "UpdateSettingForFocusTrackingMech Failed");
    return CAMERA_OK;
}

bool HCaptureSession::GetCameraAppInfo(CameraAppInfo& appInfo)
{
    appInfo.zoomValue = 1.0f; // default zoom
    appInfo.cameraId = "";
    appInfo.position = -1;
    appInfo.width = 0;
    appInfo.height = 0;
    if (cameraDevice_ != nullptr) {
        appInfo.cameraId = cameraDevice_->GetCameraId();
        appInfo.zoomValue = cameraDevice_->GetZoomRatio();
        appInfo.position = cameraDevice_->GetCameraPosition();
    }
    appInfo.tokenId = static_cast<int32_t>(callerToken_);
    appInfo.opmode = opMode_;
    appInfo.equivalentFocus = GetEquivalentFocus();
    auto hStreamOperatorSptr = GetStreamOperator();
    if (hStreamOperatorSptr != nullptr) {
        auto streams = hStreamOperatorSptr->GetAllStreams();
        for (auto& stream : streams) {
            if (stream->GetStreamType() == StreamType::REPEAT) {
                auto curStreamRepeat = CastStream<HStreamRepeat>(stream);
                appInfo.width = curStreamRepeat->width_;
                appInfo.height = curStreamRepeat->height_;
            }
        }
    }
    auto currentState = stateMachine_.GetCurrentState();
    appInfo.videoStatus = (currentState == CaptureSessionState::SESSION_STARTED);
    return true;
}

void HCaptureSession::OnCameraAppInfo()
{
    auto &sessionManager = HCameraSessionManager::GetInstance();
    auto mechSession = sessionManager.GetMechSession(userId_);
    if (mechSession == nullptr) {
        return;
    }
    CameraAppInfo appInfo;
    if (!GetCameraAppInfo(appInfo)) {
        MEDIA_INFO_LOG("HCaptureSession::OnCameraAppInfo GetCameraAppInfo failed");
        return;
    }
    std::vector<CameraAppInfo> cameraAppInfos = {};
    cameraAppInfos.emplace_back(appInfo);
    mechSession->OnCameraAppInfo(cameraAppInfos);
}

uint32_t HCaptureSession::GetEquivalentFocus()
{
    auto cameraDevice = GetCameraDevice();
    uint32_t equivalentFocus = 0;
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr,
        equivalentFocus,
        "HCaptureSession::GetEquivalentFocus() "
        "cameraDevice is null, sessionID: %{public}d",
        GetSessionId());
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET(ability == nullptr, equivalentFocus);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_EQUIVALENT_FOCUS, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, equivalentFocus,
        "HCaptureSession::GetEquivalentFocus get equivalentFocus failed");
    for (uint32_t i = 0; i < item.count; i++) {
        if ((i & 1) == 0) {
            equivalentFocus = static_cast<uint32_t>(item.data.i32[i + 1]);
        }
    }
    MEDIA_DEBUG_LOG("HCaptureSession::GetEquivalentFocus equivalentFocus "
                   "%{public}d, sessionID: %{public}d",
        equivalentFocus,
        GetSessionId());
    return equivalentFocus;
}

int32_t HCaptureSession::EnableMechDelivery(bool isEnableMech)
{
    std::lock_guard<std::mutex> lock(mechDeliveryStateLock_);
    auto currentState = stateMachine_.GetCurrentState();
    switch (currentState) {
        case CaptureSessionState::SESSION_INIT:
        case CaptureSessionState::SESSION_CONFIG_INPROGRESS:
        case CaptureSessionState::SESSION_CONFIG_COMMITTED:
            isEnableMech ? mechDeliveryState_ = MechDeliveryState::NEED_ENABLE :
                mechDeliveryState_ = MechDeliveryState::NOT_ENABLED;
            break;
        case CaptureSessionState::SESSION_STARTED:
            isEnableMech ? mechDeliveryState_ = MechDeliveryState::ENABLED :
                mechDeliveryState_ = MechDeliveryState::NOT_ENABLED;
            UpdateSettingForFocusTrackingMech(isEnableMech);
            {
                auto hStreamOperatorSptr = GetStreamOperator();
                if (hStreamOperatorSptr != nullptr) {
                    hStreamOperatorSptr->UpdateSettingForFocusTrackingMech(isEnableMech);
                }
            }
            break;
        default:
            break;
    }
    return CAMERA_OK;
}
}  // namespace CameraStandard
}  // namespace OHOS