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
#include "camera_service_ipc_interface_code.h"
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
#include "iconsumer_surface.h"
#include "image_type.h"
#include "ipc_skeleton.h"
#include "istream_common.h"
#include "media_library/photo_asset_interface.h"
#include "media_library/photo_asset_proxy.h"
#include "media_photo_asset_proxy.h"
#include "moving_photo/moving_photo_surface_wrapper.h"
#include "moving_photo_video_cache.h"
#include "parameters.h"
#include "picture.h"
#include "refbase.h"
#include "smooth_zoom.h"
#include "surface.h"
#include "surface_buffer.h"
#include "v1_0/types.h"
#include "res_type.h"
#include "res_sched_client.h"

using namespace OHOS::AAFwk;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;

namespace {
#ifdef CAMERA_USE_SENSOR
constexpr int32_t POSTURE_INTERVAL = 100000000; // 100ms;
constexpr int VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT = 3;
#endif
static GravityData gravityData = { 0.0, 0.0, 0.0 };
static int32_t sensorRotation = 0;
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
} // namespace

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
    if (session == nullptr) {
        return CAMERA_ALLOC_ERROR;
    }

    auto& sessionManager = HCameraSessionManager::GetInstance();
    MEDIA_DEBUG_LOG("HCaptureSession::NewInstance start, total session:(%{public}zu), current pid(%{public}d).",
        sessionManager.GetTotalSessionSize(), session->pid_);
    errCode = sessionManager.AddSession(session); // Do not move this AddSession after RemoveSession
    if (errCode == CAMERA_SESSION_MAX_INSTANCE_NUMBER_REACHED) {
        auto previousSession = sessionManager.GetGroupDefaultSession(session->pid_);
        auto disconnectDevice = previousSession->GetCameraDevice();
        CHECK_EXECUTE(disconnectDevice != nullptr,
            disconnectDevice->OnError(HDI::Camera::V1_0::DEVICE_PREEMPT, 0));

        MEDIA_ERR_LOG("HCaptureSession::HCaptureSession not support multicamera, release last one.");
        previousSession->Release();
        sessionManager.RemoveSession(previousSession);
        errCode = CAMERA_OK; // If there is no error to throw, return CAMERA_OK.
    }
    outSession = session;
    MEDIA_INFO_LOG("HCaptureSession::NewInstance end, total session:(%{public}zu). current opMode_= %{public}d "
                   "errorCode:%{public}d",
        sessionManager.GetTotalSessionSize(), opMode, errCode);
    return errCode;
}

HCaptureSession::HCaptureSession(const uint32_t callingTokenId, int32_t opMode)
{
    pid_ = IPCSkeleton::GetCallingPid();
    uid_ = static_cast<uint32_t>(IPCSkeleton::GetCallingUid());
    callerToken_ = callingTokenId;
    opMode_ = opMode;
}

HCaptureSession::~HCaptureSession()
{
    CAMERA_SYNC_TRACE;
    Release(CaptureSessionReleaseType::RELEASE_TYPE_OBJ_DIED);
    if (displayListener_) {
        OHOS::Rosen::DisplayManager::GetInstance().UnregisterDisplayListener(displayListener_);
        displayListener_ = nullptr;
    }
}

pid_t HCaptureSession::GetPid()
{
    return pid_;
}

int32_t HCaptureSession::GetopMode()
{
    CHECK_ERROR_RETURN_RET(featureMode_, featureMode_);
    return opMode_;
}

int32_t HCaptureSession::GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos)
{
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream) {
            StreamInfo_V1_1 curStreamInfo;
            stream->SetStreamInfo(curStreamInfo);
            CHECK_EXECUTE(stream->GetStreamType() != StreamType::METADATA, streamInfos.push_back(curStreamInfo));
        }
    }
    return CAMERA_OK;
}

void HCaptureSession::DynamicConfigStream()
{
    isDynamicConfiged_ = false;
    MEDIA_INFO_LOG("HCaptureSession::DynamicConfigStream enter. currentState = %{public}s", GetSessionState().c_str());
    auto currentState = stateMachine_.GetCurrentState();
    if (currentState == CaptureSessionState::SESSION_STARTED) {
        isDynamicConfiged_ = CheckSystemApp(); // System applications support dynamic config stream.
        MEDIA_INFO_LOG("HCaptureSession::DynamicConfigStream support dynamic stream config");
    }
}

bool HCaptureSession::IsNeedDynamicConfig()
{
    return isDynamicConfiged_;
}

int32_t HCaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    int32_t errCode;
    MEDIA_INFO_LOG("HCaptureSession::BeginConfig prepare execute");
    stateMachine_.StateGuard([&errCode, this](const CaptureSessionState state) {
        DynamicConfigStream();
        bool isStateValid = stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_INPROGRESS);
        if (!isStateValid) {
            MEDIA_ERR_LOG("HCaptureSession::BeginConfig in invalid state %{public}d", state);
            errCode = CAMERA_INVALID_STATE;
            isDynamicConfiged_ = false;
            return;
        }
        if (!IsNeedDynamicConfig()) {
            UnlinkInputAndOutputs();
            ClearSketchRepeatStream();
            ClearMovingPhotoRepeatStream();
        }
    });
    if (errCode == CAMERA_OK) {
        MEDIA_INFO_LOG("HCaptureSession::BeginConfig execute success");
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::BeginConfig", errCode, false, CameraReportUtils::GetCallerInfo());
    }
    return errCode;
}

int32_t HCaptureSession::CanAddInput(sptr<ICameraDeviceService> cameraDevice, bool& result)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    result = false;
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::CanAddInput Need to call BeginConfig before adding input");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if ((GetCameraDevice() != nullptr)) {
            MEDIA_ERR_LOG("HCaptureSession::CanAddInput Only one input is supported");
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
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::CanAddInput"));
    }
    return errorCode;
}

int32_t HCaptureSession::AddInput(sptr<ICameraDeviceService> cameraDevice)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    if (cameraDevice == nullptr) {
        errorCode = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCaptureSession::AddInput cameraDevice is null");
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddInput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    MEDIA_INFO_LOG("HCaptureSession::AddInput prepare execute");
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::AddInput Need to call BeginConfig before adding input");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if ((GetCameraDevice() != nullptr)) {
            MEDIA_ERR_LOG("HCaptureSession::AddInput Only one input is supported");
            errorCode = CAMERA_INVALID_SESSION_CFG;
            return;
        }
        sptr<HCameraDevice> hCameraDevice = static_cast<HCameraDevice*>(cameraDevice.GetRefPtr());
        MEDIA_INFO_LOG("HCaptureSession::AddInput device:%{public}s", hCameraDevice->GetCameraId().c_str());
        auto deviceSession = hCameraDevice->GetStreamOperatorCallback();
        if (deviceSession != nullptr) {
            errorCode = CAMERA_OPERATION_NOT_ALLOWED;
            return;
        }
        hCameraDevice->SetStreamOperatorCallback(this);
        SetCameraDevice(hCameraDevice);
        hCameraDevice->DispatchDefaultSettingToHdi();
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddInput"));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddInput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("HCaptureSession::AddInput execute success");
    return errorCode;
}

int32_t HCaptureSession::AddOutputStream(sptr<HStreamCommon> stream)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(
        stream == nullptr, CAMERA_INVALID_ARG, "HCaptureSession::AddOutputStream stream is null");
    MEDIA_INFO_LOG("HCaptureSession::AddOutputStream streamId:%{public}d streamType:%{public}d",
        stream->GetFwkStreamId(), stream->GetStreamType());
    CHECK_ERROR_RETURN_RET_LOG(
        stream->GetFwkStreamId() == STREAM_ID_UNSET && stream->GetStreamType() != StreamType::METADATA,
        CAMERA_INVALID_ARG, "HCaptureSession::AddOutputStream stream is released!");
    bool isAddSuccess = streamContainer_.AddStream(stream);
    CHECK_ERROR_RETURN_RET_LOG(
        !isAddSuccess, CAMERA_INVALID_SESSION_CFG, "HCaptureSession::AddOutputStream add stream fail");
    if (stream->GetStreamType() == StreamType::CAPTURE) {
        auto captureStream = CastStream<HStreamCapture>(stream);
        captureStream->SetMode(opMode_);
        captureStream->SetColorSpace(currCaptureColorSpace_);
        CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO);
    } else {
        stream->SetColorSpace(currColorSpace_);
    }
    return CAMERA_OK;
}

void HCaptureSession::StartMovingPhotoStream()
{
    int32_t errorCode = 0;
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_COMMITTED) {
            MEDIA_ERR_LOG("EnableMovingPhoto, invalid session state: %{public}d, start after preview", currentState);
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
        bool isPreviewStarted = false;
        for (auto& item : repeatStreams) {
            auto curStreamRepeat = CastStream<HStreamRepeat>(item);
            auto repeatType = curStreamRepeat->GetRepeatStreamType();
            if (repeatType != RepeatStreamType::PREVIEW) {
                continue;
            }
            if (curStreamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET && curStreamRepeat->producer_ != nullptr) {
                isPreviewStarted = true;
                break;
            }
        }
        CHECK_ERROR_RETURN_LOG(!isPreviewStarted, "EnableMovingPhoto, preview is not streaming");
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
        auto cameraDevice = GetCameraDevice();
        if (cameraDevice != nullptr) {
            settings = cameraDevice->CloneCachedSettings();
            DumpMetadata(settings);
        }
        for (auto& item : repeatStreams) {
            auto curStreamRepeat = CastStream<HStreamRepeat>(item);
            auto repeatType = curStreamRepeat->GetRepeatStreamType();
            if (repeatType != RepeatStreamType::LIVEPHOTO) {
                continue;
            }
            if (isSetMotionPhoto_) {
                errorCode = curStreamRepeat->Start(settings);
#ifdef MOVING_PHOTO_ADD_AUDIO
                std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
                audioCapturerSession_ != nullptr && audioCapturerSession_->StartAudioCapture();
#endif
            } else {
                errorCode = curStreamRepeat->Stop();
                StopMovingPhoto();
            }
            break;
        }
    });
    MEDIA_INFO_LOG("HCaptureSession::StartMovingPhotoStream result:%{public}d", errorCode);
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

void HCaptureSession::RegisterDisplayListener(sptr<HStreamRepeat> repeat)
{
    if (displayListener_ == nullptr) {
        displayListener_ = new DisplayRotationListener();
        OHOS::Rosen::DisplayManager::GetInstance().RegisterDisplayListener(displayListener_);
    }
    displayListener_->AddHstreamRepeatForListener(repeat);
}

void HCaptureSession::UnregisterDisplayListener(sptr<HStreamRepeat> repeatStream)
{
    CHECK_EXECUTE(displayListener_, displayListener_->RemoveHstreamRepeatForListener(repeatStream));
}

int32_t HCaptureSession::SetPreviewRotation(std::string& deviceClass)
{
    enableStreamRotate_ = true;
    deviceClass_ = deviceClass;
    return CAMERA_OK;
}

int32_t HCaptureSession::AddOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutput stream is null");
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    stateMachine_.StateGuard([this, &errorCode, streamType, &stream](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::AddOutput Need to call BeginConfig before adding output");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        // Temp hack to fix the library linking issue
        sptr<IConsumerSurface> captureSurface = IConsumerSurface::Create();
        if (streamType == StreamType::CAPTURE) {
            errorCode = AddOutputStream(static_cast<HStreamCapture*>(stream.GetRefPtr()));
        } else if (streamType == StreamType::REPEAT) {
            HStreamRepeat* repeatSteam = static_cast<HStreamRepeat*>(stream.GetRefPtr());
            if (enableStreamRotate_ && repeatSteam != nullptr &&
                repeatSteam->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
                RegisterDisplayListener(repeatSteam);
                repeatSteam->SetPreviewRotation(deviceClass_);
            }
            errorCode = AddOutputStream(repeatSteam);
        } else if (streamType == StreamType::METADATA) {
            errorCode = AddOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
        } else if (streamType == StreamType::DEPTH) {
            errorCode = AddOutputStream(static_cast<HStreamDepthData*>(stream.GetRefPtr()));
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddOutput with %d", streamType));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::AddOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("CaptureSession::AddOutput with with %{public}d, rc = %{public}d", streamType, errorCode);
    return errorCode;
}

int32_t HCaptureSession::RemoveInput(sptr<ICameraDeviceService> cameraDevice)
{
    int32_t errorCode = CAMERA_OK;
    if (cameraDevice == nullptr) {
        errorCode = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCaptureSession::RemoveInput cameraDevice is null");
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveInput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveInput prepare execute");
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::RemoveInput Need to call BeginConfig before removing input");
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
            MEDIA_ERR_LOG("HCaptureSession::RemoveInput Invalid camera device");
            errorCode = CAMERA_INVALID_SESSION_CFG;
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveInput"));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveInput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveInput execute success");
    return errorCode;
}

int32_t HCaptureSession::RemoveOutputStream(sptr<HStreamCommon> stream)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(
        stream == nullptr, CAMERA_INVALID_ARG, "HCaptureSession::RemoveOutputStream stream is null");
    MEDIA_INFO_LOG("HCaptureSession::RemoveOutputStream,streamType:%{public}d, streamId:%{public}d",
        stream->GetStreamType(), stream->GetFwkStreamId());
    bool isRemoveSuccess = streamContainer_.RemoveStream(stream);
    CHECK_ERROR_RETURN_RET_LOG(
        !isRemoveSuccess, CAMERA_INVALID_SESSION_CFG, "HCaptureSession::RemoveOutputStream Invalid output");
    return CAMERA_OK;
}

int32_t HCaptureSession::RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutput stream is null");
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveOutput prepare execute");
    stateMachine_.StateGuard([this, &errorCode, streamType, &stream](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::RemoveOutput Need to call BeginConfig before removing output");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if (streamType == StreamType::CAPTURE) {
            errorCode = RemoveOutputStream(static_cast<HStreamCapture*>(stream.GetRefPtr()));
            CameraDynamicLoader::FreeDynamiclib(MEDIA_LIB_SO);
        } else if (streamType == StreamType::REPEAT) {
            HStreamRepeat* repeatSteam = static_cast<HStreamRepeat*>(stream.GetRefPtr());
            if (enableStreamRotate_ && repeatSteam != nullptr &&
                repeatSteam->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
                UnregisterDisplayListener(repeatSteam);
            }
            errorCode = RemoveOutputStream(repeatSteam);
        } else if (streamType == StreamType::METADATA) {
            errorCode = RemoveOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveOutput with %d", streamType));
    } else {
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::RemoveOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_INFO_LOG("HCaptureSession::RemoveOutput execute success");
    return errorCode;
}

int32_t HCaptureSession::ValidateSessionInputs()
{
    CHECK_ERROR_RETURN_RET_LOG(GetCameraDevice() == nullptr, CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::ValidateSessionInputs No inputs present");
    return CAMERA_OK;
}

int32_t HCaptureSession::ValidateSessionOutputs()
{
    CHECK_ERROR_RETURN_RET_LOG(streamContainer_.Size() == 0, CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::ValidateSessionOutputs No outputs present");
    return CAMERA_OK;
}

int32_t HCaptureSession::LinkInputAndOutputs()
{
    int32_t rc;
    std::vector<StreamInfo_V1_1> allStreamInfos;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    auto device = GetCameraDevice();
    MEDIA_INFO_LOG("HCaptureSession::LinkInputAndOutputs prepare execute");
    CHECK_ERROR_RETURN_RET_LOG(
        device == nullptr, CAMERA_INVALID_SESSION_CFG, "HCaptureSession::LinkInputAndOutputs device is null");
    auto settings = device->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET_LOG(
        settings == nullptr, CAMERA_UNKNOWN_ERROR, "HCaptureSession::LinkInputAndOutputs deviceAbility is null");
    streamOperator = device->GetStreamOperator();
    auto allStream = streamContainer_.GetAllStreams();
    MEDIA_INFO_LOG("HCaptureSession::LinkInputAndOutputs allStream size:%{public}zu", allStream.size());
    CHECK_ERROR_RETURN_RET_LOG(!IsValidMode(opMode_, settings), CAMERA_INVALID_SESSION_CFG,
        "HCaptureSession::LinkInputAndOutputs IsValidMode false");
    for (auto& stream : allStream) {
        rc = stream->LinkInput(streamOperator, settings);
        if (rc == CAMERA_OK) {
            CHECK_EXECUTE(stream->GetHdiStreamId() == STREAM_ID_UNSET,
                stream->SetHdiStreamId(device->GenerateHdiStreamId()));
        }
        MEDIA_INFO_LOG(
            "HCaptureSession::LinkInputAndOutputs streamType:%{public}d, streamId:%{public}d ,hdiStreamId:%{public}d",
            stream->GetStreamType(), stream->GetFwkStreamId(), stream->GetHdiStreamId());
        CHECK_ERROR_RETURN_RET_LOG(rc != CAMERA_OK, rc, "HCaptureSession::LinkInputAndOutputs IsValidMode false");
        StreamInfo_V1_1 curStreamInfo;
        stream->SetStreamInfo(curStreamInfo);
        CHECK_EXECUTE(stream->GetStreamType() != StreamType::METADATA,
            allStreamInfos.push_back(curStreamInfo));
    }

    rc = device->CreateAndCommitStreams(allStreamInfos, settings, GetopMode());
    MEDIA_INFO_LOG("HCaptureSession::LinkInputAndOutputs execute success");
    return rc;
}

int32_t HCaptureSession::UnlinkInputAndOutputs()
{
    CAMERA_SYNC_TRACE;
    int32_t rc = CAMERA_UNKNOWN_ERROR;
    std::vector<int32_t> fwkStreamIds;
    std::vector<int32_t> hdiStreamIds;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        fwkStreamIds.emplace_back(stream->GetFwkStreamId());
        hdiStreamIds.emplace_back(stream->GetHdiStreamId());
        stream->UnlinkInput();
    }
    MEDIA_INFO_LOG("HCaptureSession::UnlinkInputAndOutputs() streamIds size() = %{public}zu, streamIds:%{public}s, "
                   "hdiStreamIds:%{public}s",
        fwkStreamIds.size(), Container2String(fwkStreamIds.begin(), fwkStreamIds.end()).c_str(),
        Container2String(hdiStreamIds.begin(), hdiStreamIds.end()).c_str());

    // HDI release streams, do not clear streamContainer_
    auto cameraDevice = GetCameraDevice();
    if ((cameraDevice != nullptr)) {
        cameraDevice->ReleaseStreams(hdiStreamIds);
        std::vector<StreamInfo_V1_1> emptyStreams;
        cameraDevice->UpdateStreams(emptyStreams);
        cameraDevice->ResetHdiStreamId();
    }
    return rc;
}

void HCaptureSession::ExpandSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HCaptureSession::ExpandSketchRepeatStream()");
    std::set<sptr<HStreamCommon>> sketchStreams;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::SKETCH) {
            continue;
        }
        sptr<HStreamRepeat> sketchStream = streamRepeat->GetSketchStream();
        if (sketchStream == nullptr) {
            continue;
        }
        sketchStreams.insert(sketchStream);
    }
    MEDIA_DEBUG_LOG("HCaptureSession::ExpandSketchRepeatStream() sketch size is:%{public}zu", sketchStreams.size());
    for (auto& stream : sketchStreams) {
        AddOutputStream(stream);
    }
    MEDIA_DEBUG_LOG("Exit HCaptureSession::ExpandSketchRepeatStream()");
}

VideoCodecType GetVideoCodecType(StreamContainer& streamContainer)
{
    auto captureStreams = streamContainer.GetStreams(StreamType::CAPTURE);
    MEDIA_INFO_LOG("GetVideoCodecType capture stream size = %{public}zu", captureStreams.size());
    VideoCodecType videoCodecType = VIDEO_ENCODE_TYPE_AVC;
    for (auto& stream : captureStreams) {
        auto streamCapture = CastStream<HStreamCapture>(stream);
        if (streamCapture == nullptr) {
            continue;
        }
        videoCodecType = static_cast<VideoCodecType>(streamCapture->GetMovingPhotoVideoCodecType());
        break;
    }
    MEDIA_INFO_LOG("ExpandMovingPhotoRepeatStream GetVideoCodecType videoCodecType = %{public}d", videoCodecType);
    return videoCodecType;
}

void HCaptureSession::ExpandMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream enter");
    if (!GetCameraDevice()->CheckMovingPhotoSupported(GetopMode())) {
        MEDIA_DEBUG_LOG("movingPhoto is not supported");
        return;
    }
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat && streamRepeat->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
            std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
            auto movingPhotoSurfaceWrapper =
                MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper(streamRepeat->width_, streamRepeat->height_);
            if (movingPhotoSurfaceWrapper == nullptr) {
                MEDIA_ERR_LOG("HCaptureSession::ExpandMovingPhotoRepeatStream CreateMovingPhotoSurfaceWrapper fail.");
                continue;
            }
            auto producer = movingPhotoSurfaceWrapper->GetProducer();
            metaSurface_ = Surface::CreateSurfaceAsConsumer("movingPhotoMeta");
            auto metaCache = make_shared<FixedSizeList<pair<int64_t, sptr<SurfaceBuffer>>>>(3);
            CHECK_WARNING_CONTINUE_LOG(producer == nullptr, "get producer fail.");
            livephotoListener_ = new (std::nothrow) MovingPhotoListener(
                movingPhotoSurfaceWrapper, metaSurface_, metaCache, preCacheFrameCount_, postCacheFrameCount_);
            CHECK_WARNING_CONTINUE_LOG(livephotoListener_ == nullptr, "failed to new livephotoListener_!");
            movingPhotoSurfaceWrapper->SetSurfaceBufferListener(livephotoListener_);
            livephotoMetaListener_ = new (std::nothrow) MovingPhotoMetaListener(metaSurface_, metaCache);
            CHECK_WARNING_CONTINUE_LOG(livephotoMetaListener_ == nullptr, "failed to new livephotoMetaListener_!");
            metaSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)livephotoMetaListener_);
            CreateMovingPhotoStreamRepeat(streamRepeat->format_, streamRepeat->width_, streamRepeat->height_, producer);
            std::lock_guard<std::mutex> streamLock(livePhotoStreamLock_);
            AddOutputStream(livePhotoStreamRepeat_);
            if (!audioCapturerSession_) {
                audioCapturerSession_ = new AudioCapturerSession();
            }
            if (!taskManager_ && audioCapturerSession_) {
                taskManager_ = new AvcodecTaskManager(audioCapturerSession_, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC);
                taskManager_->SetVideoBufferDuration(preCacheFrameCount_, postCacheFrameCount_);
            }
            if (!videoCache_ && taskManager_) {
                videoCache_ = new MovingPhotoVideoCache(taskManager_);
            }
            break;
        }
    }
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream Exit");
}

int32_t HCaptureSession::CreateMovingPhotoStreamRepeat(
    int32_t format, int32_t width, int32_t height, sptr<OHOS::IBufferProducer> producer)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(livePhotoStreamLock_);
    CHECK_ERROR_RETURN_RET_LOG(
        width <= 0 || height <= 0, CAMERA_INVALID_ARG, "HCameraService::CreateLivePhotoStreamRepeat args is illegal");
    CHECK_EXECUTE(livePhotoStreamRepeat_ != nullptr, livePhotoStreamRepeat_->Release());
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::LIVEPHOTO);
    CHECK_ERROR_RETURN_RET_LOG(streamRepeat == nullptr, CAMERA_ALLOC_ERROR, "HStreamRepeat allocation failed");
    MEDIA_DEBUG_LOG("para is:%{public}dx%{public}d,%{public}d", width, height, format);
    livePhotoStreamRepeat_ = streamRepeat;
    streamRepeat->SetMetaProducer(metaSurface_->GetProducer());
    streamRepeat->SetMirror(isMovingPhotoMirror_);
    MEDIA_INFO_LOG("HCameraService::CreateLivePhotoStreamRepeat end");
    return CAMERA_OK;
}

const sptr<HStreamCommon> HCaptureSession::GetStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetStream(streamId);
    CHECK_ERROR_PRINT_LOG(
        stream == nullptr, "HCaptureSession::GetStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    return stream;
}

const sptr<HStreamCommon> HCaptureSession::GetHdiStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetHdiStream(streamId);
    CHECK_ERROR_PRINT_LOG(
        stream == nullptr, "HCaptureSession::GetHdiStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    return stream;
}

void HCaptureSession::ClearSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HCaptureSession::ClearSketchRepeatStream()");

    // Already added session lock in BeginConfig()
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& repeatStream : repeatStreams) {
        if (repeatStream == nullptr) {
            continue;
        }
        auto sketchStream = CastStream<HStreamRepeat>(repeatStream);
        if (sketchStream->GetRepeatStreamType() != RepeatStreamType::SKETCH) {
            continue;
        }
        MEDIA_DEBUG_LOG(
            "HCaptureSession::ClearSketchRepeatStream() stream id is:%{public}d", sketchStream->GetFwkStreamId());
        RemoveOutputStream(repeatStream);
    }
    MEDIA_DEBUG_LOG("Exit HCaptureSession::ClearSketchRepeatStream()");
}

void HCaptureSession::ClearMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter HCaptureSession::ClearMovingPhotoRepeatStream()");
    // Already added session lock in BeginConfig()
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& repeatStream : repeatStreams) {
        if (repeatStream == nullptr) {
            continue;
        }
        auto movingPhotoStream = CastStream<HStreamRepeat>(repeatStream);
        if (movingPhotoStream->GetRepeatStreamType() != RepeatStreamType::LIVEPHOTO) {
            continue;
        }
        StopMovingPhoto();
        std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
        livephotoListener_ = nullptr;
        videoCache_ = nullptr;
        MEDIA_DEBUG_LOG("HCaptureSession::ClearLivePhotoRepeatStream() stream id is:%{public}d",
            movingPhotoStream->GetFwkStreamId());
        RemoveOutputStream(repeatStream);
    }
    MEDIA_DEBUG_LOG("Exit HCaptureSession::ClearLivePhotoRepeatStream()");
}

void HCaptureSession::StopMovingPhoto() __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter HCaptureSession::StopMovingPhoto");
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    CHECK_EXECUTE(livephotoListener_, livephotoListener_->StopDrainOut());
    CHECK_EXECUTE(videoCache_, videoCache_->ClearCache());
#ifdef MOVING_PHOTO_ADD_AUDIO
    CHECK_EXECUTE(audioCapturerSession_, audioCapturerSession_->Stop());
#endif
    CHECK_EXECUTE(taskManager_, taskManager_->Stop());
}

int32_t HCaptureSession::ValidateSession()
{
    int32_t errorCode = CAMERA_OK;
    errorCode = ValidateSessionInputs();
    CHECK_ERROR_RETURN_RET(errorCode != CAMERA_OK, errorCode);
    errorCode = ValidateSessionOutputs();
    return errorCode;
}

int32_t HCaptureSession::CommitConfig()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCaptureSession::CommitConfig begin");
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Need to call BeginConfig before committing configuration");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        errorCode = ValidateSession();
        CHECK_ERROR_RETURN(errorCode != CAMERA_OK);
        if (!IsNeedDynamicConfig()) {
            // expand moving photo always
            ExpandMovingPhotoRepeatStream();
            ExpandSketchRepeatStream();
        }
        auto device = GetCameraDevice();
        if (device == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. camera device is null");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        const int32_t secureMode = 15;
        uint64_t secureSeqId = 0L;
        device->GetSecureCameraSeq(&secureSeqId);
        if (((GetopMode() == secureMode) ^ (secureSeqId != 0))) {
            MEDIA_ERR_LOG("secureCamera is not allowed commit mode = %{public}d.", GetopMode());
            errorCode = CAMERA_OPERATION_NOT_ALLOWED;
            return;
        }

        MEDIA_INFO_LOG("HCaptureSession::CommitConfig secureSeqId = %{public}" PRIu64 "", secureSeqId);
        errorCode = LinkInputAndOutputs();
        CHECK_ERROR_RETURN_LOG(errorCode != CAMERA_OK,
            "HCaptureSession::CommitConfig() Failed to commit config. rc: %{public}d", errorCode);
        stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
    });
    CHECK_EXECUTE(errorCode != CAMERA_OK,
        CameraReportUtils::ReportCameraError(
            "HCaptureSession::CommitConfig", errorCode, false, CameraReportUtils::GetCallerInfo()));
    MEDIA_INFO_LOG("HCaptureSession::CommitConfig end");
    return errorCode;
}

int32_t HCaptureSession::GetActiveColorSpace(ColorSpace& colorSpace)
{
    colorSpace = currColorSpace_;
    return CAMERA_OK;
}

int32_t HCaptureSession::SetColorSpace(ColorSpace colorSpace, ColorSpace captureColorSpace, bool isNeedUpdate)
{
    int32_t result = CAMERA_OK;
    CHECK_ERROR_RETURN_RET_LOG(colorSpace == currColorSpace_ && captureColorSpace == currCaptureColorSpace_, result,
        "HCaptureSession::SetColorSpace() colorSpace no need to update.");
    stateMachine_.StateGuard(
        [&result, this, &colorSpace, &captureColorSpace, &isNeedUpdate](CaptureSessionState currentState) {
            if (!(currentState == CaptureSessionState::SESSION_CONFIG_INPROGRESS ||
                    currentState == CaptureSessionState::SESSION_CONFIG_COMMITTED)) {
                MEDIA_ERR_LOG("HCaptureSession::SetColorSpace(), Invalid session state: %{public}d", currentState);
                result = CAMERA_INVALID_STATE;
                return;
            }

            currColorSpace_ = colorSpace;
            currCaptureColorSpace_ = captureColorSpace;
            result = CheckIfColorSpaceMatchesFormat(colorSpace);
            if (result != CAMERA_OK) {
                if (isNeedUpdate) {
                    MEDIA_ERR_LOG("HCaptureSession::SetColorSpace() Failed, format and colorSpace not match.");
                    return;
                } else {
                    MEDIA_ERR_LOG(
                        "HCaptureSession::SetColorSpace() %{public}d, format and colorSpace: %{public}d not match.",
                        result, colorSpace);
                    currColorSpace_ = ColorSpace::BT709;
                }
            }
            MEDIA_INFO_LOG("HCaptureSession::SetColorSpace() colorSpace: %{public}d, captureColorSpace: %{public}d, "
                           "isNeedUpdate: %{public}d",
                currColorSpace_, captureColorSpace, isNeedUpdate);
            SetColorSpaceForStreams();

            if (isNeedUpdate) {
                result = UpdateStreamInfos();
            }
        });
    return result;
}

void HCaptureSession::SetColorSpaceForStreams()
{
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        MEDIA_DEBUG_LOG("HCaptureSession::SetColorSpaceForStreams() streams type %{public}d", stream->GetStreamType());
        if (stream->GetStreamType() == StreamType::CAPTURE) {
            stream->SetColorSpace(currCaptureColorSpace_);
        } else {
            stream->SetColorSpace(currColorSpace_);
        }
    }
}

void HCaptureSession::CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos)
{
    MEDIA_INFO_LOG("HCaptureSession::CancelStreamsAndGetStreamInfos enter.");
    StreamInfo_V1_1 curStreamInfo;
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream && stream->GetStreamType() == StreamType::METADATA) {
            continue;
        }
        if (stream && stream->GetStreamType() == StreamType::CAPTURE && isSessionStarted_) {
            static_cast<HStreamCapture*>(stream.GetRefPtr())->CancelCapture();
        } else if (stream && stream->GetStreamType() == StreamType::REPEAT && isSessionStarted_) {
            static_cast<HStreamRepeat*>(stream.GetRefPtr())->Stop();
        }
        if (stream) {
            stream->SetStreamInfo(curStreamInfo);
            streamInfos.push_back(curStreamInfo);
        }
    }
}

void HCaptureSession::RestartStreams()
{
    MEDIA_INFO_LOG("HCaptureSession::RestartStreams() enter.");
    if (!isSessionStarted_) {
        MEDIA_DEBUG_LOG("HCaptureSession::RestartStreams() session is not started yet.");
        return;
    }
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN(cameraDevice == nullptr);
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream && stream->GetStreamType() == StreamType::REPEAT &&
            CastStream<HStreamRepeat>(stream)->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
            std::shared_ptr<OHOS::Camera::CameraMetadata> settings = cameraDevice->CloneCachedSettings();
            MEDIA_INFO_LOG("HCaptureSession::RestartStreams() CloneCachedSettings");
            DumpMetadata(settings);
            CastStream<HStreamRepeat>(stream)->Start(settings);
        }
    }
}

int32_t HCaptureSession::UpdateStreamInfos()
{
    std::vector<StreamInfo_V1_1> streamInfos;
    CancelStreamsAndGetStreamInfos(streamInfos);

    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, CAMERA_UNKNOWN_ERROR, "HCaptureSession::UpdateStreamInfos() cameraDevice is null");
    int errorCode = cameraDevice->UpdateStreams(streamInfos);
    if (errorCode == CAMERA_OK) {
        RestartStreams();
    } else {
        MEDIA_DEBUG_LOG("HCaptureSession::UpdateStreamInfos err %{public}d", errorCode);
    }
    return errorCode;
}

int32_t HCaptureSession::CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace)
{
    if (!(colorSpace == ColorSpace::BT2020_HLG || colorSpace == ColorSpace::BT2020_PQ ||
            colorSpace == ColorSpace::BT2020_HLG_LIMIT || colorSpace == ColorSpace::BT2020_PQ_LIMIT)) {
        return CAMERA_OK;
    }

    // 选择BT2020，需要匹配10bit的format；若不匹配，返回error
    auto streams = streamContainer_.GetAllStreams();
    for (auto& curStream : streams) {
        if (!curStream) {
            continue;
        }
        // 当前拍照流不支持BT2020，无需校验format
        if (curStream->GetStreamType() != StreamType::REPEAT) {
            continue;
        }
        StreamInfo_V1_1 curStreamInfo;
        curStream->SetStreamInfo(curStreamInfo);
        MEDIA_INFO_LOG("HCaptureSession::CheckFormat, stream repeatType: %{public}d, format: %{public}d",
            static_cast<HStreamRepeat*>(curStream.GetRefPtr())->GetRepeatStreamType(), curStreamInfo.v1_0.format_);
        CHECK_ERROR_RETURN_RET_LOG(
            !(curStreamInfo.v1_0.format_ == OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCBCR_P010 ||
                curStreamInfo.v1_0.format_ == OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCRCB_P010),
            CAMERA_OPERATION_NOT_ALLOWED, "HCaptureSession::CheckFormat, stream format not match");
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::GetSessionState(CaptureSessionState& sessionState)
{
    sessionState = stateMachine_.GetCurrentState();
    return CAMERA_OK;
}

bool HCaptureSession::QueryFpsAndZoomRatio(float& currentFps, float& currentZoomRatio)
{
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, false, "HCaptureSession::QueryFpsAndZoomRatio() cameraDevice is null");
    int32_t DEFAULT_ITEMS = 2;
    int32_t DEFAULT_DATA_LENGTH = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint32_t count = 1;
    uint32_t fps = 30;
    uint32_t zoomRatio = 100;
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_FPS, &fps, count);
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &zoomRatio, count);
    cameraDevice->GetStatus(metaIn, metaOut);

    camera_metadata_item_t item;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &item);
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryFpsAndZoomRatio() current zoom not found");
        return false;
    } else if (retFindMeta == CAM_META_SUCCESS) {
        currentZoomRatio = static_cast<float>(item.data.ui32[0]);
        MEDIA_INFO_LOG("HCaptureSession::QueryFpsAndZoomRatio() current zoom %{public}d.", item.data.ui32[0]);
    }
    retFindMeta = OHOS::Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_FPS, &item);
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryFpsAndZoomRatio() current fps not found");
        return false;
    } else if (retFindMeta == CAM_META_SUCCESS) {
        currentFps = static_cast<float>(item.data.ui32[0]);
        MEDIA_INFO_LOG("HCaptureSession::QueryFpsAndZoomRatio() current fps %{public}d.", item.data.ui32[0]);
    }
    return true;
}

bool HCaptureSession::QueryZoomPerformance(std::vector<float>& crossZoomAndTime, int32_t operationMode)
{
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, false, "HCaptureSession::QueryZoomPerformance() cameraDevice is null");
    // query zoom performance. begin
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    camera_metadata_item_t zoomItem;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE, &zoomItem);
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryZoomPerformance() current zoom not found");
        return false;
    } else if (retFindMeta == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance() zoom performance count %{public}d.", zoomItem.count);
        for (int i = 0; i < static_cast<int>(zoomItem.count); i++) {
            MEDIA_DEBUG_LOG(
                "HCaptureSession::QueryZoomPerformance() zoom performance value %{public}d.", zoomItem.data.ui32[i]);
        }
    }
    int dataLenPerPoint = 3;
    int headLenPerMode = 2;
    MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance() operationMode %{public}d.",
        static_cast<OHOS::HDI::Camera::V1_3::OperationMode>(operationMode));
    for (int i = 0; i < static_cast<int>(zoomItem.count);) {
        int sceneMode = static_cast<int>(zoomItem.data.ui32[i]);
        int zoomPointsNum = static_cast<int>(zoomItem.data.ui32[i + 1]);
        if (static_cast<OHOS::HDI::Camera::V1_3::OperationMode>(operationMode) == sceneMode) {
            for (int j = 0; j < dataLenPerPoint * zoomPointsNum; j++) {
                crossZoomAndTime.push_back(zoomItem.data.ui32[i + headLenPerMode + j]);
                MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance()  crossZoomAndTime %{public}d.",
                    static_cast<int>(zoomItem.data.ui32[i + headLenPerMode + j]));
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
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, sensorOrientation, "HCaptureSession::GetSensorOritation() cameraDevice is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET(ability == nullptr, sensorOrientation);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, sensorOrientation,
        "HCaptureSession::GetSensorOritation get sensor orientation failed");
    sensorOrientation = item.data.i32[0];
    MEDIA_INFO_LOG("HCaptureSession::GetSensorOritation sensor orientation %{public}d", sensorOrientation);
    return sensorOrientation;
}

int32_t HCaptureSession::GetMovingPhotoBufferDuration()
{
    auto cameraDevice = GetCameraDevice();
    uint32_t preBufferDuration = 0;
    uint32_t postBufferDuration = 0;
    constexpr int32_t MILLSEC_MULTIPLE = 1000;
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, 0, "HCaptureSession::GetMovingPhotoBufferDuration() cameraDevice is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET(ability == nullptr, 0);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_MOVING_PHOTO_BUFFER_DURATION, &item);
    CHECK_ERROR_RETURN_RET_LOG(
        ret != CAM_META_SUCCESS, 0, "HCaptureSession::GetMovingPhotoBufferDuration get buffer duration failed");
    preBufferDuration = item.data.ui32[0];
    postBufferDuration = item.data.ui32[1];
    preCacheFrameCount_ = preBufferDuration == 0
                              ? preCacheFrameCount_
                              : static_cast<uint32_t>(float(preBufferDuration) / MILLSEC_MULTIPLE * VIDEO_FRAME_RATE);
    postCacheFrameCount_ = preBufferDuration == 0
                               ? postCacheFrameCount_
                               : static_cast<uint32_t>(float(postBufferDuration) / MILLSEC_MULTIPLE * VIDEO_FRAME_RATE);
    MEDIA_INFO_LOG(
        "HCaptureSession::GetMovingPhotoBufferDuration preBufferDuration : %{public}u, "
        "postBufferDuration : %{public}u, preCacheFrameCount_ : %{public}u, postCacheFrameCount_ : %{public}u",
        preBufferDuration, postBufferDuration, preCacheFrameCount_, postCacheFrameCount_);
    return CAMERA_OK;
}

int32_t HCaptureSession::GetRangeId(float& zoomRatio, std::vector<float>& crossZoom)
{
    int32_t rangId = 0;
    for (; rangId < static_cast<int>(crossZoom.size()); rangId++) {
        if (zoomRatio < crossZoom[rangId]) {
            return rangId;
        }
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
    MEDIA_DEBUG_LOG("HCaptureSession::GetCrossWaitTime waitTime %{public}f, targetRangeId %{public}d,"
                    " currentRangeId %{public}d",
        waitTime, targetRangeId, currentRangeId);
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
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryZoomBezierValue() current bezierValue not found");
        return false;
    }
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
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice == nullptr, CAMERA_UNKNOWN_ERROR, "HCaptureSession::SetSmoothZoom device is null");
    float currentFps = 30.0f;
    float currentZoomRatio = 1.0f;
    int32_t targetRangeId = 0;
    int32_t currentRangeId = 0;
    QueryFpsAndZoomRatio(currentFps, currentZoomRatio);
    std::vector<float> crossZoomAndTime {};
    std::vector<float> zoomBezierValue {};
    QueryZoomPerformance(crossZoomAndTime, operationMode);
    std::vector<float> mCrossZoom {};
    int32_t waitCount = 4;
    int32_t zoomInOutCount = 2;
    std::vector<std::vector<float>> crossTime(waitCount, std::vector<float>(zoomInOutCount, 0.0f)); // 生成4x2二维数组
    GetCrossZoomAndTime(crossZoomAndTime, mCrossZoom, crossTime);
    float waitTime = 0.0;
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
    for (int i = 0; i < static_cast<int>(mCrossZoom.size()); i++) {
        float crossZoom = mCrossZoom[i];
        if ((crossZoom - currentZoomRatio) * (crossZoom - targetZoomRatio) > 0 || isEqual(crossZoom, 199.0f)) {
            continue;
        }
        if (std::fabs(currentZoomRatio - crossZoom) <= std::numeric_limits<float>::epsilon() &&
            currentZoomRatio > targetZoomRatio) {
            waitTime = waitMs;
        }
        for (int j = 0; j < static_cast<int>(array.size()); j++) {
            if (static_cast<int>(array[j] - crossZoom) * static_cast<int>(array[0] - crossZoom) < 0) {
                waitTime = fmax(waitMs - frameIntervalMs * j, waitTime);
                break;
            }
        }
    }
    std::vector<uint32_t> zoomAndTimeArray {};
    for (int i = 0; i < static_cast<int>(array.size()); i++) {
        zoomAndTimeArray.push_back(static_cast<uint32_t>(array[i]));
        zoomAndTimeArray.push_back(static_cast<uint32_t>(i * frameIntervalMs + waitTime));
        MEDIA_DEBUG_LOG("HCaptureSession::SetSmoothZoom() zoom %{public}d, waitMs %{public}d.",
            static_cast<uint32_t>(array[i]), static_cast<uint32_t>(i * frameIntervalMs + waitTime));
    }
    duration = (static_cast<int>(array.size()) - 1) * frameIntervalMs + waitTime;
    MEDIA_DEBUG_LOG("HCaptureSession::SetSmoothZoom() duration %{public}f", duration);
    ProcessMetaZoomArray(zoomAndTimeArray, cameraDevice);
    return CAMERA_OK;
}

void HCaptureSession::ProcessMetaZoomArray(std::vector<uint32_t>& zoomAndTimeArray, sptr<HCameraDevice>& cameraDevice)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaZoomArray = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    uint32_t zoomCount = static_cast<uint32_t>(zoomAndTimeArray.size());
    MEDIA_INFO_LOG("HCaptureSession::ProcessMetaZoomArray() zoomArray size: %{public}zu, zoomCount: %{public}u",
        zoomAndTimeArray.size(), zoomCount);
    metaZoomArray->addEntry(OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, zoomAndTimeArray.data(), zoomCount);
    cameraDevice->UpdateSettingOnce(metaZoomArray);
}

int32_t HCaptureSession::EnableMovingPhoto(bool isEnable)
{
    isSetMotionPhoto_ = isEnable;
    StartMovingPhotoStream();
#ifdef CAMERA_USE_SENSOR
    if (isSetMotionPhoto_) {
        RegisterSensorCallback();
    } else {
        UnregisterSensorCallback();
    }
#endif
    auto device = GetCameraDevice();
    CHECK_EXECUTE(device != nullptr, device->EnableMovingPhoto(isEnable));
    GetMovingPhotoBufferDuration();
    GetMovingPhotoStartAndEndTime();
    return CAMERA_OK;
}

int32_t HCaptureSession::Start()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    MEDIA_INFO_LOG("HCaptureSession::Start prepare execute");
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_STARTED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Start() Need to call after committing configuration");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }

        std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
        auto cameraDevice = GetCameraDevice();
        uint8_t usedAsPositionU8 = OHOS_CAMERA_POSITION_OTHER;
        MEDIA_INFO_LOG("HCaptureSession::Start usedAsPositionU8 default = %{public}d", usedAsPositionU8);
        if (cameraDevice != nullptr) {
            settings = cameraDevice->CloneCachedSettings();
            usedAsPositionU8 = cameraDevice->GetUsedAsPosition();
            MEDIA_INFO_LOG("HCaptureSession::Start usedAsPositionU8 set %{public}d", usedAsPositionU8);
            DumpMetadata(settings);
            UpdateMuteSetting(cameraDevice->GetDeviceMuteMode(), settings);
        }
        camera_position_enum_t cameraPosition = static_cast<camera_position_enum_t>(usedAsPositionU8);
        errorCode = StartPreviewStream(settings, cameraPosition);
        if (errorCode == CAMERA_OK) {
            isSessionStarted_ = true;
        }
        stateMachine_.Transfer(CaptureSessionState::SESSION_STARTED);
    });
    MEDIA_INFO_LOG("HCaptureSession::Start execute success");
    return errorCode;
}

void HCaptureSession::UpdateMuteSetting(bool muteMode, std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    int32_t count = 1;
    uint8_t mode = muteMode ? OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK : OHOS_CAMERA_MUTE_MODE_OFF;
    settings->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
}

void HCaptureSession::StartMovingPhoto(sptr<HStreamRepeat>& curStreamRepeat)
{
    auto thisPtr = wptr<HCaptureSession>(this);
    curStreamRepeat->SetMovingPhotoStartCallback([thisPtr]() {
        auto sessionPtr = thisPtr.promote();
        if (sessionPtr != nullptr) {
            MEDIA_INFO_LOG("StartMovingPhotoStream when addDeferedSurface");
            sessionPtr->StartMovingPhotoStream();
        }
    });
}

void HCaptureSession::GetMovingPhotoStartAndEndTime()
{
    auto thisPtr = wptr<HCaptureSession>(this);
    auto cameraDevice = GetCameraDevice();
    CHECK_ERROR_RETURN_LOG(cameraDevice == nullptr, "HCaptureSession::GetMovingPhotoStartAndEndTime device is null");
    cameraDevice->SetMovingPhotoStartTimeCallback([thisPtr](int32_t captureId, int64_t startTimeStamp) {
        MEDIA_INFO_LOG("SetMovingPhotoStartTimeCallback function enter");
        auto sessionPtr = thisPtr.promote();
        CHECK_ERROR_RETURN_LOG(sessionPtr == nullptr, "Set start time callback sessionPtr is null");
        CHECK_ERROR_RETURN_LOG(sessionPtr->taskManager_ == nullptr, "Set start time callback taskManager_ is null");
        std::lock_guard<mutex> lock(sessionPtr->taskManager_->startTimeMutex_);
        if (sessionPtr->taskManager_->mPStartTimeMap_.count(captureId) == 0) {
            MEDIA_INFO_LOG("Save moving photo start info, captureId : %{public}d, start timestamp : %{public}" PRIu64,
                captureId, startTimeStamp);
            sessionPtr->taskManager_->mPStartTimeMap_.insert(make_pair(captureId, startTimeStamp));
        }
    });

    cameraDevice->SetMovingPhotoEndTimeCallback([thisPtr](int32_t captureId, int64_t endTimeStamp) {
        auto sessionPtr = thisPtr.promote();
        CHECK_ERROR_RETURN_LOG(sessionPtr == nullptr, "Set end time callback sessionPtr is null");
        CHECK_ERROR_RETURN_LOG(sessionPtr->taskManager_ == nullptr, "Set end time callback taskManager_ is null");
        std::lock_guard<mutex> lock(sessionPtr->taskManager_->endTimeMutex_);
        if (sessionPtr->taskManager_->mPEndTimeMap_.count(captureId) == 0) {
            MEDIA_INFO_LOG("Save moving photo end info, captureId : %{public}d, end timestamp : %{public}" PRIu64,
                captureId, endTimeStamp);
            sessionPtr->taskManager_->mPEndTimeMap_.insert(make_pair(captureId, endTimeStamp));
        }
    });
}

int32_t HCaptureSession::StartPreviewStream(
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings, camera_position_enum_t cameraPosition)
{
    int32_t errorCode = CAMERA_OK;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    bool hasDerferedPreview = false;
    // start preview
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType != RepeatStreamType::PREVIEW) {
            continue;
        }
        if (curStreamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET) {
            continue;
        }
        curStreamRepeat->SetUsedAsPosition(cameraPosition);
        errorCode = curStreamRepeat->Start(settings);
        hasDerferedPreview = curStreamRepeat->producer_ == nullptr;
        CHECK_EXECUTE(isSetMotionPhoto_ && hasDerferedPreview, StartMovingPhoto(curStreamRepeat));
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSession::Start(), Failed to start preview, rc: %{public}d", errorCode);
            break;
        }
    }
    // start movingPhoto
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType != RepeatStreamType::LIVEPHOTO) {
            continue;
        }
        int32_t movingPhotoErrorCode = CAMERA_OK;
        if (isSetMotionPhoto_ && !hasDerferedPreview) {
            movingPhotoErrorCode = curStreamRepeat->Start(settings);
#ifdef MOVING_PHOTO_ADD_AUDIO
            std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
            audioCapturerSession_ != nullptr && audioCapturerSession_->StartAudioCapture();
#endif
        }
        if (movingPhotoErrorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to start movingPhoto, rc: %{public}d", movingPhotoErrorCode);
            break;
        }
    }
    return errorCode;
}

int32_t HCaptureSession::Stop()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    MEDIA_INFO_LOG("HCaptureSession::Stop prepare execute");
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Stop() Need to call after Start");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        auto allStreams = streamContainer_.GetAllStreams();
        for (auto& item : allStreams) {
            if (item->GetStreamType() == StreamType::REPEAT) {
                auto repeatStream = CastStream<HStreamRepeat>(item);
                if (repeatStream->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
                    errorCode = repeatStream->Stop();
                } else if (repeatStream->GetRepeatStreamType() == RepeatStreamType::LIVEPHOTO) {
                    repeatStream->Stop();
                    StopMovingPhoto();
                } else {
                    repeatStream->Stop();
                }
            } else if (item->GetStreamType() == StreamType::METADATA) {
                CastStream<HStreamMetadata>(item)->Stop();
            } else if (item->GetStreamType() == StreamType::CAPTURE) {
                CastStream<HStreamCapture>(item)->CancelCapture();
            } else if (item->GetStreamType() == StreamType::DEPTH) {
                CastStream<HStreamDepthData>(item)->Stop();
            } else {
                MEDIA_ERR_LOG("HCaptureSession::Stop(), get unknow stream, streamType: %{public}d, streamId:%{public}d",
                    item->GetStreamType(), item->GetFwkStreamId());
            }
            CHECK_ERROR_PRINT_LOG(errorCode != CAMERA_OK,
                "HCaptureSession::Stop(), Failed to stop stream, rc: %{public}d, streamId:%{public}d",
                errorCode, item->GetFwkStreamId());
        }
        if (errorCode == CAMERA_OK) {
            isSessionStarted_ = false;
        }
        stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
    });
    MEDIA_INFO_LOG("HCaptureSession::Stop execute success");
    return errorCode;
}

void HCaptureSession::ReleaseStreams()
{
    CAMERA_SYNC_TRACE;
    std::vector<int32_t> fwkStreamIds;
    std::vector<int32_t> hdiStreamIds;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        auto fwkStreamId = stream->GetFwkStreamId();
        CHECK_EXECUTE(fwkStreamId != STREAM_ID_UNSET, fwkStreamIds.emplace_back(fwkStreamId));
        auto hdiStreamId = stream->GetHdiStreamId();
        CHECK_EXECUTE(hdiStreamId != STREAM_ID_UNSET, hdiStreamIds.emplace_back(hdiStreamId));
        stream->ReleaseStream(true);
    }
    streamContainer_.Clear();
    MEDIA_INFO_LOG("HCaptureSession::ReleaseStreams() streamIds size() = %{public}zu, fwkStreamIds:%{public}s, "
                   "hdiStreamIds:%{public}s,",
        fwkStreamIds.size(), Container2String(fwkStreamIds.begin(), fwkStreamIds.end()).c_str(),
        Container2String(hdiStreamIds.begin(), hdiStreamIds.end()).c_str());
    auto cameraDevice = GetCameraDevice();
    CHECK_EXECUTE((cameraDevice != nullptr) && !hdiStreamIds.empty(), cameraDevice->ReleaseStreams(hdiStreamIds));
}

int32_t HCaptureSession::Release(CaptureSessionReleaseType type)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    MEDIA_INFO_LOG("HCaptureSession::Release prepare execute, release type is:%{public}d pid(%{public}d)", type, pid_);
    // Check release without lock first
    CHECK_ERROR_RETURN_RET_LOG(stateMachine_.IsStateNoLock(CaptureSessionState::SESSION_RELEASED), CAMERA_INVALID_STATE,
        "HCaptureSession::Release error, session is already released!");

    stateMachine_.StateGuard([&errorCode, this, type](CaptureSessionState currentState) {
        MEDIA_INFO_LOG("HCaptureSession::Release pid(%{public}d). release type is:%{public}d", pid_, type);
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_RELEASED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Release error, this session is already released!");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        // stop movingPhoto
        StopMovingPhoto();

        // Clear outputs
        ReleaseStreams();

        // Clear inputs
        auto cameraDevice = GetCameraDevice();
        if (cameraDevice != nullptr) {
            cameraDevice->Release();
            SetCameraDevice(nullptr);
        }

        // Clear current session
        if (type != CaptureSessionReleaseType::RELEASE_TYPE_OBJ_DIED) {
            HCameraSessionManager::GetInstance().RemoveSession(this);
            MEDIA_DEBUG_LOG("HCaptureSession::Release clear pid left sessions(%{public}zu).",
                HCameraSessionManager::GetInstance().GetTotalSessionSize());
        }
#ifdef CAMERA_USE_SENSOR
        CHECK_EXECUTE(isSetMotionPhoto_, UnregisterSensorCallback());
#endif
        stateMachine_.Transfer(CaptureSessionState::SESSION_RELEASED);
        isSessionStarted_ = false;
        if (displayListener_) {
            OHOS::Rosen::DisplayManager::GetInstance().UnregisterDisplayListener(displayListener_);
            displayListener_ = nullptr;
        }
        std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
        livephotoListener_ = nullptr;
        videoCache_ = nullptr;
        if (taskManager_) {
            taskManager_->ClearTaskResource();
            taskManager_ = nullptr;
        }
    });
    MEDIA_INFO_LOG("HCaptureSession::Release execute success");
    return errorCode;
}

int32_t HCaptureSession::Release()
{
    MEDIA_INFO_LOG("HCaptureSession::Release()");
    CameraReportUtils::GetInstance().SetModeChangePerfStartInfo(opMode_, CameraReportUtils::GetCallerInfo());
    return Release(CaptureSessionReleaseType::RELEASE_TYPE_CLIENT);
}

int32_t HCaptureSession::OperatePermissionCheck(uint32_t interfaceCode)
{
    CHECK_ERROR_RETURN_RET_LOG(stateMachine_.GetCurrentState() == CaptureSessionState::SESSION_RELEASED,
        CAMERA_INVALID_STATE, "HCaptureSession::OperatePermissionCheck session is released");
    switch (static_cast<CaptureSessionInterfaceCode>(interfaceCode)) {
        case CAMERA_CAPTURE_SESSION_START: {
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

int32_t HCaptureSession::SetCallback(sptr<ICaptureSessionCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_WARNING_LOG("HCaptureSession::SetCallback callback is null, we should clear the callback");
    }
    // Not implement yet.
    return CAMERA_OK;
}

int32_t HCaptureSession::UnSetCallback()
{
    // Not implement yet.
    return CAMERA_OK;
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
    for (auto& stream : streamContainer_.GetAllStreams()) {
        infoDumper.Push();
        stream->DumpStreamInfo(infoDumper);
        infoDumper.Pop();
    }
}

int32_t HCaptureSession::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
    if (!isConfig) {
        isMovingPhotoMirror_ = isMirror;
        return CAMERA_OK;
    }
    if (!isSetMotionPhoto_ || isMirror == isMovingPhotoMirror_) {
        return CAMERA_OK;
    }
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::LIVEPHOTO) {
            MEDIA_INFO_LOG("restart movingphoto stream.");
            if (streamRepeat->SetMirrorForLivePhoto(isMirror, opMode_)) {
                isMovingPhotoMirror_ = isMirror;
                // set clear cache flag
                std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
                livephotoListener_->SetClearFlag();
            }
            break;
        }
    }
    return CAMERA_OK;
}

void HCaptureSession::GetOutputStatus(int32_t& status)
{
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::VIDEO) {
            if (streamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET) {
                const int32_t videoStartStatus = 2;
                status = videoStartStatus;
            }
        }
    }
}

#ifdef CAMERA_USE_SENSOR
void HCaptureSession::RegisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    if (isRegisterSensorSuccess_) {
        MEDIA_INFO_LOG("HCaptureSession::RegisterSensorCallback isRegisterSensorSuccess return");
        return;
    }
    MEDIA_INFO_LOG("HCaptureSession::RegisterSensorCallback start");
    user.callback = GravityDataCallbackImpl;
    int32_t subscribeRet = SubscribeSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, subscribeRet: %{public}d", subscribeRet);
    int32_t setBatchRet = SetBatch(SENSOR_TYPE_ID_GRAVITY, &user, POSTURE_INTERVAL, 0);
    MEDIA_INFO_LOG("RegisterSensorCallback, setBatchRet: %{public}d", setBatchRet);
    int32_t activateRet = ActivateSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, activateRet: %{public}d", activateRet);
    if (subscribeRet != CAMERA_OK || setBatchRet != CAMERA_OK || activateRet != CAMERA_OK) {
        isRegisterSensorSuccess_ = false;
        MEDIA_INFO_LOG("RegisterSensorCallback failed.");
    } else {
        isRegisterSensorSuccess_ = true;
    }
}

void HCaptureSession::UnregisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    int32_t deactivateRet = DeactivateSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    int32_t unsubscribeRet = UnsubscribeSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    if (deactivateRet == CAMERA_OK && unsubscribeRet == CAMERA_OK) {
        MEDIA_INFO_LOG("HCameraService.UnregisterSensorCallback success.");
        isRegisterSensorSuccess_ = false;
    } else {
        MEDIA_INFO_LOG("HCameraService.UnregisterSensorCallback failed.");
    }
}

void HCaptureSession::GravityDataCallbackImpl(SensorEvent* event)
{
    MEDIA_INFO_LOG("GravityDataCallbackImpl prepare execute");
    CHECK_ERROR_RETURN_LOG(event == nullptr, "SensorEvent is nullptr.");
    CHECK_ERROR_RETURN_LOG(event[0].data == nullptr, "SensorEvent[0].data is nullptr.");
    CHECK_ERROR_RETURN_LOG(event->sensorTypeId != SENSOR_TYPE_ID_GRAVITY, "SensorCallback error type.");
    // this data will be delete when callback execute finish
    GravityData* nowGravityData = reinterpret_cast<GravityData*>(event->data);
    gravityData = { nowGravityData->x, nowGravityData->y, nowGravityData->z };
    sensorRotation = CalcSensorRotation(CalcRotationDegree(gravityData));
}

int32_t HCaptureSession::CalcSensorRotation(int32_t sensorDegree)
{
    // Use ROTATION_0 when degree range is [0, 30]∪[330, 359]
    if (sensorDegree >= 0 && (sensorDegree <= 30 || sensorDegree >= 330)) {
        return STREAM_ROTATE_0;
    } else if (sensorDegree >= 60 && sensorDegree <= 120) { // Use ROTATION_90 when degree range is [60, 120]
        return STREAM_ROTATE_90;
    } else if (sensorDegree >= 150 && sensorDegree <= 210) { // Use ROTATION_180 when degree range is [150, 210]
        return STREAM_ROTATE_180;
    } else if (sensorDegree >= 240 && sensorDegree <= 300) { // Use ROTATION_270 when degree range is [240, 300]
        return STREAM_ROTATE_270;
    } else {
        return sensorRotation;
    }
}

int32_t HCaptureSession::CalcRotationDegree(GravityData data)
{
    float x = data.x;
    float y = data.y;
    float z = data.z;
    int degree = -1;
    CHECK_ERROR_RETURN_RET((x * x + y * y) * VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT < z * z, degree);
    // arccotx = pi / 2 - arctanx, 90 is used to calculate acot(in degree); degree = rad / pi * 180
    degree = 90 - static_cast<int>(round(atan2(y, -x) / M_PI * 180));
    // Normalize the degree to the range of 0~360
    return degree >= 0 ? degree % 360 : degree % 360 + 360;
}
#endif

void HCaptureSession::StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId)
{
    CHECK_ERROR_RETURN(!isSetMotionPhoto_);
    int32_t addMirrorRotation = 0;
    MEDIA_INFO_LOG("sensorRotation is %{public}d", sensorRotation);
    if ((sensorRotation == STREAM_ROTATE_0 || sensorRotation == STREAM_ROTATE_180) && isMovingPhotoMirror_) {
        addMirrorRotation = STREAM_ROTATE_180;
    }
    int32_t realRotation = GetSensorOritation() + rotation + addMirrorRotation;
    realRotation = realRotation % ROTATION_360;
    StartRecord(timestamp, realRotation, captureId);
}

std::string HCaptureSession::CreateDisplayName()
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
        MEDIA_ERR_LOG("Failed to get current time.");
    }
    if (lastDisplayName_ == formattedTime) {
        saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(saveIndex);
        MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
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
    MEDIA_DEBUG_LOG("burst prefix is %{private}s", lastBurstPrefix_.c_str());

    if (seqId == 1) {
        ss << coverTag;
    }
    formattedTime = ss.str();
    MEDIA_INFO_LOG("CreateBurstDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

void HCaptureSession::SetCameraPhotoProxyInfo(
    sptr<CameraServerPhotoProxy> cameraPhotoProxy, int32_t& cameraShotType, bool& isBursting, std::string& burstKey)
{
    cameraPhotoProxy->SetShootingMode(opMode_);
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    std::string imageId = cameraPhotoProxy->GetPhotoId();
    isBursting = false;
    bool isCoverPhoto = false;
    int32_t invalidBurstSeqId = -1;
    auto captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    for (auto& stream : captureStreams) {
        CHECK_WARNING_CONTINUE_LOG(stream == nullptr, "stream is null");
        MEDIA_INFO_LOG("CreateMediaLibrary get captureStream");
        auto streamCapture = CastStream<HStreamCapture>(stream);
        isBursting = streamCapture->IsBurstCapture(captureId);
        if (isBursting) {
            burstKey = streamCapture->GetBurstKey(captureId);
            streamCapture->SetBurstImages(captureId, imageId);
            isCoverPhoto = streamCapture->IsBurstCover(captureId);
            int32_t burstSeqId = cameraPhotoProxy->GetBurstSeqId();
            int32_t imageSeqId = streamCapture->GetCurBurstSeq(captureId);
            int32_t displaySeqId = (burstSeqId != invalidBurstSeqId) ? burstSeqId : imageSeqId;
            cameraPhotoProxy->SetDisplayName(CreateBurstDisplayName(imageSeqId, displaySeqId));
            streamCapture->CheckResetBurstKey(captureId);
            MEDIA_INFO_LOG("isBursting burstKey:%{public}s isCoverPhoto:%{public}d", burstKey.c_str(), isCoverPhoto);
            int32_t burstShotType = 3;
            cameraShotType = burstShotType;
            cameraPhotoProxy->SetBurstInfo(burstKey, isCoverPhoto);
            break;
        }
        MEDIA_INFO_LOG("CreateMediaLibrary not Bursting");
    }
}

int32_t HCaptureSession::CreateMediaLibrary(sptr<CameraPhotoProxy>& photoProxy, std::string& uri,
    int32_t& cameraShotType, std::string& burstKey, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    constexpr int32_t movingPhotoShotType = 2;
    constexpr int32_t imageShotType = 0;
    cameraShotType = isSetMotionPhoto_ ? movingPhotoShotType : imageShotType;
    MessageParcel data;
    photoProxy->WriteToParcel(data);
    photoProxy->CameraFreeBufferHandle();
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->ReadFromParcel(data);
    cameraPhotoProxy->SetDisplayName(CreateDisplayName());
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    bool isBursting = false;
    string pictureId = cameraPhotoProxy->GetTitle() + "." + cameraPhotoProxy->GetExtension();
    CameraReportDfxUtils::GetInstance()->SetPictureId(captureId, pictureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo(captureId);
    SetCameraPhotoProxyInfo(cameraPhotoProxy, cameraShotType, isBursting, burstKey);
    auto photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, IPCSkeleton::GetCallingUid());
    CHECK_ERROR_RETURN_RET_LOG(
        photoAssetProxy == nullptr, CAMERA_ALLOC_ERROR, "HCaptureSession::CreateMediaLibrary get photoAssetProxy fail");
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
    uri = photoAssetProxy->GetPhotoAssetUri();
    if (!isBursting && isSetMotionPhoto_ && taskManager_) {
        MEDIA_INFO_LOG("taskManager setVideoFd start");
        taskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    } else {
        photoAssetProxy.reset();
    }
    CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo(captureId);
    return CAMERA_OK;
}

static std::unordered_map<std::string, float> exifOrientationDegree = {
    { "Top-left", 0 },
    { "Top-right", 90 },
    { "Bottom-right", 180 },
    { "Right-top", 90 },
    { "Left-bottom", 270 },
};

inline float TransExifOrientationToDegree(const std::string& orientation)
{
    float degree = .0;
    if (exifOrientationDegree.count(orientation)) {
        degree = exifOrientationDegree[orientation];
    }
    return degree;
}

inline void RotatePixelMap(std::shared_ptr<Media::PixelMap> pixelMap, const std::string& exifOrientation)
{
    float degree = TransExifOrientationToDegree(exifOrientation);
    if (pixelMap) {
        MEDIA_INFO_LOG("RotatePicture degree is %{public}f", degree);
        pixelMap->rotate(degree);
    } else {
        MEDIA_ERR_LOG("RotatePicture Failed pixelMap is nullptr");
    }
}

std::string GetAndSetExifOrientation(OHOS::Media::ImageMetadata* exifData)
{
    std::string orientation = "";
    if (exifData != nullptr) {
        exifData->GetValue("Orientation", orientation);
        std::string defalutExifOrientation = "1";
        exifData->SetValue("Orientation", defalutExifOrientation);
        MEDIA_INFO_LOG("GetExifOrientation orientation:%{public}s", orientation.c_str());
        exifData->RemoveExifThumbnail();
        MEDIA_INFO_LOG("RemoveExifThumbnail");
    } else {
        MEDIA_ERR_LOG("GetExifOrientation exifData is nullptr");
    }
    return orientation;
}

void RotatePicture(std::shared_ptr<Media::Picture> picture)
{
    CAMERA_SYNC_TRACE;
    std::string orientation =
        GetAndSetExifOrientation(reinterpret_cast<OHOS::Media::ImageMetadata*>(picture->GetExifMetadata().get()));
    RotatePixelMap(picture->GetMainPixel(), orientation);
    auto gainMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::GAINMAP);
    if (gainMap) {
        RotatePixelMap(gainMap->GetContentPixel(), orientation);
    }
    auto depthMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::DEPTH_MAP);
    if (depthMap) {
        RotatePixelMap(depthMap->GetContentPixel(), orientation);
    }
}

std::shared_ptr<PhotoAssetIntf> HCaptureSession::ProcessPhotoProxy(int32_t captureId,
    std::shared_ptr<Media::Picture> picturePtr, bool isBursting,
    sptr<CameraServerPhotoProxy> cameraPhotoProxy, std::string &uri)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(picturePtr == nullptr, nullptr, "picturePtr is null");
    sptr<HStreamCapture> captureStream = nullptr;
    for (auto& stream : streamContainer_.GetStreams(StreamType::CAPTURE)) {
        captureStream = CastStream<HStreamCapture>(stream);
        if (captureStream != nullptr) {
            break;
        }
    }
    CHECK_ERROR_RETURN_RET_LOG(captureStream == nullptr, nullptr, "stream is null");
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = nullptr;
    std::thread taskThread;
    if (isBursting) {
        int32_t cameraShotType = 3;
        photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, IPCSkeleton::GetCallingUid());
    } else {
        photoAssetProxy = captureStream->GetPhotoAssetInstance(captureId);
    }
    CHECK_ERROR_RETURN_RET_LOG(photoAssetProxy == nullptr, nullptr, "photoAssetProxy is null");
    if (!isBursting && picturePtr) {
        MEDIA_DEBUG_LOG("CreateMediaLibrary RotatePicture E");
        taskThread = std::thread(RotatePicture, picturePtr);
    }
    bool isProfessionalPhoto = (opMode_ == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PROFESSIONAL_PHOTO));
    if (isBursting || captureStream->GetAddPhotoProxyEnabled() == false || isProfessionalPhoto) {
        MEDIA_DEBUG_LOG("CreateMediaLibrary AddPhotoProxy E");
        string pictureId = cameraPhotoProxy->GetTitle() + "." + cameraPhotoProxy->GetExtension();
        CameraReportDfxUtils::GetInstance()->SetPictureId(captureId, pictureId);
        photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
        MEDIA_DEBUG_LOG("CreateMediaLibrary AddPhotoProxy X");
    }
    uri = photoAssetProxy->GetPhotoAssetUri();
    if (!isBursting && taskThread.joinable()) {
        taskThread.join();
        MEDIA_DEBUG_LOG("CreateMediaLibrary RotatePicture X");
    }
    MEDIA_DEBUG_LOG("CreateMediaLibrary NotifyLowQualityImage E");
    DeferredProcessing::DeferredProcessingService::GetInstance().NotifyLowQualityImage(
        photoAssetProxy->GetUserId(), uri, picturePtr);
    MEDIA_DEBUG_LOG("CreateMediaLibrary NotifyLowQualityImage X");
    return photoAssetProxy;
}

void HCaptureSession::ConfigPayload(uint32_t pid, uint32_t tid, const char *bundleName, int32_t qosLevel,
    std::unordered_map<std::string, std::string> &mapPayload)
{
    std::string strBundleName = bundleName;
    std::string strPid = std::to_string(pid);
    std::string strTid = std::to_string(tid);
    std::string strQos = std::to_string(qosLevel);
    mapPayload["pid"] = strPid;
    mapPayload[strTid] = strQos;
    mapPayload["bundleName"] = strBundleName;
    MEDIA_INFO_LOG("mapPayload pid: %{public}s. tid: %{public}s. Qos: %{public}s",
        strPid.c_str(), strTid.c_str(), strQos.c_str());
}

int32_t HCaptureSession::CreateMediaLibrary(std::unique_ptr<Media::Picture> picture, sptr<CameraPhotoProxy>& photoProxy,
    std::string& uri, int32_t& cameraShotType, std::string& burstKey, int64_t timestamp)
{
    const int MAX_RETRIES = 7;
    int32_t tempPid = getpid();
    int32_t tempTid = gettid();
    std::unordered_map<std::string, std::string> mapPayload;
    ConfigPayload(tempPid, tempTid, "camera_service", MAX_RETRIES, mapPayload);
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        OHOS::ResourceSchedule::ResType::RES_TYPE_THREAD_QOS_CHANGE, 0, mapPayload);

    constexpr int32_t movingPhotoShotType = 2;
    constexpr int32_t imageShotType = 0;
    cameraShotType = isSetMotionPhoto_ ? movingPhotoShotType : imageShotType;
    MessageParcel data;
    photoProxy->WriteToParcel(data);
    photoProxy->CameraFreeBufferHandle();
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->ReadFromParcel(data);
    cameraPhotoProxy->SetDisplayName(CreateDisplayName());
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    bool isBursting = false;
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo(captureId);
    SetCameraPhotoProxyInfo(cameraPhotoProxy, cameraShotType, isBursting, burstKey);
    std::shared_ptr<Media::Picture> picturePtr(picture.release());
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy =
        HCaptureSession::ProcessPhotoProxy(captureId, picturePtr, isBursting, cameraPhotoProxy, uri);
    CHECK_ERROR_RETURN_RET_LOG(photoAssetProxy == nullptr, CAMERA_INVALID_ARG, "photoAssetProxy is null");
    if (!isBursting && isSetMotionPhoto_ && taskManager_) {
        MEDIA_INFO_LOG("CreateMediaLibrary captureId :%{public}d", captureId);
        if (taskManager_) {
            taskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
        }
    } else {
        photoAssetProxy.reset();
    }
    CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo(captureId);
    return CAMERA_OK;
}

int32_t HCaptureSession::SetFeatureMode(int32_t featureMode)
{
    MEDIA_INFO_LOG("SetFeatureMode is called!");
    featureMode_ = featureMode;
    return CAMERA_OK;
}

int32_t HCaptureSession::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    MEDIA_INFO_LOG("HCaptureSession::OnCaptureStarted captureId:%{public}d, streamIds:%{public}s", captureId,
        Container2String(streamIds.begin(), streamIds.end()).c_str());
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::OnCaptureStarted StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameStarted();
            CameraReportUtils::GetInstance().SetOpenCamPerfEndInfo();
            CameraReportUtils::GetInstance().SetModeChangePerfEndInfo();
            CameraReportUtils::GetInstance().SetSwitchCamPerfEndInfo();
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId);
        }
    }
    return CAMERA_OK;
}

void HCaptureSession::StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId)
{
    if (isSetMotionPhoto_) {
        taskManager_->SubmitTask(
            [this, timestamp, rotation, captureId]() { this->StartOnceRecord(timestamp, rotation, captureId); });
    }
}

SessionDrainImageCallback::SessionDrainImageCallback(std::vector<sptr<FrameRecord>>& frameCacheList,
    wptr<MovingPhotoListener> listener, wptr<MovingPhotoVideoCache> cache, uint64_t timestamp, int32_t rotation,
    int32_t captureId)
    : frameCacheList_(frameCacheList), listener_(listener), videoCache_(cache), timestamp_(timestamp),
      rotation_(rotation), captureId_(captureId)
{}

SessionDrainImageCallback::~SessionDrainImageCallback()
{
    MEDIA_INFO_LOG("~SessionDrainImageCallback enter");
}

void SessionDrainImageCallback::OnDrainImage(sptr<FrameRecord> frame)
{
    MEDIA_INFO_LOG("OnDrainImage enter");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        frameCacheList_.push_back(frame);
    }
    auto videoCache = videoCache_.promote();
    if (frame->IsIdle() && videoCache) {
        videoCache->CacheFrame(frame);
    } else if (frame->IsFinishCache() && videoCache) {
        videoCache->OnImageEncoded(frame, frame->IsEncoded());
    } else if (frame->IsReadyConvert()) {
        MEDIA_DEBUG_LOG("frame is ready convert");
    } else {
        MEDIA_INFO_LOG("videoCache and frame is not useful");
    }
}

void SessionDrainImageCallback::OnDrainImageFinish(bool isFinished)
{
    MEDIA_INFO_LOG("OnDrainImageFinish enter");
    auto videoCache = videoCache_.promote();
    if (videoCache) {
        videoCache_->GetFrameCachedResult(
            frameCacheList_,
            [videoCache](const std::vector<sptr<FrameRecord>>& frameRecords, uint64_t timestamp, int32_t rotation,
                int32_t captureId) { videoCache->DoMuxerVideo(frameRecords, timestamp, rotation, captureId); },
            timestamp_, rotation_, captureId_);
    }
    auto listener = listener_.promote();
    CHECK_EXECUTE(listener && isFinished, listener->RemoveDrainImageManager(this));
}

void HCaptureSession::StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId)
{
    MEDIA_INFO_LOG("StartOnceRecord enter");
    // frameCacheList only used by now thread
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    std::vector<sptr<FrameRecord>> frameCacheList;
    sptr<SessionDrainImageCallback> imageCallback =
        new SessionDrainImageCallback(frameCacheList, livephotoListener_, videoCache_, timestamp, rotation, captureId);
    livephotoListener_->ClearCache(timestamp);
    livephotoListener_->DrainOutImage(imageCallback);
    MEDIA_INFO_LOG("StartOnceRecord end");
}

int32_t HCaptureSession::OnCaptureStarted_V1_2(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos)
{
    MEDIA_INFO_LOG("HCaptureSession::OnCaptureStarted_V1_2 captureId:%{public}d", captureId);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::OnCaptureStarted_V1_2 StreamId: %{public}d not found."
                          " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            MEDIA_DEBUG_LOG("HCaptureSession::OnCaptureStarted_V1_2 StreamId: %{public}d."
                            " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId, captureInfo.exposureTime_);
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    MEDIA_INFO_LOG("HCaptureSession::OnCaptureEnded");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::OnCaptureEnded StreamId: %{public}d not found."
                          " Framecount: %{public}d",
                captureInfo.streamId_, captureInfo.frameCount_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameEnded(captureInfo.frameCount_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureEnded(captureId, captureInfo.frameCount_);
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnCaptureEndedExt(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos)
{
    MEDIA_INFO_LOG("HCaptureSession::OnCaptureEndedExt captureId:%{public}d", captureId);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::OnCaptureEndedExt StreamId: %{public}d not found."
                          " Framecount: %{public}d",
                captureInfo.streamId_, captureInfo.frameCount_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameEnded(captureInfo.frameCount_);
            CaptureEndedInfoExt extInfo;
            extInfo.streamId = captureInfo.streamId_;
            extInfo.frameCount = captureInfo.frameCount_;
            extInfo.isDeferredVideoEnhancementAvailable = captureInfo.isDeferredVideoEnhancementAvailable_;
            extInfo.videoId = captureInfo.videoId_;
            MEDIA_INFO_LOG("HCaptureSession::OnCaptureEndedExt captureId:%{public}d videoId:%{public}s "
                           "isDeferredVideo:%{public}d",
                captureId, extInfo.videoId.c_str(), extInfo.isDeferredVideoEnhancementAvailable);
            CastStream<HStreamRepeat>(curStream)->OnDeferredVideoEnhancementInfo(extInfo);
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    MEDIA_INFO_LOG("HCaptureSession::OnCaptureError");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& errInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(errInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::OnCaptureError StreamId: %{public}d not found."
                          " Error: %{public}d",
                errInfo.streamId_, errInfo.error_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameError(errInfo.error_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            captureStream->rotationMap_.Erase(captureId);
            captureStream->OnCaptureError(captureId, errInfo.error_);
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnFrameShutter(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_INFO_LOG("HCaptureSession::OnFrameShutter ts is:%{public}" PRIu64, timestamp);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            int32_t rotation = 0;
            captureStream->rotationMap_.Find(captureId, rotation);
            StartMovingPhotoEncode(rotation, timestamp, captureStream->format_, captureId);
            captureStream->OnFrameShutter(captureId, timestamp);
        } else {
            MEDIA_ERR_LOG("HCaptureSession::OnFrameShutter StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnFrameShutterEnd(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_INFO_LOG("HCaptureSession::OnFrameShutterEnd ts is:%{public}" PRIu64, timestamp);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            captureStream->rotationMap_.Erase(captureId);
            captureStream->OnFrameShutterEnd(captureId, timestamp);
        } else {
            MEDIA_ERR_LOG("HCaptureSession::OnFrameShutterEnd StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnCaptureReady(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_DEBUG_LOG("HCaptureSession::OnCaptureReady");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            CastStream<HStreamCapture>(curStream)->OnCaptureReady(captureId, timestamp);
        } else {
            MEDIA_ERR_LOG("HCaptureSession::OnCaptureReady StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::OnResult(int32_t streamId, const std::vector<uint8_t>& result)
{
    MEDIA_DEBUG_LOG("HCaptureSession::OnResult");
    sptr<HStreamCommon> curStream;
    const int32_t metaStreamId = -1;
    if (streamId == metaStreamId) {
        curStream = GetStreamByStreamID(streamId);
    } else {
        curStream = GetHdiStreamByStreamID(streamId);
    }
    if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::METADATA)) {
        CastStream<HStreamMetadata>(curStream)->OnMetaResult(streamId, result);
    } else {
        MEDIA_ERR_LOG("HCaptureSession::OnResult StreamId: %{public}d is null or not Not adapted", streamId);
        return CAMERA_INVALID_ARG;
    }
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

bool StreamContainer::AddStream(sptr<HStreamCommon> stream)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto& list = streams_[stream->GetStreamType()];
    auto it = std::find_if(list.begin(), list.end(), [stream](auto item) { return item == stream; });
    if (it == list.end()) {
        list.emplace_back(stream);
        return true;
    }
    return false;
}

bool StreamContainer::RemoveStream(sptr<HStreamCommon> stream)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto& list = streams_[stream->GetStreamType()];
    auto it = std::find_if(list.begin(), list.end(), [stream](auto item) { return item == stream; });
    CHECK_ERROR_RETURN_RET(it == list.end(), false);
    list.erase(it);
    return true;
}

sptr<HStreamCommon> StreamContainer::GetStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            CHECK_ERROR_RETURN_RET(stream->GetFwkStreamId() == streamId, stream);
        }
    }
    return nullptr;
}

sptr<HStreamCommon> StreamContainer::GetHdiStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            CHECK_ERROR_RETURN_RET(stream->GetHdiStreamId() == streamId, stream);
        }
    }
    return nullptr;
}

void StreamContainer::Clear()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    streams_.clear();
}

size_t StreamContainer::Size()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    size_t totalSize = 0;
    for (auto& pair : streams_) {
        totalSize += pair.second.size();
    }
    return totalSize;
}

std::list<sptr<HStreamCommon>> StreamContainer::GetStreams(const StreamType streamType)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    std::list<sptr<HStreamCommon>> totalOrderedStreams;
    for (auto& stream : streams_[streamType]) {
        auto insertPos = std::find_if(totalOrderedStreams.begin(), totalOrderedStreams.end(),
            [&stream](auto& it) { return stream->GetFwkStreamId() <= it->GetFwkStreamId(); });
        totalOrderedStreams.emplace(insertPos, stream);
    }
    return totalOrderedStreams;
}

std::list<sptr<HStreamCommon>> StreamContainer::GetAllStreams()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    std::list<sptr<HStreamCommon>> totalOrderedStreams;
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            auto insertPos = std::find_if(totalOrderedStreams.begin(), totalOrderedStreams.end(),
                [&stream](auto& it) { return stream->GetFwkStreamId() <= it->GetFwkStreamId(); });
            totalOrderedStreams.emplace(insertPos, stream);
        }
    }
    return totalOrderedStreams;
}

MovingPhotoListener::MovingPhotoListener(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper, sptr<Surface> metaSurface,
    shared_ptr<FixedSizeList<MetaElementType>> metaCache, uint32_t preCacheFrameCount, uint32_t postCacheFrameCount)
    : movingPhotoSurfaceWrapper_(surfaceWrapper), metaSurface_(metaSurface), metaCache_(metaCache),
      recorderBufferQueue_("videoBuffer", preCacheFrameCount), postCacheFrameCount_(postCacheFrameCount)
{
    shutterTime_ = 0;
}

MovingPhotoListener::~MovingPhotoListener()
{
    recorderBufferQueue_.SetActive(false);
    metaCache_->clear();
    recorderBufferQueue_.Clear();
    MEDIA_ERR_LOG("HStreamRepeat::LivePhotoListener ~ end");
}

void MovingPhotoListener::RemoveDrainImageManager(sptr<SessionDrainImageCallback> callback)
{
    callbackMap_.Erase(callback);
    MEDIA_INFO_LOG("RemoveDrainImageManager drainImageManagerVec_ Start %d", callbackMap_.Size());
}

void MovingPhotoListener::ClearCache(uint64_t timestamp)
{
    CHECK_ERROR_RETURN(!isNeededClear_.load());
    MEDIA_INFO_LOG("ClearCache enter");
    shutterTime_ = static_cast<int64_t>(timestamp);
    while (!recorderBufferQueue_.Empty()) {
        sptr<FrameRecord> popFrame = recorderBufferQueue_.Front();
        MEDIA_DEBUG_LOG("surface_ release surface buffer %{public}llu, timestamp %{public}llu",
            (long long unsigned)popFrame->GetTimeStamp(), (long long unsigned)timestamp);
        if (popFrame->GetTimeStamp() > shutterTime_) {
            isNeededClear_ = false;
            MEDIA_INFO_LOG("ClearCache end");
            return;
        }
        recorderBufferQueue_.Pop();
        popFrame->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
        popFrame->ReleaseMetaBuffer(metaSurface_, true);
    }
}

void MovingPhotoListener::SetClearFlag()
{
    MEDIA_INFO_LOG("need clear cache!");
    isNeededClear_ = true;
}

void MovingPhotoListener::StopDrainOut()
{
    MEDIA_INFO_LOG("StopDrainOut drainImageManagerVec_ Start %d", callbackMap_.Size());
    callbackMap_.Iterate([](const sptr<SessionDrainImageCallback> callback, sptr<DrainImageManager> manager) {
        manager->DrainFinish(false);
    });
    callbackMap_.Clear();
}

void MovingPhotoListener::OnBufferArrival(sptr<SurfaceBuffer> buffer, int64_t timestamp, GraphicTransformType transform)
{
    MEDIA_DEBUG_LOG("OnBufferArrival timestamp %{public}llu", (long long unsigned)timestamp);
    if (recorderBufferQueue_.Full()) {
        MEDIA_DEBUG_LOG("surface_ release surface buffer");
        sptr<FrameRecord> popFrame = recorderBufferQueue_.Pop();
        popFrame->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
        popFrame->ReleaseMetaBuffer(metaSurface_, true);
        MEDIA_DEBUG_LOG("surface_ release surface buffer: %{public}s, refCount: %{public}d",
            popFrame->GetFrameId().c_str(), popFrame->GetSptrRefCount());
    }
    MEDIA_DEBUG_LOG("surface_ push buffer %{public}d x %{public}d, stride is %{public}d",
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), buffer->GetStride());
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(buffer, timestamp, transform);
    CHECK_ERROR_RETURN_LOG(frameRecord == nullptr, "MovingPhotoListener::OnBufferAvailable create FrameRecord fail!");
    if (isNeededClear_ && isNeededPop_) {
        if (timestamp < shutterTime_) {
            frameRecord->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
            MEDIA_INFO_LOG("Drop this frame in cache");
            return;
        } else {
            isNeededClear_ = false;
            isNeededPop_ = false;
            MEDIA_INFO_LOG("ClearCache end");
        }
    }
    recorderBufferQueue_.Push(frameRecord);
    auto metaPair = metaCache_->find_if([timestamp](const MetaElementType& value) { return value.first == timestamp; });
    if (metaPair.has_value()) {
        MEDIA_DEBUG_LOG("frame has meta");
        frameRecord->SetMetaBuffer(metaPair.value().second);
    }
    vector<sptr<SessionDrainImageCallback>> callbacks;
    callbackMap_.Iterate([frameRecord, &callbacks](const sptr<SessionDrainImageCallback> callback,
                             sptr<DrainImageManager> manager) { callbacks.push_back(callback); });
    for (sptr<SessionDrainImageCallback> drainImageCallback : callbacks) {
        sptr<DrainImageManager> drainImageManager;
        if (callbackMap_.Find(drainImageCallback, drainImageManager)) {
            std::lock_guard<std::mutex> lock(drainImageManager->drainImageLock_);
            drainImageManager->DrainImage(frameRecord);
        }
    }
}

void MovingPhotoListener::DrainOutImage(sptr<SessionDrainImageCallback> drainImageCallback)
{
    sptr<DrainImageManager> drainImageManager =
        new DrainImageManager(drainImageCallback, recorderBufferQueue_.Size() + postCacheFrameCount_);
    {
        MEDIA_INFO_LOG("DrainOutImage enter %{public}zu", recorderBufferQueue_.Size());
        callbackMap_.Insert(drainImageCallback, drainImageManager);
    }
    // Convert recorderBufferQueue_ to a vector
    std::vector<sptr<FrameRecord>> frameList = recorderBufferQueue_.GetAllElements();
    CHECK_EXECUTE(!frameList.empty(), frameList.back()->SetCoverFrame());
    std::lock_guard<std::mutex> lock(drainImageManager->drainImageLock_);
    for (const auto& frame : frameList) {
        MEDIA_DEBUG_LOG("DrainOutImage enter DrainImage");
        drainImageManager->DrainImage(frame);
    }
}

void MovingPhotoMetaListener::OnBufferAvailable()
{
    MEDIA_DEBUG_LOG("metaSurface_ OnBufferAvailable %{public}u", surface_->GetQueueSize());
    CHECK_ERROR_RETURN_LOG(!surface_, "streamRepeat surface is null");
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    SurfaceError surfaceRet = surface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire meta surface buffer");
    surfaceRet = surface_->DetachBufferFromQueue(buffer);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "Failed to detach meta buffer. %{public}d", surfaceRet);
    metaCache_->add({ timestamp, buffer });
}

MovingPhotoMetaListener::MovingPhotoMetaListener(
    sptr<Surface> surface, shared_ptr<FixedSizeList<MetaElementType>> metaCache)
    : surface_(surface), metaCache_(metaCache)
{}

MovingPhotoMetaListener::~MovingPhotoMetaListener()
{
    MEDIA_ERR_LOG("HStreamRepeat::MovingPhotoMetaListener ~ end");
}
} // namespace CameraStandard
} // namespace OHOS
