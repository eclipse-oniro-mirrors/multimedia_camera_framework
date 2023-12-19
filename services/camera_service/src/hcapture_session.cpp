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
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <new>
#include <sched.h>
#include <utility>
#include <vector>
#include <algorithm>

#include "bundle_mgr_interface.h"
#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"
#include "errors.h"
#include "hcamera_device_manager.h"
#include "hstream_capture.h"
#include "hstream_common.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "iconsumer_surface.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "istream_common.h"
#include "metadata_utils.h"
#include "refbase.h"
#include "system_ability_definition.h"
#include "v1_0/types.h"
#include "smooth_zoom.h"
#include "hcamera_restore_param.h"

using namespace OHOS::AAFwk;
namespace OHOS {
namespace CameraStandard {
using HDI::Camera::V1_0::CamRetCode;
namespace {
static std::map<pid_t, sptr<HCaptureSession>> g_totalSessions;
static std::mutex g_totalSessionLock;
static size_t TotalSessionSize()
{
    std::lock_guard<std::mutex> lock(g_totalSessionLock);
    return g_totalSessions.size();
}

static const std::map<pid_t, sptr<HCaptureSession>> TotalSessionsCopy()
{
    std::lock_guard<std::mutex> lock(g_totalSessionLock);
    return g_totalSessions;
}

static void TotalSessionsInsert(pid_t pid, sptr<HCaptureSession> session)
{
    std::lock_guard<std::mutex> lock(g_totalSessionLock);
    auto it = g_totalSessions.find(pid);
    if (it != g_totalSessions.end()) {
        MEDIA_ERR_LOG("HCaptureSession TotalSessionsInsert insert session but pid already exist!, memory leak may "
                      "occurred, pid is:%{public}d",
            pid);
        it->second = session;
        return;
    }
    g_totalSessions.emplace(pid, session);
}

static sptr<HCaptureSession> TotalSessionsGet(pid_t pid)
{
    std::lock_guard<std::mutex> lock(g_totalSessionLock);
    auto it = g_totalSessions.find(pid);
    if (it != g_totalSessions.end()) {
        return it->second;
    }
    return nullptr;
}

static void TotalSessionErase(pid_t pid)
{
    std::lock_guard<std::mutex> lock(g_totalSessionLock);
    g_totalSessions.erase(pid);
}
} // namespace

static const std::map<CaptureSessionState, std::string> SESSION_STATE_STRING_MAP = {
    {CaptureSessionState::SESSION_INIT, "Init"},
    {CaptureSessionState::SESSION_CONFIG_INPROGRESS, "Config_In-progress"},
    {CaptureSessionState::SESSION_CONFIG_COMMITTED, "Committed"},
    {CaptureSessionState::SESSION_RELEASED, "Released"}
};

HCaptureSession::HCaptureSession(const uint32_t callingTokenId, int32_t opMode)
{
    pid_ = IPCSkeleton::GetCallingPid();
    uid_ = IPCSkeleton::GetCallingUid();
    MEDIA_DEBUG_LOG("HCaptureSession: camera stub services(%{public}zu) pid(%{public}d).", TotalSessionSize(), pid_);
    auto pidSession = TotalSessionsGet(pid_);
    if (pidSession != nullptr) {
        auto disconnectDevice = pidSession->GetCameraDevice();
        if (disconnectDevice != nullptr) {
            disconnectDevice->OnError(HDI::Camera::V1_0::DEVICE_PREEMPT, 0);
        }
        MEDIA_ERR_LOG("HCaptureSession::HCaptureSession doesn't support multiple sessions per pid");
        pidSession->Release();
    }
    TotalSessionsInsert(pid_, this);
    callerToken_ = callingTokenId;
    opMode_ = opMode;
    SetOpMode(opMode_);
    MEDIA_INFO_LOG(
        "HCaptureSession: camera stub services(%{public}zu). opMode_= %{public}d", TotalSessionSize(), opMode_);
}

HCaptureSession::~HCaptureSession()
{
    Release(CaptureSessionReleaseType::RELEASE_TYPE_OBJ_DIED);
}

pid_t HCaptureSession::GetPid()
{
    return pid_;
}

int32_t HCaptureSession::GetopMode()
{
    return opMode_;
}

int32_t HCaptureSession::GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos)
{
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream) {
            StreamInfo_V1_1 curStreamInfo;
            stream->SetStreamInfo(curStreamInfo);
            streamInfos.push_back(curStreamInfo);
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    int32_t errCode;

    stateMachine_.StateGuard([&errCode, this](const CaptureSessionState state) {
        bool isStateValid = stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_INPROGRESS);
        if (!isStateValid) {
            MEDIA_ERR_LOG("HCaptureSession::BeginConfig in invalid state %{public}d", state);
            errCode = CAMERA_INVALID_STATE;
            return;
        }
        UnlinkInputAndOutputs();
        ClearSketchRepeatStream();
    });
    return errCode;
}

int32_t HCaptureSession::CanAddInput(sptr<ICameraDeviceService> cameraDevice, bool& result)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    result = false;
    stateMachine_.StateGuard([this, &errorCode](const CaptureSessionState currentState) {
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
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddInput cameraDevice is null");
        return CAMERA_INVALID_ARG;
    }
    int32_t errorCode = CAMERA_OK;
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
        hCameraDevice->SetStreamOperatorCallback(this);
        SetCameraDevice(hCameraDevice);
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddInput"));
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::AddOutputStream(sptr<HStreamCommon> stream)
{
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutputStream stream is null");
        return CAMERA_INVALID_ARG;
    }
    bool isAddSuccess = streamContainer_.AddStream(stream);
    if (!isAddSuccess) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutputStream add stream fail");
        return CAMERA_INVALID_SESSION_CFG;
    }
    if (stream->GetStreamType() == StreamType::CAPTURE) {
        auto captureStream = CastStream<HStreamCapture>(stream);
        captureStream->SetMode(opMode_);
        captureStream->SetColorSpace(currCaptureColorSpace_);
    } else {
        stream->SetColorSpace(currColorSpace_);
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::AddOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutput stream is null");
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
            errorCode = AddOutputStream(static_cast<HStreamRepeat*>(stream.GetRefPtr()));
        } else if (streamType == StreamType::METADATA) {
            errorCode = AddOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddOutput with %d", streamType));
    }
    MEDIA_INFO_LOG("CaptureSession::AddOutput with with %{public}d, rc = %{public}d", streamType, errorCode);
    return errorCode;
}

int32_t HCaptureSession::RemoveInput(sptr<ICameraDeviceService> cameraDevice)
{
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveInput cameraDevice is null");
        return CAMERA_INVALID_ARG;
    }
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([this, &errorCode, &cameraDevice](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::RemoveInput Need to call BeginConfig before removing input");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        auto currentDevice = GetCameraDevice();
        if (currentDevice != nullptr && cameraDevice->AsObject() == currentDevice->AsObject()) {
            // Do not close device while remove input!
            MEDIA_INFO_LOG(
                "HCaptureSession::RemoveInput camera id is %{public}s", currentDevice->GetCameraId().c_str());
            SetCameraDevice(nullptr);
        } else {
            MEDIA_ERR_LOG("HCaptureSession::RemoveInput Invalid camera device");
            errorCode = CAMERA_INVALID_SESSION_CFG;
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveInput"));
    }
    return errorCode;
}

int32_t HCaptureSession::RemoveOutputStream(sptr<HStreamCommon> stream)
{
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutputStream stream is null");
        return CAMERA_INVALID_ARG;
    }

    bool isRemoveSuccess = streamContainer_.RemoveStream(stream);
    if (!isRemoveSuccess) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutputStream Invalid output");
        return CAMERA_INVALID_SESSION_CFG;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutput stream is null");
        return errorCode;
    }
    stateMachine_.StateGuard([this, &errorCode, streamType, &stream](const CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
            MEDIA_ERR_LOG("HCaptureSession::RemoveOutput Need to call BeginConfig before removing output");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        if (streamType == StreamType::CAPTURE) {
            errorCode = RemoveOutputStream(static_cast<HStreamCapture*>(stream.GetRefPtr()));
        } else if (streamType == StreamType::REPEAT) {
            errorCode = RemoveOutputStream(static_cast<HStreamRepeat*>(stream.GetRefPtr()));
        } else if (streamType == StreamType::METADATA) {
            errorCode = RemoveOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
        }
    });
    if (errorCode == CAMERA_OK) {
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveOutput with %d", streamType));
    }
    return errorCode;
}

int32_t HCaptureSession::ValidateSessionInputs()
{
    if (GetCameraDevice() == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::ValidateSessionInputs No inputs present");
        return CAMERA_INVALID_SESSION_CFG;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::ValidateSessionOutputs()
{
    if (streamContainer_.Size() == 0) {
        MEDIA_ERR_LOG("HCaptureSession::ValidateSessionOutputs No outputs present");
        return CAMERA_INVALID_SESSION_CFG;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::LinkInputAndOutputs()
{
    int32_t rc;
    std::vector<StreamInfo_V1_1> allStreamInfos;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    auto device = GetCameraDevice();
    if (device == nullptr) {
        return CAMERA_INVALID_SESSION_CFG;
    }
    auto settings = device->GetSettings();
    if (settings == nullptr) {
        return CAMERA_UNKNOWN_ERROR;
    }
    streamOperator = device->GetStreamOperator();
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        rc = stream->LinkInput(streamOperator, settings);
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSession::HandleCaptureOuputsConfig() Failed to link Output, %{public}d", rc);
            return rc;
        }
        StreamInfo_V1_1 curStreamInfo;
        stream->SetStreamInfo(curStreamInfo);
        allStreamInfos.push_back(curStreamInfo);
    }

    rc = device->CreateAndCommitStreams(allStreamInfos, settings, opMode_);
    return rc;
}

int32_t HCaptureSession::UnlinkInputAndOutputs()
{
    int32_t rc = CAMERA_UNKNOWN_ERROR;

    std::vector<int32_t> streamIds;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        stream->UnlinkInput();
        streamIds.emplace_back(stream->GetStreamId());
    }
    MEDIA_DEBUG_LOG("HCaptureSession::UnlinkInputAndOutputs() streamIds size() = %{public}zu", streamIds.size());
    for (size_t i = 0; i < streamIds.size(); i++) {
        MEDIA_DEBUG_LOG(
            "HCaptureSession::UnlinkInputAndOutputs() streamIds[%{public}zu] = %{public}d", i, streamIds.at(i));
    }

    // HDI release streams
    auto cameraDevice = GetCameraDevice();
    if ((cameraDevice != nullptr)) {
        cameraDevice->ReleaseStreams(streamIds);
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

const sptr<HStreamCommon> HCaptureSession::GetStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetStream(streamId);
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::GetStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    }
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
            "HCaptureSession::ClearSketchRepeatStream() stream id is:%{public}d", sketchStream->GetStreamId());
        RemoveOutputStream(repeatStream);
    }
    MEDIA_DEBUG_LOG("Exit HCaptureSession::ClearSketchRepeatStream()");
}

int32_t HCaptureSession::CommitConfig()
{
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Need to call BeginConfig before committing configuration");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        errorCode = ValidateSessionInputs();
        if (errorCode != CAMERA_OK) {
            return;
        }
        errorCode = ValidateSessionOutputs();
        if (errorCode != CAMERA_OK) {
            return;
        }
        ExpandSketchRepeatStream();
        auto device = GetCameraDevice();
        if (device == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. camera device is null");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        errorCode = LinkInputAndOutputs();
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. rc: %{public}d", errorCode);
            return;
        }
        if (device != nullptr) {
            int32_t pid = IPCSkeleton::GetCallingPid();
            int32_t uid = IPCSkeleton::GetCallingUid();
            POWERMGR_SYSEVENT_CAMERA_CONNECT(pid, uid, device->GetCameraId().c_str(), GetClientBundle(uid));
        }
        stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_COMMITTED);
    });
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
    if (colorSpace == currColorSpace_ && captureColorSpace == currCaptureColorSpace_) {
        MEDIA_INFO_LOG("HCaptureSession::SetColorSpace() colorSpace no need to update.");
        return result;
    }
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
            MEDIA_INFO_LOG("HCaptureSession::SetColorSpace() colorSpace %{public}d, captureColorSpace %{public}d, "
                           "isNeedUpdate %{public}d",
                colorSpace, captureColorSpace, isNeedUpdate);

            result = CheckIfColorSpaceMatchesFormat(colorSpace);
            if (result != CAMERA_OK && isNeedUpdate) {
                MEDIA_ERR_LOG("HCaptureSession::SetColorSpace() Failed, format and colorSpace not match.");
                return;
            }
            if (result != CAMERA_OK && !isNeedUpdate) {
                MEDIA_ERR_LOG("HCaptureSession::SetColorSpace() %{public}d, format and colorSpace not match.", result);
                currColorSpace_ = ColorSpace::BT709;
            }

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
    if (cameraDevice == nullptr) {
        return;
    }
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
    // 待为HDR VIVID增加逻辑
    return CAMERA_OPERATION_NOT_ALLOWED;
}

int32_t HCaptureSession::GetSessionState(CaptureSessionState& sessionState)
{
    sessionState = stateMachine_.GetCurrentState();
    return CAMERA_OK;
}

bool HCaptureSession::QueryFpsAndZoomRatio(float& currentFps, float& currentZoomRatio)
{
    auto cameraDevice = GetCameraDevice();
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::QueryFpsAndZoomRatio() cameraDevice is null");
        return false;
    }
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
    int retFindMeta = OHOS::Camera::FindCameraMetadataItem(metaOut->get(),
        OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &item);
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryFpsAndZoomRatio() current zoom not found");
        return false;
    } else if (retFindMeta == CAM_META_SUCCESS) {
        currentZoomRatio = static_cast<float>(item.data.ui32[0]);
        MEDIA_DEBUG_LOG("HCaptureSession::QueryFpsAndZoomRatio() current zoom %{public}d.", item.data.ui32[0]);
    }
    retFindMeta = OHOS::Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_FPS, &item);
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryFpsAndZoomRatio() current fps not found");
        return false;
    } else if (retFindMeta == CAM_META_SUCCESS) {
        currentFps = static_cast<float>(item.data.ui32[0]);
        MEDIA_DEBUG_LOG("HCaptureSession::QueryFpsAndZoomRatio() current fps %{public}d.", item.data.ui32[0]);
    }
    return true;
}

bool HCaptureSession::QueryZoomPerformance(std::vector<float>& crossZoomAndTime, int32_t operationMode)
{
    auto cameraDevice = GetCameraDevice();
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::QueryZoomPerformance() cameraDevice is null");
        return false;
    }
    // query zoom performance. begin
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice->GetSettings();
    camera_metadata_item_t zoomItem;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE, &zoomItem);
    if (retFindMeta == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_ERR_LOG("HCaptureSession::QueryZoomPerformance() current zoom not found");
        return false;
    } else if (retFindMeta == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance() zoom performance count %{public}d.", zoomItem.count);
        for (int i = 0; i <= static_cast<int>(zoomItem.count); i++) {
            MEDIA_DEBUG_LOG(
                "HCaptureSession::QueryZoomPerformance() zoom performance value %{public}d.", zoomItem.data.ui32[i]);
        }
    }
    int dataLenPerPoint = 3;
    int headLenPerMode = 2;
    MEDIA_DEBUG_LOG("HCaptureSession::QueryZoomPerformance() operationMode %{public}d.",
        static_cast<OHOS::HDI::Camera::V1_2::OperationMode_V1_2>(operationMode));
    for (int i = 0; i < static_cast<int>(zoomItem.count);) {
        int sceneMode = zoomItem.data.ui32[i];
        int zoomPointsNum = zoomItem.data.ui32[i + 1];
        if (static_cast<OHOS::HDI::Camera::V1_2::OperationMode_V1_2>(operationMode) == sceneMode) {
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

int32_t HCaptureSession::SetSmoothZoom(
    int32_t smoothZoomType, int32_t operationMode, float targetZoomRatio, float& duration)
{
    constexpr int32_t ZOOM_RATIO_MULTIPLE = 100;
    auto cameraDevice = GetCameraDevice();
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::SetSmoothZoom device is null");
        return CAMERA_UNKNOWN_ERROR;
    }
    float currentFps;
    float currentZoomRatio;
    QueryFpsAndZoomRatio(currentFps, currentZoomRatio);
    std::vector<float> crossZoomAndTime {};
    QueryZoomPerformance(crossZoomAndTime, operationMode);
    float waitTime = 0.0;
    int dataLenPerPoint = 3;
    float frameIntervalMs = 1000.0 / currentFps;
    targetZoomRatio = targetZoomRatio * ZOOM_RATIO_MULTIPLE;
    int indexAdded = targetZoomRatio > currentZoomRatio ? 1 : 2;
    auto zoomAlgorithm = SmoothZoom::GetZoomAlgorithm(static_cast<SmoothZoomType>(smoothZoomType));
    auto array = zoomAlgorithm->GetZoomArray(currentZoomRatio, targetZoomRatio, frameIntervalMs);

    for (int i = 0; i < static_cast<int>(crossZoomAndTime.size()); i = i + dataLenPerPoint) {
        float crossZoom = crossZoomAndTime[i];
        if ((crossZoom - currentZoomRatio) * (crossZoom - targetZoomRatio) > 0) {
            continue;
        }
        float waitMs = crossZoomAndTime[i + indexAdded];
        for (int j = 0; j < static_cast<int>(array.size()); j++) {
            if ((array[j] - crossZoom) * (array[0] - crossZoom) < 0) {
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
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaZoomArray = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    uint32_t zoomCount = static_cast<uint32_t>(zoomAndTimeArray.size());
    metaZoomArray->addEntry(OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, zoomAndTimeArray.data(), zoomCount);
    cameraDevice->UpdateSettingOnce(metaZoomArray);
    return CAMERA_OK;
}

int32_t HCaptureSession::Start()
{
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_COMMITTED) {
            MEDIA_ERR_LOG("HCaptureSession::Start(), Invalid session state: %{public}d", currentState);
            errorCode = CAMERA_INVALID_STATE;
            return;
        }

        if (IsValidTokenId(callerToken_)) {
            if (!Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA)) {
                MEDIA_ERR_LOG("Start session is not allowed!");
                errorCode = CAMERA_OPERATION_NOT_ALLOWED;
                return;
            }
            StartUsingPermissionCallback(callerToken_, OHOS_PERMISSION_CAMERA);
            RegisterPermissionCallback(callerToken_, OHOS_PERMISSION_CAMERA);
        }
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
        auto cameraDevice = GetCameraDevice();
        if (cameraDevice != nullptr) {
            settings = cameraDevice->CloneCachedSettings();
            MEDIA_INFO_LOG("HCaptureSession::Start()");
            DumpMetadata(settings);
        }

        auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
        for (auto& item : repeatStreams) {
            auto curStreamRepeat = CastStream<HStreamRepeat>(item);
            auto repeatType = curStreamRepeat->GetRepeatStreamType();
            if (repeatType != RepeatStreamType::PREVIEW) {
                continue;
            }
            errorCode = curStreamRepeat->Start(settings);
            if (errorCode != CAMERA_OK) {
                MEDIA_ERR_LOG("HCaptureSession::Start(), Failed to start preview, rc: %{public}d", errorCode);
                break;
            }
        }
        if (errorCode == CAMERA_OK) {
            isSessionStarted_ = true;
        }
    });
    return errorCode;
}

int32_t HCaptureSession::Stop()
{
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([&errorCode, this](CaptureSessionState currentState) {
        if (currentState != CaptureSessionState::SESSION_CONFIG_COMMITTED) {
            errorCode = CAMERA_INVALID_STATE;
            return;
        }
        auto allStreams = streamContainer_.GetAllStreams();
        for (auto& item : allStreams) {
            if (item->GetStreamType() == StreamType::REPEAT) {
                auto repeatStream = CastStream<HStreamRepeat>(item);
                if (repeatStream->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
                    errorCode = repeatStream->Stop();
                } else {
                    repeatStream->Stop();
                }
            } else if (item->GetStreamType() == StreamType::METADATA) {
                CastStream<HStreamMetadata>(item)->Stop();
            } else if (item->GetStreamType() == StreamType::CAPTURE) {
                CastStream<HStreamCapture>(item)->CancelCapture();
            } else {
                MEDIA_ERR_LOG("HCaptureSession::Stop(), get unknow stream, streamType: %{public}d, streamId:%{public}d",
                    item->GetStreamType(), item->GetStreamId());
            }
            if (errorCode != CAMERA_OK) {
                MEDIA_ERR_LOG("HCaptureSession::Stop(), Failed to stop stream, rc: %{public}d, streamId:%{public}d",
                    errorCode, item->GetStreamId());
            }
        }
        if (errorCode == CAMERA_OK) {
            isSessionStarted_ = false;
        }
    });
    return errorCode;
}

void HCaptureSession::ReleaseStreams()
{
    std::vector<int32_t> streamIds;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        streamIds.emplace_back(stream->GetStreamId());
        stream->Release();
    }
    streamContainer_.Clear();
    MEDIA_DEBUG_LOG("HCaptureSession::ReleaseStreams() streamIds size() = %{public}zu", streamIds.size());
    for (size_t i = 0; i < streamIds.size(); i++) {
        MEDIA_DEBUG_LOG("HCaptureSession::ReleaseStreams() streamIds[%{public}zu] = %{public}d", i, streamIds.at(i));
    }
    auto cameraDevice = GetCameraDevice();
    if ((cameraDevice != nullptr) && !streamIds.empty()) {
        cameraDevice->ReleaseStreams(streamIds);
    }
}

int32_t HCaptureSession::Release(CaptureSessionReleaseType type)
{
    int32_t errorCode = CAMERA_OK;
    stateMachine_.StateGuard([&errorCode, this, type](CaptureSessionState currentState) {
        MEDIA_INFO_LOG("HCaptureSession::Release pid(%{public}d). release type is:%{public}d", pid_, type);
        bool isTransferSupport = stateMachine_.CheckTransfer(CaptureSessionState::SESSION_RELEASED);
        if (!isTransferSupport) {
            MEDIA_ERR_LOG("HCaptureSession::Release error, this session is already released!");
            errorCode = CAMERA_INVALID_STATE;
            return;
        }

        // Clear outputs
        ReleaseStreams();

        // Clear inputs
        auto cameraDevice = GetCameraDevice();
        if (cameraDevice != nullptr) {
            cameraDevice->Release();
            POWERMGR_SYSEVENT_CAMERA_DISCONNECT(cameraDevice->GetCameraId().c_str());
            SetCameraDevice(nullptr);
        }
        StopUsingPermissionCallback(callerToken_, OHOS_PERMISSION_CAMERA);
        UnregisterPermissionCallback(callerToken_);

        // Clear current session
        MEDIA_DEBUG_LOG(
            "ClearCaptureSession: camera stub services(%{public}zu) pid(%{public}d).", TotalSessionSize(), pid_);
        TotalSessionErase(pid_);
        MEDIA_DEBUG_LOG("ClearCaptureSession: camera stub services(%{public}zu).", TotalSessionSize());

        sptr<ICaptureSessionCallback> emptyCallback = nullptr;
        SetCallback(emptyCallback);
        stateMachine_.Transfer(CaptureSessionState::SESSION_RELEASED);
        isSessionStarted_ = false;
    });

    return errorCode;
}

int32_t HCaptureSession::Release()
{
    return Release(CaptureSessionReleaseType::RELEASE_TYPE_CLIENT);
}

int32_t HCaptureSession::OperatePermissionCheck(uint32_t interfaceCode)
{
    if (stateMachine_.GetCurrentState() == CaptureSessionState::SESSION_RELEASED) {
        MEDIA_ERR_LOG("HCaptureSession::OperatePermissionCheck session is released");
        return CAMERA_INVALID_STATE;
    }
    switch (static_cast<CaptureSessionInterfaceCode>(interfaceCode)) {
        case CAMERA_CAPTURE_SESSION_START: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            if (callerToken_ != callerToken) {
                MEDIA_ERR_LOG("HCaptureSession::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                              "is %{public}d",
                    callerToken_, callerToken);
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

void HCaptureSession::RegisterPermissionCallback(const uint32_t callingTokenId, const std::string permissionName)
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {permissionName};
    scopeInfo.tokenIDs = {callingTokenId};
    callbackPtr_ = std::make_shared<PermissionStatusChangeCb>(this, scopeInfo);
    MEDIA_DEBUG_LOG("after tokenId:%{public}d register", callingTokenId);
    int32_t res = Security::AccessToken::AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr_);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("RegisterPermStateChangeCallback failed.");
    }
}

void HCaptureSession::UnregisterPermissionCallback(const uint32_t callingTokenId)
{
    if (callbackPtr_ == nullptr) {
        MEDIA_ERR_LOG("callbackPtr_ is null.");
        return;
    }
    int32_t res = Security::AccessToken::AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr_);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("UnRegisterPermStateChangeCallback failed.");
    }
    callbackPtr_ = nullptr;
    MEDIA_DEBUG_LOG("after tokenId:%{public}d unregister", callingTokenId);
}

void HCaptureSession::DestroyStubObjectForPid(pid_t pid)
{
    MEDIA_DEBUG_LOG("camera stub services(%{public}zu) pid(%{public}d).", TotalSessionSize(), pid);
    sptr<HCaptureSession> session = TotalSessionsGet(pid);
    if (session != nullptr) {
        session->Release(CaptureSessionReleaseType::RELEASE_TYPE_CLIENT_DIED);
    }
    MEDIA_DEBUG_LOG("camera stub services(%{public}zu).", TotalSessionSize());
}

int32_t HCaptureSession::SetCallback(sptr<ICaptureSessionCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_WARNING_LOG("HCaptureSession::SetCallback callback is null, we should clear the callback");
    }

    // Not implement yet.
    return CAMERA_OK;
}

std::string HCaptureSession::GetSessionState()
{
    std::map<CaptureSessionState, std::string>::const_iterator iter =
        SESSION_STATE_STRING_MAP.find(stateMachine_.GetCurrentState());
    if (iter != SESSION_STATE_STRING_MAP.end()) {
        return iter->second;
    }
    return nullptr;
}

void HCaptureSession::CameraSessionSummary(std::string& dumpString)
{
    dumpString += "# Number of Camera clients:[" + std::to_string(TotalSessionSize()) + "]:\n";
}

void HCaptureSession::dumpSessions(std::string& dumpString)
{
    auto totalSession = TotalSessionsCopy();
    for (auto it = totalSession.begin(); it != totalSession.end(); it++) {
        if (it->second != nullptr) {
            sptr<HCaptureSession> session = it->second;
            dumpString += "No. of sessions for client:[" + std::to_string(1) + "]:\n";
            session->dumpSessionInfo(dumpString);
        }
    }
}

void HCaptureSession::dumpSessionInfo(std::string& dumpString)
{
    dumpString += "Client pid:[" + std::to_string(pid_)
        + "]    Client uid:[" + std::to_string(uid_) + "]:\n";
    dumpString += "session state:[" + GetSessionState() + "]:\n";
    for (auto& stream : streamContainer_.GetAllStreams()) {
        stream->DumpStreamInfo(dumpString);
    }
}

void HCaptureSession::StartUsingPermissionCallback(const uint32_t callingTokenId, const std::string permissionName)
{
    if (cameraUseCallbackPtr_) {
        MEDIA_ERR_LOG("has StartUsingPermissionCallback!");
        return;
    }
    cameraUseCallbackPtr_ = std::make_shared<CameraUseStateChangeCb>(this);
    int32_t res =
        Security::AccessToken::PrivacyKit::StartUsingPermission(callingTokenId, permissionName, cameraUseCallbackPtr_);
    MEDIA_DEBUG_LOG("after StartUsingPermissionCallback tokenId:%{public}d", callingTokenId);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("StartUsingPermissionCallback failed.");
    }
}

void HCaptureSession::StopUsingPermissionCallback(const uint32_t callingTokenId, const std::string permissionName)
{
    MEDIA_DEBUG_LOG("enter StopUsingPermissionCallback tokenId:%{public}d", callingTokenId);
    int32_t res = Security::AccessToken::PrivacyKit::StopUsingPermission(callingTokenId, permissionName);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("StopUsingPermissionCallback failed.");
    }
    if (cameraUseCallbackPtr_) {
        cameraUseCallbackPtr_ = nullptr;
    }
}

void PermissionStatusChangeCb::PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result)
{
    auto item = captureSession_.promote();
    if ((result.permStateChangeType == 0) && (item != nullptr)) {
        item->Release(CaptureSessionReleaseType::RELEASE_TYPE_SECURE);
    }
}

void CameraUseStateChangeCb::StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing)
{
    MEDIA_INFO_LOG("enter CameraUseStateChangeNotify tokenId:%{public}d", tokenId);
    auto item = captureSession_.promote();
    if ((isShowing == false) && (item != nullptr)) {
        item->Release(CaptureSessionReleaseType::RELEASE_TYPE_SECURE);
    }
}

int32_t StreamOperatorCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    MEDIA_DEBUG_LOG("StreamOperatorCallback::OnCaptureStarted");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetStreamByStreamID(streamId);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureStarted StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameStarted();
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId);
        }
    }
    return CAMERA_OK;
}

int32_t StreamOperatorCallback::OnCaptureStartedV1_2(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos)
{
    MEDIA_DEBUG_LOG("StreamOperatorCallback::OnCaptureStartedV1_2");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureStartedV1_2 StreamId: %{public}d not found."
                          " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            MEDIA_DEBUG_LOG("StreamOperatorCallback::OnCaptureStartedV1_2 StreamId: %{public}d."
                            " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId, captureInfo.exposureTime_);
        }
    }
    return CAMERA_OK;
}

int32_t StreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    MEDIA_DEBUG_LOG("StreamOperatorCallback::OnCaptureEnded");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureEnded StreamId: %{public}d not found."
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

int32_t StreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    MEDIA_DEBUG_LOG("StreamOperatorCallback::OnCaptureError");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& errInfo : infos) {
        sptr<HStreamCommon> curStream = GetStreamByStreamID(errInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureError StreamId: %{public}d not found."
                          " Error: %{public}d",
                errInfo.streamId_, errInfo.error_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameError(errInfo.error_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureError(captureId, errInfo.error_);
        }
    }
    return CAMERA_OK;
}

int32_t StreamOperatorCallback::OnFrameShutter(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_DEBUG_LOG("StreamOperatorCallback::OnFrameShutter");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetStreamByStreamID(streamId);
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            CastStream<HStreamCapture>(curStream)->OnFrameShutter(captureId, timestamp);
        } else {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnFrameShutter StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
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
        CaptureSessionState::SESSION_CONFIG_INPROGRESS, CaptureSessionState::SESSION_RELEASED
    };

    stateTransferMap_[static_cast<uint32_t>(CaptureSessionState::SESSION_RELEASED)] = {};
}

bool StateMachine::CheckTransfer(CaptureSessionState targetState)
{
    std::lock_guard<std::recursive_mutex> lock(sessionStateLock_);
    for (auto& state : stateTransferMap_[static_cast<uint32_t>(currentState_)]) {
        if (state == targetState) {
            return true;
        }
    }
    return false;
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
    if (it == list.end()) {
        return false;
    }
    list.erase(it);
    return true;
}

sptr<HStreamCommon> StreamContainer::GetStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            if (stream->GetStreamId() == streamId) {
                return stream;
            }
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
            [&stream](auto& it) { return stream->GetStreamId() <= it->GetStreamId(); });
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
                [&stream](auto& it) { return stream->GetStreamId() <= it->GetStreamId(); });
            totalOrderedStreams.emplace(insertPos, stream);
        }
    }
    return totalOrderedStreams;
}
} // namespace CameraStandard
} // namespace OHOS
