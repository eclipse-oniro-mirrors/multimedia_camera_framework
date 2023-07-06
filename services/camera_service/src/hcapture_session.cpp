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

#include "camera_util.h"
#include "camera_log.h"
#include "surface.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace CameraStandard {
static std::map<int32_t, sptr<HCaptureSession>> session_;
static std::mutex sessionLock_;
static std::map<CaptureSessionState, std::string> sessionState_ = {
    {CaptureSessionState::SESSION_INIT, "Init"},
    {CaptureSessionState::SESSION_CONFIG_INPROGRESS, "Config_In-progress"},
    {CaptureSessionState::SESSION_CONFIG_COMMITTED, "Committed"}
};
static std::string GetClientBundle(int uid)
{
    std::string bundleName = "";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Get ability manager failed");
        return bundleName;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        MEDIA_DEBUG_LOG("object is NULL.");
        return bundleName;
    }

    sptr<AppExecFwk::IBundleMgr> bms = iface_cast<AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        MEDIA_DEBUG_LOG("bundle manager service is NULL.");
        return bundleName;
    }

    auto result = bms->GetBundleNameForUid(uid, bundleName);
    if (!result) {
        MEDIA_ERR_LOG("GetBundleNameForUid fail");
        return "";
    }
    MEDIA_INFO_LOG("bundle name is %{public}s ", bundleName.c_str());

    return bundleName;
}

HCaptureSession::HCaptureSession(sptr<HCameraHostManager> cameraHostManager,
    sptr<StreamOperatorCallback> streamOperatorCb, const uint32_t callingTokenId)
    : cameraHostManager_(cameraHostManager), streamOperatorCallback_(streamOperatorCb),
    sessionCallback_(nullptr)
{
    pid_ = IPCSkeleton::GetCallingPid();
    uid_ = IPCSkeleton::GetCallingUid();
    MEDIA_DEBUG_LOG("HCaptureSession: camera stub services(%{public}zu) pid(%{public}d).", session_.size(), pid_);
    std::map<int32_t, sptr<HCaptureSession>> oldSessions;
    for (auto it = session_.begin(); it != session_.end(); it++) {
        sptr<HCaptureSession> session = it->second;
        oldSessions[it->first] = session;
    }
    for (auto it = oldSessions.begin(); it != oldSessions.end(); it++) {
        if (it->second != nullptr) {
            sptr<HCaptureSession> session = it->second;
            sptr<HCameraDevice> disconnectDevice;
            int32_t rc = session->GetCameraDevice(disconnectDevice);
            if (rc == CAMERA_OK) {
                disconnectDevice->OnError(DEVICE_PREEMPT, 0);
            }
            session->Release(it->first);
            MEDIA_ERR_LOG("currently multi-session not supported, release session for pid(%{public}d)", it->first);
        }
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    session_[pid_] = this;
    callerToken_ = callingTokenId;
    MEDIA_DEBUG_LOG("HCaptureSession: camera stub services(%{public}zu).", session_.size());
}

HCaptureSession::~HCaptureSession()
{}

int32_t HCaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    if (curState_ == CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        MEDIA_ERR_LOG("HCaptureSession::BeginConfig Already in config inprogress state!");
        return CAMERA_INVALID_STATE;
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    prevState_ = curState_;
    curState_ = CaptureSessionState::SESSION_CONFIG_INPROGRESS;
    tempCameraDevices_.clear();
    tempStreams_.clear();
    deletedStreamIds_.clear();
    return CAMERA_OK;
}

int32_t HCaptureSession::AddInput(sptr<ICameraDeviceService> cameraDevice)
{
    CAMERA_SYNC_TRACE;
    sptr<HCameraDevice> localCameraDevice = nullptr;

    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddInput cameraDevice is null");
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    if (curState_ != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        MEDIA_ERR_LOG("HCaptureSession::AddInput Need to call BeginConfig before adding input");
        return CAMERA_INVALID_STATE;
    }
    if (!tempCameraDevices_.empty() || (cameraDevice_ != nullptr && !cameraDevice_->IsReleaseCameraDevice())) {
        MEDIA_ERR_LOG("HCaptureSession::AddInput Only one input is supported");
        return CAMERA_INVALID_SESSION_CFG;
    }
    localCameraDevice = static_cast<HCameraDevice*>(cameraDevice.GetRefPtr());
    if (cameraDevice_ == localCameraDevice && cameraDevice_ != nullptr) {
        cameraDevice_->SetReleaseCameraDevice(false);
    } else {
        tempCameraDevices_.emplace_back(localCameraDevice);
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddInput"));
    }

    sptr<IStreamOperator> streamOperator;
    int32_t rc = localCameraDevice->GetStreamOperator(streamOperatorCallback_, streamOperator);
    if (rc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSession::GetCameraDevice GetStreamOperator returned %{public}d", rc);
        localCameraDevice->Close();
        return rc;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::AddOutputStream(sptr<HStreamCommon> stream)
{
    std::lock_guard<std::mutex> lock(sessionLock_);
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutputStream stream is null");
        return CAMERA_INVALID_ARG;
    }
    if (curState_ != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutputStream Need to call BeginConfig before adding output");
        return CAMERA_INVALID_STATE;
    }
    if (std::find(tempStreams_.begin(), tempStreams_.end(), stream) != tempStreams_.end()) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutputStream Adding same output multiple times in tempStreams_");
        return CAMERA_INVALID_SESSION_CFG;
    }
    int32_t rc = FindRepeatStream(stream);
    if (rc != STREAM_NOT_FOUNT) {
        return rc;
    }
    if (stream) {
        stream->SetReleaseStream(false);
    }
    tempStreams_.emplace_back(stream);
    return CAMERA_OK;
}
int32_t HCaptureSession::FindRepeatStream(sptr<HStreamCommon> stream)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto it = std::find(streams_.begin(), streams_.end(), stream);
    if (it != streams_.end()) {
        if (stream && stream->IsReleaseStream()) {
            stream->SetReleaseStream(false);
            auto it2 = std::find(deletedStreamIds_.begin(), deletedStreamIds_.end(), stream->GetStreamId());
            if (it2 != deletedStreamIds_.end()) {
                deletedStreamIds_.erase(it2);
            }
            return CAMERA_OK;
        } else {
            MEDIA_ERR_LOG("HCaptureSession::AddOutputStream Adding same output multiple times in streams_");
            return CAMERA_INVALID_SESSION_CFG;
        }
    }
    return STREAM_NOT_FOUNT;
}

int32_t HCaptureSession::AddOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t rc = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::AddOutput stream is null");
        return rc;
    }
    // Temp hack to fix the library linking issue
    sptr<Surface> captureSurface = Surface::CreateSurfaceAsConsumer();

    if (streamType == StreamType::CAPTURE) {
        rc = AddOutputStream(static_cast<HStreamCapture *>(stream.GetRefPtr()));
    } else if (streamType == StreamType::REPEAT) {
        rc = AddOutputStream(static_cast<HStreamRepeat *>(stream.GetRefPtr()));
    }  else if (streamType == StreamType::METADATA) {
        rc = AddOutputStream(static_cast<HStreamMetadata *>(stream.GetRefPtr()));
    }
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::AddOutput with %d", streamType));
    MEDIA_INFO_LOG("CaptureSession::AddOutput with with %{public}d, rc = %{public}d", streamType, rc);
    return rc;
}

int32_t HCaptureSession::RemoveInput(sptr<ICameraDeviceService> cameraDevice)
{
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveInput cameraDevice is null");
        return CAMERA_INVALID_ARG;
    }
    if (curState_ != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveInput Need to call BeginConfig before removing input");
        return CAMERA_INVALID_STATE;
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    sptr<HCameraDevice> localCameraDevice;
    localCameraDevice = static_cast<HCameraDevice*>(cameraDevice.GetRefPtr());
    auto it = std::find(tempCameraDevices_.begin(), tempCameraDevices_.end(), localCameraDevice);
    if (it != tempCameraDevices_.end()) {
        tempCameraDevices_.erase(it);
    } else if (cameraDevice_ != nullptr && cameraDevice_ == localCameraDevice) {
        cameraDevice_->SetReleaseCameraDevice(true);
    } else {
        MEDIA_ERR_LOG("HCaptureSession::RemoveInput Invalid camera device");
        return CAMERA_INVALID_SESSION_CFG;
    }
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveInput"));
    return CAMERA_OK;
}

int32_t HCaptureSession::RemoveOutputStream(sptr<HStreamCommon> stream)
{
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutputStream stream is null");
        return CAMERA_INVALID_ARG;
    }
    if (curState_ != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutputStream Need to call BeginConfig before removing output");
        return CAMERA_INVALID_STATE;
    }
    auto it = std::find(tempStreams_.begin(), tempStreams_.end(), stream);
    if (it != tempStreams_.end()) {
        tempStreams_.erase(it);
    } else {
        std::lock_guard<std::mutex> lock(streamsLock_);
        it = std::find(streams_.begin(), streams_.end(), stream);
        if (it != streams_.end()) {
            if (stream && !stream->IsReleaseStream()) {
                deletedStreamIds_.emplace_back(stream->GetStreamId());
                stream->SetReleaseStream(true);
            }
        } else {
            MEDIA_ERR_LOG("HCaptureSession::RemoveOutputStream Invalid output");
            return CAMERA_INVALID_SESSION_CFG;
        }
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t rc = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::RemoveOutput stream is null");
        return rc;
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    if (streamType == StreamType::CAPTURE) {
        rc = RemoveOutputStream(static_cast<HStreamCapture *>(stream.GetRefPtr()));
    } else if (streamType == StreamType::REPEAT) {
        rc = RemoveOutputStream(static_cast<HStreamRepeat *>(stream.GetRefPtr()));
    } else if (streamType == StreamType::METADATA) {
        rc = RemoveOutputStream(static_cast<HStreamMetadata *>(stream.GetRefPtr()));
    }
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CaptureSession::RemoveOutput with %d", streamType));
    return rc;
}

int32_t HCaptureSession::ValidateSessionInputs()
{
    if (tempCameraDevices_.empty() && (cameraDevice_ == nullptr || cameraDevice_->IsReleaseCameraDevice())) {
        MEDIA_ERR_LOG("HCaptureSession::ValidateSessionInputs No inputs present");
        return CAMERA_INVALID_SESSION_CFG;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::ValidateSessionOutputs()
{
    if (tempStreams_.size() + streams_.size() - deletedStreamIds_.size() == 0) {
        MEDIA_ERR_LOG("HCaptureSession::ValidateSessionOutputs No outputs present");
        return CAMERA_INVALID_SESSION_CFG;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::GetCameraDevice(sptr<HCameraDevice> &device)
{
    if (cameraDevice_ != nullptr && !cameraDevice_->IsReleaseCameraDevice()) {
        MEDIA_DEBUG_LOG("HCaptureSession::GetCameraDevice Camera device has not changed");
        device = cameraDevice_;
        return CAMERA_OK;
    } else if (!tempCameraDevices_.empty()) {
        device = tempCameraDevices_[0];
        return CAMERA_OK;
    }

    MEDIA_ERR_LOG("HCaptureSession::GetCameraDevice Failed because don't have camera device");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSession::GetCurrentStreamInfos(sptr<HCameraDevice> &device,
                                               std::shared_ptr<OHOS::Camera::CameraMetadata> &deviceSettings,
                                               std::vector<StreamInfo> &streamInfos)
{
    int32_t rc;
    int32_t streamId = streamId_;
    bool isNeedLink;
    StreamInfo curStreamInfo;
    sptr<IStreamOperator> streamOperator;
    if (device != nullptr) {
        streamOperator = device->GetStreamOperator();
    }
    isNeedLink = (device != cameraDevice_);
    std::lock_guard<std::mutex> lock(streamsLock_);
    sptr<HStreamCommon> curStream;
    for (auto item = streams_.begin(); item != streams_.end(); ++item) {
        curStream = *item;
        if (curStream && curStream->IsReleaseStream()) {
            continue;
        }
        if (curStream && isNeedLink) {
            rc = curStream->LinkInput(streamOperator, deviceSettings, streamId);
            if (rc != CAMERA_OK) {
                MEDIA_ERR_LOG("HCaptureSession::GetCurrentStreamInfos() Failed to link Output, %{public}d", rc);
                return rc;
            }
            streamId++;
        }
        if (curStream) {
            curStream->SetStreamInfo(curStreamInfo);
        }
        streamInfos.push_back(curStreamInfo);
    }
    if (streamId != streamId_) {
        streamId_ = streamId;
    }
    return CAMERA_OK;
}

int32_t HCaptureSession::CreateAndCommitStreams(sptr<HCameraDevice> &device,
                                                std::shared_ptr<OHOS::Camera::CameraMetadata> &deviceSettings,
                                                std::vector<StreamInfo> &streamInfos)
{
    CamRetCode hdiRc = HDI::Camera::V1_0::NO_ERROR;
    StreamInfo curStreamInfo;
    sptr<IStreamOperator> streamOperator;
    if (device != nullptr) {
        streamOperator = device->GetStreamOperator();
    }
    if (streamOperator != nullptr && !streamInfos.empty()) {
        hdiRc = (CamRetCode)(streamOperator->CreateStreams(streamInfos));
    } else {
        MEDIA_INFO_LOG("HCaptureSession::CreateAndCommitStreams(), No new streams to create");
    }
    if (streamOperator != nullptr && hdiRc == HDI::Camera::V1_0::NO_ERROR) {
        std::vector<uint8_t> setting;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(deviceSettings, setting);
        hdiRc = (CamRetCode)(streamOperator->CommitStreams(NORMAL, setting));
        if (hdiRc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCaptureSession::CreateAndCommitStreams(), Failed to commit %{public}d", hdiRc);
            std::vector<int32_t> streamIds;
            for (auto item = streamInfos.begin(); item != streamInfos.end(); ++item) {
                curStreamInfo = *item;
                streamIds.emplace_back(curStreamInfo.streamId_);
            }
            if (!streamIds.empty() && streamOperator->ReleaseStreams(streamIds) != HDI::Camera::V1_0::NO_ERROR) {
                MEDIA_ERR_LOG("HCaptureSession::CreateAndCommitStreams(), Failed to release streams");
            }
        }
    }
    return HdiToServiceError(hdiRc);
}

int32_t HCaptureSession::CheckAndCommitStreams(sptr<HCameraDevice> &device,
                                               std::shared_ptr<OHOS::Camera::CameraMetadata> &deviceSettings,
                                               std::vector<StreamInfo> &allStreamInfos,
                                               std::vector<StreamInfo> &newStreamInfos)
{
    return CreateAndCommitStreams(device, deviceSettings, newStreamInfos);
}

void HCaptureSession::DeleteReleasedStream()
{
    auto matchFunction = [](const auto& curStream) { return curStream->IsReleaseStream();};
    captureStreams_.erase(std::remove_if(captureStreams_.begin(), captureStreams_.end(), matchFunction),
        captureStreams_.end());
    repeatStreams_.erase(std::remove_if(repeatStreams_.begin(), repeatStreams_.end(), matchFunction),
        repeatStreams_.end());
    metadataStreams_.erase(std::remove_if(metadataStreams_.begin(), metadataStreams_.end(), matchFunction),
        metadataStreams_.end());
    {
        std::lock_guard<std::mutex> lock(streamsLock_);
        sptr<HStreamCommon> curStream;
        for (auto item = streams_.begin(); item != streams_.end(); ++item) {
            curStream = *item;
            if (curStream && curStream->IsReleaseStream()) {
                curStream->Release();
                streams_.erase(item--);
            }
        }
    }
}

void HCaptureSession::RestorePreviousState(sptr<HCameraDevice> &device, bool isCreateReleaseStreams)
{
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo;
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    sptr<HStreamCommon> curStream;

    MEDIA_DEBUG_LOG("HCaptureSession::RestorePreviousState, Restore to previous state");
    {
        std::lock_guard<std::mutex> lock(streamsLock_);
        for (auto item = streams_.begin(); item != streams_.end(); ++item) {
            curStream = *item;
            if (curStream && isCreateReleaseStreams && curStream->IsReleaseStream()) {
                curStream->SetStreamInfo(streamInfo);
                streamInfos.push_back(streamInfo);
            }
            if (curStream) {
                curStream->SetReleaseStream(false);
            }
        }
    }
    for (auto item = tempStreams_.begin(); item != tempStreams_.end(); ++item) {
        curStream = *item;
        if (curStream) {
            curStream->Release();
        }
    }
    tempStreams_.clear();
    deletedStreamIds_.clear();
    tempCameraDevices_.clear();
    if (device != nullptr) {
        device->SetReleaseCameraDevice(false);
        if (isCreateReleaseStreams) {
            settings = device->GetSettings();
            if (settings != nullptr) {
                CreateAndCommitStreams(device, settings, streamInfos);
            }
        }
    }
    curState_ = prevState_;
}

void HCaptureSession::UpdateSessionConfig(sptr<HCameraDevice> &device)
{
    DeleteReleasedStream();
    deletedStreamIds_.clear();
    {
        std::lock_guard<std::mutex> lock(streamsLock_);
        sptr<HStreamCommon> curStream;
        for (auto item = tempStreams_.begin(); item != tempStreams_.end(); ++item) {
            curStream = *item;
            if (curStream && curStream->GetStreamType() == StreamType::REPEAT) {
                repeatStreams_.emplace_back(curStream);
            } else if (curStream && curStream->GetStreamType() == StreamType::CAPTURE) {
                captureStreams_.emplace_back(curStream);
            } else if (curStream && curStream->GetStreamType() == StreamType::METADATA) {
                metadataStreams_.emplace_back(curStream);
            }
            streams_.emplace_back(curStream);
        }
    }
    tempStreams_.clear();
    if (streamOperatorCallback_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::UpdateSessionConfig streamOperatorCallback_ is nullptr");
        return;
    }
    streamOperatorCallback_->SetCaptureSession(this);
    cameraDevice_ = device;
    curState_ = CaptureSessionState::SESSION_CONFIG_COMMITTED;
}

int32_t HCaptureSession::HandleCaptureOuputsConfig(sptr<HCameraDevice> &device)
{
    int32_t rc;
    int32_t streamId;
    std::vector<StreamInfo> newStreamInfos;
    std::vector<StreamInfo> allStreamInfos;
    StreamInfo curStreamInfo;
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    sptr<IStreamOperator> streamOperator;
    sptr<HStreamCommon> curStream;
    if (device != nullptr) {
        settings = device->GetSettings();
    }
    if (device == nullptr || settings == nullptr) {
        return CAMERA_UNKNOWN_ERROR;
    }

    rc = GetCurrentStreamInfos(device, settings, allStreamInfos);
    if (rc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSession::HandleCaptureOuputsConfig() Failed to get streams info, %{public}d", rc);
        return rc;
    }

    if (cameraDevice_ != device) {
        newStreamInfos = allStreamInfos;
    }

    streamOperator = device->GetStreamOperator();
    streamId = streamId_;
    for (auto item = tempStreams_.begin(); item != tempStreams_.end(); ++item) {
        curStream = *item;
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::HandleCaptureOuputsConfig() curStream is null");
            return CAMERA_UNKNOWN_ERROR;
        }
        if (curStream) {
            rc = curStream->LinkInput(streamOperator, settings, streamId);
            if (rc != CAMERA_OK) {
                MEDIA_ERR_LOG("HCaptureSession::HandleCaptureOuputsConfig() Failed to link Output, %{public}d", rc);
                return rc;
            }
        }
        if (curStream) {
            curStream->SetStreamInfo(curStreamInfo);
        }
        newStreamInfos.push_back(curStreamInfo);
        allStreamInfos.push_back(curStreamInfo);
        streamId++;
    }

    rc = CheckAndCommitStreams(device, settings, allStreamInfos, newStreamInfos);
    if (rc == CAMERA_OK) {
        streamId_ = streamId;
    }
    return rc;
}

int32_t HCaptureSession::CommitConfig()
{
    sptr<HCameraDevice> device = nullptr;

    if (curState_ != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Need to call BeginConfig before committing configuration");
        return CAMERA_INVALID_STATE;
    }
    
    std::lock_guard<std::mutex> lock(sessionLock_);
    int32_t rc = ValidateSessionInputs();
    if (rc != CAMERA_OK) {
        return rc;
    }
    rc = ValidateSessionOutputs();
    if (rc != CAMERA_OK) {
        return rc;
    }

    rc = GetCameraDevice(device);
    if ((rc == CAMERA_OK) && (device == cameraDevice_) && !deletedStreamIds_.empty()) {
        rc = HdiToServiceError((CamRetCode)(device->GetStreamOperator()->ReleaseStreams(deletedStreamIds_)));
    }

    if (rc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. camera device rc: %{public}d", rc);
        if (device != nullptr && device != cameraDevice_) {
            device->Close();
        }
        RestorePreviousState(cameraDevice_, false);
        return rc;
    }

    rc = HandleCaptureOuputsConfig(device);
    if (rc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSession::CommitConfig() Failed to commit config. rc: %{public}d", rc);
        if (device != nullptr && device != cameraDevice_) {
            device->Close();
        }
        RestorePreviousState(cameraDevice_, !deletedStreamIds_.empty());
        return rc;
    }
    if (device != nullptr) {
        int32_t pid = IPCSkeleton::GetCallingPid();
        int32_t uid = IPCSkeleton::GetCallingUid();
        POWERMGR_SYSEVENT_CAMERA_CONNECT(pid, uid, device->GetCameraId().c_str(),
                                         GetClientBundle(uid));
    }

    if (cameraDevice_ != nullptr && device != cameraDevice_) {
        cameraDevice_->Close();
        cameraDevice_ = nullptr;
    }
    UpdateSessionConfig(device);
    return rc;
}

int32_t HCaptureSession::GetSessionState(CaptureSessionState &sessionState)
{
    int32_t rc = CAMERA_OK;
    sessionState = curState_;
    return rc;
}

int32_t HCaptureSession::Start()
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    if (callerToken_ != callerToken) {
        MEDIA_ERR_LOG("Failed to Start Session, createSession token is : %{public}d, now token is %{public}d",
            callerToken_, callerToken);
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    if (curState_ != CaptureSessionState::SESSION_CONFIG_COMMITTED) {
        MEDIA_ERR_LOG("HCaptureSession::Start(), Invalid session state: %{public}d", curState_);
        return CAMERA_INVALID_STATE;
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    if (IsValidTokenId(callerToken)) {
        if (!Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken, OHOS_PERMISSION_CAMERA)) {
            MEDIA_ERR_LOG("Start session is not allowed!");
            return CAMERA_ALLOC_ERROR;
        }
        StartUsingPermissionCallback(callerToken, OHOS_PERMISSION_CAMERA);
        RegisterPermissionCallback(callerToken, OHOS_PERMISSION_CAMERA);
    }
    sptr<HStreamRepeat> curStreamRepeat;
    int32_t rc = CAMERA_OK;
    for (auto item = repeatStreams_.begin(); item != repeatStreams_.end(); ++item) {
        curStreamRepeat = static_cast<HStreamRepeat *>((*item).GetRefPtr());
        if (!curStreamRepeat->IsVideo()) {
            rc = curStreamRepeat->Start();
            if (rc != CAMERA_OK) {
                MEDIA_ERR_LOG("HCaptureSession::Start(), Failed to start preview, rc: %{public}d", rc);
                break;
            }
        }
    }
    return rc;
}

int32_t HCaptureSession::Stop()
{
    int32_t rc = CAMERA_OK;
    sptr<HStreamRepeat> curStreamRepeat;
    if (curState_ != CaptureSessionState::SESSION_CONFIG_COMMITTED) {
        return CAMERA_INVALID_STATE;
    }
    std::lock_guard<std::mutex> lock(sessionLock_);
    for (auto item = repeatStreams_.begin(); item != repeatStreams_.end(); ++item) {
        curStreamRepeat = static_cast<HStreamRepeat *>((*item).GetRefPtr());
        if (!curStreamRepeat->IsVideo()) {
            rc = curStreamRepeat->Stop();
            if (rc != CAMERA_OK) {
                MEDIA_ERR_LOG("HCaptureSession::Stop(), Failed to stop preview, rc: %{public}d", rc);
                break;
            }
        }
    }

    return rc;
}

void HCaptureSession::ClearCaptureSession(pid_t pid)
{
    MEDIA_DEBUG_LOG("ClearCaptureSession: camera stub services(%{public}zu) pid(%{public}d).", session_.size(), pid);
    auto it = session_.find(pid);
    if (it != session_.end()) {
        session_.erase(it);
    }
    MEDIA_DEBUG_LOG("ClearCaptureSession: camera stub services(%{public}zu).", session_.size());
}

void HCaptureSession::ReleaseStreams()
{
    std::vector<int32_t> streamIds;
    {
        std::lock_guard<std::mutex> lock(streamsLock_);
        sptr<HStreamCommon> curStream;
        for (auto item = streams_.begin(); item != streams_.end(); ++item) {
            curStream = *item;
            if (curStream) {
                streamIds.emplace_back(curStream->GetStreamId());
                curStream->Release();
            }
        }
        streams_.clear();
    }
    repeatStreams_.clear();
    captureStreams_.clear();
    metadataStreams_.clear();
    if ((cameraDevice_ != nullptr) && (cameraDevice_->GetStreamOperator() != nullptr) && !streamIds.empty()) {
        cameraDevice_->GetStreamOperator()->ReleaseStreams(streamIds);
    }
}

int32_t HCaptureSession::ReleaseInner()
{
    MEDIA_INFO_LOG("HCaptureSession::ReleaseInner enter");
    return Release(pid_);
}

int32_t HCaptureSession::Release(pid_t pid)
{
    std::lock_guard<std::mutex> lock(sessionLock_);
    MEDIA_INFO_LOG("HCaptureSession::Release pid(%{public}d).", pid);
    auto it = session_.find(pid);
    if (it == session_.end()) {
        MEDIA_DEBUG_LOG("HCaptureSession::Release session for pid(%{public}d) already released.", pid);
        return CAMERA_OK;
    }
    ReleaseStreams();
    tempCameraDevices_.clear();
    if (streamOperatorCallback_ != nullptr) {
        streamOperatorCallback_->SetCaptureSession(nullptr);
        streamOperatorCallback_ = nullptr;
    }
    if (cameraDevice_ != nullptr) {
        cameraDevice_->Close();
        POWERMGR_SYSEVENT_CAMERA_DISCONNECT(cameraDevice_->GetCameraId().c_str());
        cameraDevice_ = nullptr;
    }
    if (IsValidTokenId(callerToken_)) {
        StopUsingPermissionCallback(callerToken_, OHOS_PERMISSION_CAMERA);
        UnregisterPermissionCallback(callerToken_);
    }
    tempStreams_.clear();
    ClearCaptureSession(pid);
    sessionCallback_ = nullptr;
    cameraHostManager_ = nullptr;
    return CAMERA_OK;
}

void HCaptureSession::RegisterPermissionCallback(const uint32_t callingTokenId, const std::string permissionName)
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {permissionName};
    scopeInfo.tokenIDs = {callingTokenId};
    callbackPtr_ = std::make_shared<PermissionStatusChangeCb>(scopeInfo);
    callbackPtr_->SetCaptureSession(this);
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
    if (callbackPtr_) {
        callbackPtr_->SetCaptureSession(nullptr);
        callbackPtr_ = nullptr;
    }
    MEDIA_DEBUG_LOG("after tokenId:%{public}d unregister", callingTokenId);
}

void HCaptureSession::DestroyStubObjectForPid(pid_t pid)
{
    MEDIA_DEBUG_LOG("camera stub services(%{public}zu) pid(%{public}d).", session_.size(), pid);
    sptr<HCaptureSession> session;

    auto it = session_.find(pid);
    if (it != session_.end()) {
        if (it->second != nullptr) {
            session = it->second;
            session->Release(pid);
        }
    }
    MEDIA_DEBUG_LOG("camera stub services(%{public}zu).", session_.size());
}

int32_t HCaptureSession::SetCallback(sptr<ICaptureSessionCallback> &callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }

    sessionCallback_ = callback;
    return CAMERA_OK;
}

std::string HCaptureSession::GetSessionState()
{
    std::map<CaptureSessionState, std::string>::const_iterator iter =
        sessionState_.find(curState_);
    if (iter != sessionState_.end()) {
        return iter->second;
    }
    return nullptr;
}

void HCaptureSession::CameraSessionSummary(std::string& dumpString)
{
    dumpString += "# Number of Camera clients:[" + std::to_string(session_.size()) + "]:\n";
}

void HCaptureSession::dumpSessions(std::string& dumpString)
{
    for (auto it = session_.begin(); it != session_.end(); it++) {
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
    if (cameraDevice_ != nullptr) {
        dumpString += "session Camera Id:[" + cameraDevice_->GetCameraId() + "]:\n";
        dumpString += "session Camera release status:["
        + std::to_string(cameraDevice_->IsReleaseCameraDevice()) + "]:\n";
    }
    for (const auto& stream : captureStreams_) {
        stream->DumpStreamInfo(dumpString);
    }
    for (const auto& stream : repeatStreams_) {
        stream->DumpStreamInfo(dumpString);
    }
    for (const auto& stream : metadataStreams_) {
        stream->DumpStreamInfo(dumpString);
    }
}

void HCaptureSession::StartUsingPermissionCallback(const uint32_t callingTokenId, const std::string permissionName)
{
    if (cameraUseCallbackPtr_) {
        MEDIA_ERR_LOG("has StartUsingPermissionCallback!");
        return;
    }
    cameraUseCallbackPtr_ = std::make_shared<CameraUseStateChangeCb>();
    cameraUseCallbackPtr_->SetCaptureSession(this);
    int32_t res = Security::AccessToken::PrivacyKit::StartUsingPermission(
        callingTokenId, permissionName, cameraUseCallbackPtr_);
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
        cameraUseCallbackPtr_->SetCaptureSession(nullptr);
        cameraUseCallbackPtr_ = nullptr;
    }
}

PermissionStatusChangeCb::~PermissionStatusChangeCb()
{
    captureSession_ = nullptr;
}

void PermissionStatusChangeCb::SetCaptureSession(sptr<HCaptureSession> captureSession)
{
    captureSession_ = captureSession;
}

void PermissionStatusChangeCb::PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result)
{
    auto item = captureSession_.promote();
    if ((result.PermStateChangeType == 0) && (item != nullptr)) {
        item->ReleaseInner();
    }
};

CameraUseStateChangeCb::~CameraUseStateChangeCb()
{
    captureSession_ = nullptr;
}

void CameraUseStateChangeCb::SetCaptureSession(sptr<HCaptureSession> captureSession)
{
    captureSession_ = captureSession;
}

void CameraUseStateChangeCb::StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing)
{
    const int32_t delayProcessTime = 200000;
    usleep(delayProcessTime);
    MEDIA_INFO_LOG("enter CameraUseStateChangeNotify tokenId:%{public}d", tokenId);
    auto item = captureSession_.promote();
    if ((isShowing == false) && (item != nullptr)) {
        item->ReleaseInner();
    }
};


StreamOperatorCallback::StreamOperatorCallback(sptr<HCaptureSession> session)
{
    captureSession_ = session;
}

StreamOperatorCallback::~StreamOperatorCallback()
{
    captureSession_ = nullptr;
}

sptr<HStreamCommon> StreamOperatorCallback::GetStreamByStreamID(int32_t streamId)
{
    sptr<HStreamCommon> result = nullptr;
    if (captureSession_ != nullptr) {
        std::lock_guard<std::mutex> lock(captureSession_->streamsLock_);
        for (const auto &item : captureSession_->streams_) {
            if (item && item->GetStreamId() == streamId) {
                result = item;
                break;
            }
        }
    }
    return result;
}

int32_t StreamOperatorCallback::OnCaptureStarted(int32_t captureId,
                                                 const std::vector<int32_t> &streamIds)
{
    sptr<HStreamCommon> curStream;
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto item = streamIds.begin(); item != streamIds.end(); ++item) {
        curStream = GetStreamByStreamID(*item);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureStarted StreamId: %{public}d not found", *item);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            static_cast<HStreamRepeat *>(curStream.GetRefPtr())->OnFrameStarted();
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            static_cast<HStreamCapture *>(curStream.GetRefPtr())->OnCaptureStarted(captureId);
        }
    }
    return CAMERA_OK;
}

int32_t StreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    sptr<HStreamCommon> curStream;
    CaptureEndedInfo captureInfo;
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto item = infos.begin(); item != infos.end(); ++item) {
        captureInfo = *item;
        curStream = GetStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureEnded StreamId: %{public}d not found."
                          " Framecount: %{public}d", captureInfo.streamId_, captureInfo.frameCount_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            static_cast<HStreamRepeat *>(curStream.GetRefPtr())->OnFrameEnded(captureInfo.frameCount_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            static_cast<HStreamCapture *>(curStream.GetRefPtr())->OnCaptureEnded(captureId, captureInfo.frameCount_);
        }
    }
    return CAMERA_OK;
}

int32_t StreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    sptr<HStreamCommon> curStream;
    CaptureErrorInfo errInfo;
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto item = infos.begin(); item != infos.end(); ++item) {
        errInfo = *item;
        curStream = GetStreamByStreamID(errInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnCaptureError StreamId: %{public}d not found."
                          " Error: %{public}d", errInfo.streamId_, errInfo.error_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            static_cast<HStreamRepeat *>(curStream.GetRefPtr())->OnFrameError(errInfo.error_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            static_cast<HStreamCapture *>(curStream.GetRefPtr())->OnCaptureError(captureId, errInfo.error_);
        }
    }
    return CAMERA_OK;
}

int32_t StreamOperatorCallback::OnFrameShutter(int32_t captureId,
                                               const std::vector<int32_t> &streamIds,
                                               uint64_t timestamp)
{
    sptr<HStreamCommon> curStream;
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto item = streamIds.begin(); item != streamIds.end(); ++item) {
        curStream = GetStreamByStreamID(*item);
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            static_cast<HStreamCapture *>(curStream.GetRefPtr())->OnFrameShutter(captureId, timestamp);
        } else {
            MEDIA_ERR_LOG("StreamOperatorCallback::OnFrameShutter StreamId: %{public}d not found", *item);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

void StreamOperatorCallback::SetCaptureSession(sptr<HCaptureSession> captureSession)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    captureSession_ = captureSession;
}
} // namespace CameraStandard
} // namespace OHOS
