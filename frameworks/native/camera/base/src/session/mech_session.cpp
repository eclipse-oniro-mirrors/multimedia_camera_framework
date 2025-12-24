/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "session/mech_session.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t FOCUS_TRACKING_REGION_DATA_CNT = 4;
constexpr int32_t LOG_INTERVAL_FREQUENCY = 10;

int32_t MechSessionCallbackImpl::OnFocusTrackingInfo(int32_t streamId, bool isNeedMirror, bool isNeedFlip,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    int32_t ret = CAMERA_OK;
    CHECK_RETURN_RET(result == nullptr, ret);
    auto mechSession = mechSession_.promote();
    CHECK_RETURN_RET(!mechSession, ret);
    auto appCallback = mechSession->GetCallback();
    CHECK_RETURN_RET(!appCallback, ret);

    FocusTrackingMetaInfo info;
    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    Rect region = {0.0, 0.0, 0.0, 0.0};
    std::vector<sptr<MetadataObject>> metaObjects;

    MetadataCommonUtils::ProcessFocusTrackingModeInfo(result, mode);
    info.SetTrackingMode(mode);

    ProcessRectInfo(result, region);
    info.SetTrackingRegion(region);

    MetadataCommonUtils::ProcessMetaObjects(streamId, result, metaObjects, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_MECH);
    info.SetDetectedObjects(metaObjects);

    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(result->get(), OHOS_CONTROL_FOCUS_TRACKING_OBJECT_ID, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        info.SetTrackingObjectId(item.data.i32[0]);
    }
    PrintFocusTrackingInfo(info);
    appCallback->OnFocusTrackingInfo(info);
    return ret;
}

int32_t MechSessionCallbackImpl::OnCaptureSessionConfiged(const CaptureSessionInfo& captureSessionInfo)
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    int32_t ret = CAMERA_OK;
    auto mechSession = mechSession_.promote();
    CHECK_RETURN_RET(!mechSession, ret);
    auto appCallback = mechSession->GetCallback();
    CHECK_RETURN_RET(!appCallback, ret);
    PrintCaptureSessionInfo(captureSessionInfo);
    appCallback->OnCaptureSessionConfiged(captureSessionInfo);
    return CAMERA_OK;
}

int32_t MechSessionCallbackImpl::OnZoomInfoChange(int32_t sessionid, const ZoomInfo& zoomInfo)
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    int32_t ret = CAMERA_OK;
    auto mechSession = mechSession_.promote();
    CHECK_RETURN_RET(!mechSession, ret);
    auto appCallback = mechSession->GetCallback();
    CHECK_RETURN_RET(!appCallback, ret);
    MEDIA_INFO_LOG("%{public}s sessionid:%{public}d, zoomValue:%{public}f,"
        "equivalentFocus:%{public}d, focusStatus:%{public}d,"
        "focusMode:%{public}d, videoStabilizationMode:%{public}d",
        __FUNCTION__, sessionid, zoomInfo.zoomValue,
        zoomInfo.equivalentFocus, zoomInfo.focusStatus,
        zoomInfo.focusMode, zoomInfo.videoStabilizationMode);
    appCallback->OnZoomInfoChange(sessionid, zoomInfo);
    return CAMERA_OK;
}

int32_t MechSessionCallbackImpl::OnSessionStatusChange(int32_t sessionid, bool status)
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    int32_t ret = CAMERA_OK;
    auto mechSession = mechSession_.promote();
    CHECK_RETURN_RET(!mechSession, ret);
    auto appCallback = mechSession->GetCallback();
    CHECK_RETURN_RET(!appCallback, ret);
    MEDIA_INFO_LOG("%{public}s sessionid:%{public}d, status:%{public}d",
        __FUNCTION__, sessionid, status);
    appCallback->OnSessionStatusChange(sessionid, status);
    return CAMERA_OK;
}

bool MechSessionCallbackImpl::ProcessRectInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
    Rect& rect)
{
    constexpr int32_t scale = 1000000;
    constexpr int32_t offsetOne = 1;
    constexpr int32_t offsetTwo = 2;
    constexpr int32_t offsetThree = 3;

    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "metadata is nullptr");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_TRACKING_REGION, &item);
    CHECK_RETURN_RET_DLOG(ret != CAM_META_SUCCESS || item.count < FOCUS_TRACKING_REGION_DATA_CNT, false,
        "%{public}s FindCameraMetadataItem failed", __FUNCTION__);
    int32_t left = item.data.i32[0];
    int32_t top = item.data.i32[offsetOne];
    int32_t width = item.data.i32[offsetTwo];
    int32_t height = item.data.i32[offsetThree];

    double rectLeft = static_cast<double>(left);
    double rectTop = static_cast<double>(top);
    double rectWidth = static_cast<double>(width);
    double rectHeight = static_cast<double>(height);

    rect = { rectLeft / scale, rectTop / scale, rectWidth / scale, rectHeight / scale};
    return true;
}

void MechSessionCallbackImpl::PrintFocusTrackingInfo(FocusTrackingMetaInfo& info)
{
    logCount_ ++;
    CHECK_RETURN(logCount_ % LOG_INTERVAL_FREQUENCY != 0);
    auto trackingRegion = info.GetTrackingRegion();
    MEDIA_INFO_LOG("OnFocusTrackingInfo trackingRegion: "
        "[%{public}f, %{public}f, %{public}f, %{public}f], "
        "trackingObjectId:%{public}d ",
        trackingRegion.topLeftX, trackingRegion.topLeftY,
        trackingRegion.width, trackingRegion.height,
        info.GetTrackingObjectId());

    auto detectedObjects = info.GetDetectedObjects();
    MEDIA_INFO_LOG("OnFocusTrackingInfo detectedObjects size:%{public}d", static_cast<int32_t>(detectedObjects.size()));
    for (size_t i = 0; i < detectedObjects.size(); i++) {
        auto metadataObject = detectedObjects[i];
        auto type = metadataObject->GetType();
        auto box = metadataObject->GetBoundingBox();
        int32_t objectId = metadataObject->GetObjectId();
        int32_t confidence = metadataObject->GetConfidence();
        MEDIA_INFO_LOG("OnFocusTrackingInfo detectedObject type:%{public}d, "
            "boundingBox:[%{public}f, %{public}f, %{public}f, %{public}f], "
            "objectId:%{public}d, confidence:%{public}d",
            type, box.topLeftX, box.topLeftY,
            box.width, box.height, objectId, confidence);
    }
}

void MechSessionCallbackImpl::PrintCaptureSessionInfo(const CaptureSessionInfo& captureSessionInfo)
{
    MEDIA_INFO_LOG("OnCaptureSessionConfiged sessionId:%{public}d, "
        "cameraId:%{public}s, position:%{public}d, sessionMode:%{public}d, "
        "colorSpace:%{public}d, sessionStatus:%{public}d",
        captureSessionInfo.sessionId, captureSessionInfo.cameraId.c_str(),
        captureSessionInfo.position, captureSessionInfo.sessionMode,
        captureSessionInfo.colorSpace, captureSessionInfo.sessionStatus);

    auto outputInfos = captureSessionInfo.outputInfos;
    MEDIA_INFO_LOG("OnCaptureSessionConfiged outputInfos size:%{public}d", static_cast<int32_t>(outputInfos.size()));
    for (size_t i = 0; i < outputInfos.size(); i++) {
        auto outputInfo = outputInfos[i];
        MEDIA_INFO_LOG("OnCaptureSessionConfiged outputInfo type:%{public}d, "
            "minfps:%{public}d, maxfps:%{public}d, width:%{public}d, "
            "height:%{public}d",
            outputInfo.type, outputInfo.minfps, outputInfo.minfps,
            outputInfo.width, outputInfo.height);
    }

    auto zoomInfo = captureSessionInfo.zoomInfo;
    MEDIA_INFO_LOG("OnCaptureSessionConfiged zoomInfo zoomValue:%{public}f, "
        "equivalentFocus:%{public}d, focusStatus:%{public}d, focusMode:%{public}d, "
        "videoStabilizationMode:%{public}d",
        zoomInfo.zoomValue, zoomInfo.equivalentFocus, zoomInfo.focusStatus,
        zoomInfo.focusMode, zoomInfo.videoStabilizationMode);
}

MechSession::MechSession(sptr<IMechSession> session) : remoteSession_(session)
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    sptr<IRemoteObject> object = remoteSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_ELOG(deathRecipient_ == nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb([this](pid_t pid) { CameraServerDied(pid); });
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_ELOG(!result, "failed to add deathRecipient");
}

MechSession::~MechSession()
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    RemoveDeathRecipient();
}

int32_t MechSession::EnableMechDelivery(bool isEnableMech)
{
    MEDIA_INFO_LOG("%{public}s is called, isEnableMech:%{public}d", __FUNCTION__, isEnableMech);
    auto remoteSession = GetRemoteSession();
    CHECK_RETURN_RET_ELOG(remoteSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "MechSession::EnableMechDelivery mechSession is nullptr");

    int32_t retCode = remoteSession->EnableMechDelivery(isEnableMech);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "Failed to EnableMechDelivery!, %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
}

void MechSession::SetCallback(std::shared_ptr<MechSessionCallback> callback)
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto remoteSession = GetRemoteSession();
    CHECK_RETURN_ELOG(remoteSession == nullptr, "MechSession::SetCallback mechSession is null");
    sptr<IMechSessionCallback> remoteCallback = new(std::nothrow) MechSessionCallbackImpl(this);
    CHECK_RETURN_ELOG(remoteCallback == nullptr, "MechSession::SetCallback failed to new MechSessionCallbackImpl!");
    remoteSession->SetCallback(remoteCallback);

    appCallback_ = callback;
}

std::shared_ptr<MechSessionCallback> MechSession::GetCallback()
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    return appCallback_;
}

int32_t MechSession::Release()
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    auto remoteSession = GetRemoteSession();
    CHECK_RETURN_RET_ELOG(
        remoteSession == nullptr, CameraErrorCode::INVALID_ARGUMENT, "MechSession::Release remoteSession is nullptr");
    int32_t retCode = remoteSession->Release();
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "Failed to Release!, %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
}

sptr<IMechSession> MechSession::GetRemoteSession()
{
    std::lock_guard<std::mutex> lock(remoteSessionMutex_);
    return remoteSession_;
}

void MechSession::SetRemoteSession(sptr<IMechSession> remoteSession)
{
    std::lock_guard<std::mutex> lock(remoteSessionMutex_);
    remoteSession_ = remoteSession;
}

void MechSession::RemoveDeathRecipient()
{
    auto remoteSession = GetRemoteSession();
    if (remoteSession != nullptr) {
        auto asObject = remoteSession->AsObject();
        if (asObject) {
            (void)asObject->RemoveDeathRecipient(deathRecipient_);
        }
        SetRemoteSession(nullptr);
    }
    deathRecipient_ = nullptr;
}

void MechSession::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    RemoveDeathRecipient();
}
} // namespace CameraStandard
} // namespace OHOS
