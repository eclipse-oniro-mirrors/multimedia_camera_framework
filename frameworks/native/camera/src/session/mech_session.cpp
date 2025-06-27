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

int32_t MechSessionCallbackImpl::OnFocusTrackingInfo(int32_t streamId, bool isNeedMirror, bool isNeedFlip,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    int32_t ret = CAMERA_OK;
    auto mechSession = mechSession_.promote();
    CHECK_ERROR_RETURN_RET(!mechSession, ret);
    auto appCallback = mechSession->GetCallback();
    CHECK_ERROR_RETURN_RET(!appCallback, ret);

    FocusTrackingMetaInfo info;
    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    Rect region = {0.0, 0.0, 0.0, 0.0};
    std::vector<sptr<MetadataObject>> metaObjects;

    MetadataCommonUtils::ProcessFocusTrackingModeInfo(result, mode);
    info.SetTrackingMode(mode);

    ProcessRectInfo(result, region);
    info.SetTrackingRegion(region);

    MetadataCommonUtils::ProcessMetaObjects(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    info.SetDetectedObjects(metaObjects);

    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(result->get(), OHOS_CONTROL_FOCUS_TRACKING_OBJECT_ID, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        info.SetTrackingObjectId(item.data.i32[0]);
    }
    appCallback->OnFocusTrackingInfo(info);
    return ret;
}

int32_t MechSessionCallbackImpl::OnCameraAppInfo(const std::vector<CameraAppInfo>& cameraAppInfos)
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    int32_t ret = CAMERA_OK;
    auto mechSession = mechSession_.promote();
    CHECK_ERROR_RETURN_RET(!mechSession, ret);
    auto appCallback = mechSession->GetCallback();
    CHECK_ERROR_RETURN_RET(!appCallback, ret);

    appCallback->OnCameraAppInfo(cameraAppInfos);
    return CAMERA_OK;
}

bool MechSessionCallbackImpl::ProcessRectInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
    Rect& rect)
{
    constexpr int32_t scale = 1000000;
    constexpr int32_t offsetOne = 1;
    constexpr int32_t offsetTwo = 2;
    constexpr int32_t offsetThree = 3;
 
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false, "metadata is nullptr");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_TRACKING_REGION, &item);
    if (ret != CAM_META_SUCCESS || item.count < FOCUS_TRACKING_REGION_DATA_CNT) {
        MEDIA_DEBUG_LOG("%{public}s FindCameraMetadataItem failed", __FUNCTION__);
        return false;
    }
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

MechSession::MechSession(sptr<IMechSession> session) : remoteSession_(session)
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    sptr<IRemoteObject> object = remoteSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_ERROR_RETURN_LOG(deathRecipient_ == nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb([this](pid_t pid) { CameraServerDied(pid); });
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return;
    }
}

MechSession::~MechSession()
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    RemoveDeathRecipient();
}

int32_t MechSession::EnableMechDelivery(bool isEnableMech)
{
    MEDIA_INFO_LOG("%{public}s is called, isEnableMech:%{public}d", __FUNCTION__, isEnableMech);
    auto remoteSession = GetRemoteSession();
    CHECK_ERROR_RETURN_RET_LOG(remoteSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "MechSession::EnableMechDelivery mechSession is nullptr");

    int32_t retCode = remoteSession->EnableMechDelivery(isEnableMech);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CAMERA_OK, retCode,
        "Failed to EnableMechDelivery!, %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
}

void MechSession::SetCallback(std::shared_ptr<MechSessionCallback> callback)
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto remoteSession = GetRemoteSession();
    CHECK_ERROR_RETURN_LOG(remoteSession == nullptr,
        "MechSession::SetCallback mechSession is null");
    sptr<IMechSessionCallback> remoteCallback = new(std::nothrow) MechSessionCallbackImpl(this);
    CHECK_ERROR_RETURN_LOG(remoteCallback == nullptr,
        "MechSession::SetCallback failed to new MechSessionCallbackImpl!");
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
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
    auto remoteSession = GetRemoteSession();
    CHECK_ERROR_RETURN_RET_LOG(remoteSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "MechSession::Release remoteSession is nullptr");
    int32_t retCode = remoteSession->Release();
    CHECK_ERROR_RETURN_RET_LOG(retCode != CAMERA_OK, retCode,
        "Failed to Release!, %{public}d", retCode);
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
