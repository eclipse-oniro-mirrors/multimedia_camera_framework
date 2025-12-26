/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <uv.h>

#include "video_session_for_sys_taihe.h"
 
namespace Ani {
namespace Camera {
using namespace std;
using namespace taihe;
using namespace ohos::multimedia::camera;

void VideoSessionForSysImpl::RegisterFocusTrackingInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_DEBUG_LOG("VideoSessionForSysImpl::RegisterFocusTrackingInfoCallbackListener is called");
    CHECK_RETURN_ELOG(videoSessionForSys_ == nullptr, "videoSessionForSys is nullptr!");
    if (focusTrackingInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        focusTrackingInfoCallback_ = std::make_shared<FocusTrackingCallbackListener>(env);
        videoSessionForSys_->SetFocusTrackingInfoCallback(focusTrackingInfoCallback_);
    }
    focusTrackingInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionForSysImpl::UnregisterFocusTrackingInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(focusTrackingInfoCallback_ == nullptr,
        "focusTrackingInfoCallback_ is nullptr");
    focusTrackingInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void FocusTrackingCallbackListener::OnFocusTrackingInfoAvailable(
    OHOS::CameraStandard::FocusTrackingInfo &focusTrackingInfo) const
{
    OnFocusTrackingInfoCallback(focusTrackingInfo);
}

void FocusTrackingCallbackListener::OnFocusTrackingInfoCallback(
    OHOS::CameraStandard::FocusTrackingInfo &focusTrackingInfo) const
{
    auto sharePtr = shared_from_this();
    auto taiheMode = FocusTrackingMode::from_value(static_cast<int32_t>(focusTrackingInfo.GetMode()));
    ohos::multimedia::camera::Rect taiheRect = {
        .topLeftX = focusTrackingInfo.GetRegion().topLeftX,
        .topLeftY = focusTrackingInfo.GetRegion().topLeftY,
        .width = focusTrackingInfo.GetRegion().width,
        .height = focusTrackingInfo.GetRegion().height,
    };
    FocusTrackingInfo taiheFocusTrackingInfo = {
        taiheMode,
        taiheRect
    };
    auto task = [taiheFocusTrackingInfo, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteCallback<FocusTrackingInfo const&>(
            "focusTrackingInfoAvailable", taiheFocusTrackingInfo));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFocusTrackingInfoAvailable",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoSessionForSysImpl::RegisterLightStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("VideoSessionForSysImpl::RegisterLightStatusCallbackListener called");
    CHECK_RETURN_ELOG(videoSessionForSys_ == nullptr, "videoSessionForSys_ is null!");
    if (lightStatusCallback_ == nullptr) {
        ani_env *env = get_env();
        lightStatusCallback_ = std::make_shared<LightStatusCallbackListener>(env);
        videoSessionForSys_->SetLightStatusCallback(lightStatusCallback_);
        videoSessionForSys_->SetLightStatus(0);
    }
    lightStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionForSysImpl::UnregisterLightStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("VideoSessionForSysImpl::UnregisterLightStatusCallbackListener is called");
    if (lightStatusCallback_ == nullptr) {
        MEDIA_DEBUG_LOG("abilityCallback is null");
    } else {
        lightStatusCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void LightStatusCallbackListener::OnLightStatusChangedCallback(OHOS::CameraStandard::LightStatus &status) const
{
    MEDIA_DEBUG_LOG("OnLightStatusChangedCallback is called, light status is %{public}d", status.status);
    auto sharePtr = shared_from_this();
    auto task = [status, sharePtr]() {
        auto taiheStatus = LightStatus::from_value(static_cast<int32_t>(status.status));
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("lightStatusChange", 0, "Callback is OK", taiheStatus));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnLightStatusChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void LightStatusCallbackListener::OnLightStatusChanged(OHOS::CameraStandard::LightStatus &status)
{
    MEDIA_DEBUG_LOG("OnLightStatusChanged is called, lightStatus: %{public}d", status.status);
    OnLightStatusChangedCallback(status);
}
} // namespace Camera
} // namespace Ani

