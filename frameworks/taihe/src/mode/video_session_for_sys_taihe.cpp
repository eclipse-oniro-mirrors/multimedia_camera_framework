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
#include "camera_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "session/camera_session_taihe.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_input_taihe.h"
#include "camera_output_taihe.h"
#include "camera_input.h"
#include "camera_security_utils_taihe.h"
 
namespace Ani {
namespace Camera {
using namespace std;
using namespace taihe;
using namespace ohos::multimedia::camera;

void VideoSessionForSysImpl::RegisterFocusTrackingInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_DEBUG_LOG("VideoSessionForSysImpl::RegisterFocusTrackingInfoCallbackListener is called");
    CHECK_ERROR_RETURN_LOG(videoSession_ == nullptr, "videoSession is nullptr!");
    if (focusTrackingInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        focusTrackingInfoCallback_ = std::make_shared<FocusTrackingCallbackListener>(env);
        videoSession_->SetFocusTrackingInfoCallback(focusTrackingInfoCallback_);
    }
    focusTrackingInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionForSysImpl::UnregisterFocusTrackingInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(focusTrackingInfoCallback_ == nullptr,
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
    auto taiheMode = CameraUtilsTaihe::ToTaiheFocusTrackingMode(focusTrackingInfo.GetMode());
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
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFocusTrackingInfoAvailable",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoSessionForSysImpl::RegisterLightStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("VideoSessionForSysImpl::RegisterLightStatusCallbackListener called");
    if (lightStatusCallback_ == nullptr) {
        ani_env *env = get_env();
        lightStatusCallback_ = std::make_shared<LightStatusCallbackListener>(env);
        videoSession_->SetLightStatusCallback(lightStatusCallback_);
        videoSession_->SetLightStatus(0);
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
        auto taiheStatus = CameraUtilsTaihe::ToTaiheLightStatus(status.status);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("lightStatusChange", 0, "Callback is OK", taiheStatus));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnLightStatusChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void LightStatusCallbackListener::OnLightStatusChanged(OHOS::CameraStandard::LightStatus &status)
{
    MEDIA_DEBUG_LOG("OnLightStatusChanged is called, lightStatus: %{public}d", status.status);
    OnLightStatusChangedCallback(status);
}
} // namespace Camera
} // namespace Ani

