/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include  "camera_security_utils_taihe.h"
#include "slow_motion_video_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

void SlowMotionStateListener::OnSlowMotionState(const OHOS::CameraStandard::SlowMotionState state)
{
    MEDIA_DEBUG_LOG("SlowMotionStateListener::OnSlowMotionState is called");
    OnSlowMotionStateCb(state);
}
void SlowMotionStateListener::OnSlowMotionStateCb(const OHOS::CameraStandard::SlowMotionState state) const
{
    MEDIA_DEBUG_LOG("SlowMotionStateListener::OnSlowMotionStateCb is called");
    auto sharePtr = shared_from_this();
    auto task = [state, sharePtr]() {
        auto taiheState = CameraUtilsTaihe::ToTaiheSlowMotionState(state);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("slowMotionStatus", 0, "Callback is OK", taiheState));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnSlowMotionStatus", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SlowMotionZoomInfoListener::OnZoomInfoChange(const std::vector<float> zoomInfoRange)
{
    MEDIA_DEBUG_LOG("SlowMotionZoomInfoListener::OnZoomInfoChange is called");
    OnZoomInfoChangeCb(zoomInfoRange);
}

void SlowMotionZoomInfoListener::OnZoomInfoChangeCb(const std::vector<float> zoomInfoRange) const
{
    MEDIA_DEBUG_LOG("SlowMotionZoomInfoListener::OnZoomInfoChangeCb is called");
    auto sharePtr = shared_from_this();
    auto task = [zoomInfoRange, sharePtr]() {
        std::vector<double> zoomInfoTemp;
        for (auto item : zoomInfoRange) {
            zoomInfoTemp.push_back(static_cast<double>(item));
        }
        ZoomInfo zoomInfoTaihe {};
        zoomInfoTaihe.zoomRatioRange = optional<array<double>>::make(zoomInfoTemp);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<ZoomInfo const&>("zoomInfoChange", 0, "Callback is OK", zoomInfoTaihe));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnZoomInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SlowMotionVideoSessionImpl::RegisterSlowMotionStateCb(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("RegisterSlowMotionStateCb is called");
    if (slowMotionState_ == nullptr) {
        ani_env *env = get_env();
        auto slowMotionStateListenerTemp =
            std::static_pointer_cast<SlowMotionStateListener>(slowMotionSession_->GetApplicationCallback());
        if (slowMotionStateListenerTemp == nullptr) {
            slowMotionStateListenerTemp = std::make_shared<SlowMotionStateListener>(env);
            CHECK_RETURN_ELOG(slowMotionSession_ == nullptr, "slowMotionSession_ is null!");
            slowMotionSession_->SetCallback(slowMotionStateListenerTemp);
        }
        slowMotionState_ = slowMotionStateListenerTemp;
    }
    slowMotionState_->SaveCallbackReference(eventName, callback, isOnce);
    MEDIA_INFO_LOG("RegisterSlowMotionStateCb success");
}

void SlowMotionVideoSessionImpl::UnregisterSlowMotionStateCb(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("UnregisterSlowMotionStateCb is called");
    CHECK_RETURN_ELOG(slowMotionState_ == nullptr, "slowMotionState_ is null");
    slowMotionState_->RemoveCallbackRef(eventName, callback);
    MEDIA_INFO_LOG("UnregisterSlowMotionStateCb success");
}

void SlowMotionVideoSessionImpl::RegisterZoomInfoCbListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("RegisterZoomInfoCbListener is called");
    if (zoomInfoListener_ == nullptr) {
        CHECK_RETURN_ELOG(!slowMotionSession_, "slowMotionSession_ is nullptr");
        std::shared_ptr<SlowMotionZoomInfoListener> zoomInfoListenerTemp =
            std::static_pointer_cast<SlowMotionZoomInfoListener>(slowMotionSession_->GetZoomInfoCallback());
        if (zoomInfoListenerTemp == nullptr) {
            ani_env *env = get_env();
            zoomInfoListenerTemp = std::make_shared<SlowMotionZoomInfoListener>(env);
            slowMotionSession_->SetZoomInfoCallback(zoomInfoListenerTemp);
        }
        zoomInfoListener_ = zoomInfoListenerTemp;
    }
    zoomInfoListener_->SaveCallbackReference(eventName, callback, isOnce);
    MEDIA_INFO_LOG("RegisterZoomInfoCbListener success");
}
void SlowMotionVideoSessionImpl::UnregisterZoomInfoCbListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("UnregisterZoomInfoCbListener is called");
    CHECK_RETURN_ELOG(zoomInfoListener_ == nullptr, "zoomInfoListener_ is null");
    zoomInfoListener_->RemoveCallbackRef(eventName, callback);
}

bool SlowMotionVideoSessionImpl::IsSlowMotionDetectionSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsSlowMotionDetectionSupported is called!");
    CHECK_RETURN_RET_ELOG(slowMotionSession_ == nullptr, false, "slowMotionSession_ is null");
    return slowMotionSession_->IsSlowMotionDetectionSupported();
}

void SlowMotionVideoSessionImpl::SetSlowMotionDetectionArea(ohos::multimedia::camera::Rect const& area)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetSlowMotionDetectionArea is called!");
    CHECK_RETURN_ELOG(slowMotionSession_ == nullptr, "slowMotionSession_ is null");
    OHOS::CameraStandard::Rect rect = (OHOS::CameraStandard::Rect) {
        .topLeftX = area.topLeftX,
        .topLeftY = area.topLeftY,
        .width = area.width,
        .height = area.height };
    slowMotionSession_->SetSlowMotionDetectionArea(rect);
}
} // namespace Ani
} // namespace Camera