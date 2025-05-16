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

#include "time_lapse_photo_session_taihe.h"
namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

void IsoInfoCallbackListenerTime::OnIsoInfoChanged(OHOS::CameraStandard::IsoInfo info)
{
    MEDIA_DEBUG_LOG("OnIsoInfoChanged is called, info: %{public}d", info.isoValue);
    OnIsoInfoChangedCallback(info);
}

void IsoInfoCallbackListenerTime::OnIsoInfoChangedCallback(OHOS::CameraStandard::IsoInfo info) const
{
    MEDIA_DEBUG_LOG("OnIsoInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        IsoInfo isoInfo{ optional<int32_t>::make(info.isoValue) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("isoInfoChange", 0, "Callback is OK", isoInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnIsoInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void LuminationInfoCallbackListenerTime::OnLuminationInfoChanged(OHOS::CameraStandard::LuminationInfo info)
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChanged is called, luminationValue: %{public}f", info.luminationValue);
    OnLuminationInfoChangedCallback(info);
}

void LuminationInfoCallbackListenerTime::OnLuminationInfoChangedCallback(
    OHOS::CameraStandard::LuminationInfo info) const
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        LuminationInfo luminationInfo{ optional<float>::make(info.luminationValue) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("luminationInfoChange", 0, "Callback is OK", luminationInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnLuminationInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void ExposureInfoCallbackListenerTime::OnExposureInfoChanged(OHOS::CameraStandard::ExposureInfo info)
{
    MEDIA_DEBUG_LOG("OnExposureInfoChanged is called, info: %{public}d", info.exposureDurationValue);
    OnExposureInfoChangedCallback(info);
}

void ExposureInfoCallbackListenerTime::OnExposureInfoChangedCallback(OHOS::CameraStandard::ExposureInfo info) const
{
    MEDIA_DEBUG_LOG("OnExposureInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        ExposureInfo exposureInfo{ optional<int32_t>::make(info.exposureDurationValue) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("exposureInfoChange", 0, "Callback is OK", exposureInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnExposureInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TryAEInfoCallbackListener::OnTryAEInfoChanged(OHOS::CameraStandard::TryAEInfo info)
{
    MEDIA_DEBUG_LOG("OnTryAEInfoChanged is called");
    OnTryAEInfoChangedCallback(info);
}

void TryAEInfoCallbackListener::OnTryAEInfoChangedCallback(OHOS::CameraStandard::TryAEInfo info) const
{
    MEDIA_DEBUG_LOG("OnTryAEInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        auto timePreviewType = CameraUtilsTaihe::ToTaiheTimeLapsePreviewType(info.previewType);
        TryAEInfo jsTryAEInfo = {
            .isTryAEDone = info.isTryAEDone,
            .isTryAEHintNeeded = optional<bool>::make(info.isTryAEHintNeeded),
            .previewType = optional<ohos::multimedia::camera::TimeLapsePreviewType>::make(timePreviewType),
            .captureInterval = optional<int32_t>::make(info.captureInterval) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("tryAEInfoChange", 0, "Callback is OK", jsTryAEInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnTryAEInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TimeLapsePhotoSessionImpl::RegisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (isoInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        isoInfoCallback_ = std::make_shared<IsoInfoCallbackListenerTime>(env);
        timeLapsePhotoSession_->SetIsoInfoCallback(isoInfoCallback_);
    }
    isoInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionImpl::UnregisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(isoInfoCallback_ == nullptr, "isoInfoCallback is null");
    isoInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void TimeLapsePhotoSessionImpl::RegisterLuminationInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (luminationInfoCallback_ == nullptr) {
        OHOS::CameraStandard::ExposureHintMode mode = OHOS::CameraStandard::EXPOSURE_HINT_MODE_ON;
        timeLapsePhotoSession_->LockForControl();
        timeLapsePhotoSession_->SetExposureHintMode(mode);
        timeLapsePhotoSession_->UnlockForControl();
        MEDIA_INFO_LOG("TimeLapsePhotoSessionImpl SetExposureHintMode set exposureHint %{public}d!", mode);
        ani_env *env = get_env();
        luminationInfoCallback_ = std::make_shared<LuminationInfoCallbackListenerTime>(env);
        timeLapsePhotoSession_->SetLuminationInfoCallback(luminationInfoCallback_);
    }
    luminationInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionImpl::UnregisterLuminationInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (luminationInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("luminationInfoCallback is null");
    } else {
        OHOS::CameraStandard::ExposureHintMode mode = OHOS::CameraStandard::EXPOSURE_HINT_MODE_OFF;
        timeLapsePhotoSession_->LockForControl();
        timeLapsePhotoSession_->SetExposureHintMode(mode);
        timeLapsePhotoSession_->UnlockForControl();
        MEDIA_INFO_LOG("TimeLapsePhotoSessionImpl SetExposureHintMode set exposureHint %{public}d!", mode);
        luminationInfoCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void TimeLapsePhotoSessionImpl::RegisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (exposureInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        exposureInfoCallback_ = std::make_shared<ExposureInfoCallbackListenerTime>(env);
        timeLapsePhotoSession_->SetExposureInfoCallback(exposureInfoCallback_);
    }
    exposureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionImpl::UnregisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(exposureInfoCallback_ == nullptr, "exposureInfoCallback is null");
    exposureInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void TimeLapsePhotoSessionImpl::RegisterTryAEInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (tryAEInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        tryAEInfoCallback_ = std::make_shared<TryAEInfoCallbackListener>(env);
        timeLapsePhotoSession_->SetTryAEInfoCallback(tryAEInfoCallback_);
    }
    tryAEInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionImpl::UnregisterTryAEInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(tryAEInfoCallback_ == nullptr, "tryAEInfoCallback is null");
    tryAEInfoCallback_->RemoveCallbackRef(eventName, callback);
}
} // namespace Ani
} // namespace Camera