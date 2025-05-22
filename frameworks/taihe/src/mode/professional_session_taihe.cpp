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

#include "professional_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
void ProfessionalSessionImpl::RegisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (isoInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        isoInfoCallback_ = std::make_shared<IsoInfoCallbackListener>(env);
        professionSession_->SetIsoInfoCallback(isoInfoCallback_);
    }
    isoInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void ProfessionalSessionImpl::UnregisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(isoInfoCallback_ == nullptr, "isoInfoCallback is null");
    isoInfoCallback_->RemoveCallbackRef(eventName, callback);
}


void IsoInfoCallbackListener::OnIsoInfoChanged(OHOS::CameraStandard::IsoInfo info)
{
    MEDIA_DEBUG_LOG("OnIsoInfoChanged is called, info: %{public}d", info.isoValue);
    OnIsoInfoChangedCallback(info);
}

void IsoInfoCallbackListener::OnIsoInfoChangedCallback(OHOS::CameraStandard::IsoInfo info) const
{
    MEDIA_DEBUG_LOG("OnIsoInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        IsoInfo isoInfo{ optional<int32_t>::make(info.isoValue) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<IsoInfo const&>("isoInfoChange", 0, "Callback is OK", isoInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnIsoInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void ProfessionalSessionImpl::RegisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (exposureInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        exposureInfoCallback_ = std::make_shared<ExposureInfoCallbackListener>(env);
        professionSession_->SetExposureInfoCallback(exposureInfoCallback_);
    }
    exposureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void ProfessionalSessionImpl::UnregisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(exposureInfoCallback_ == nullptr, "exposureInfoCallback is null");
    exposureInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void ExposureInfoCallbackListener::OnExposureInfoChanged(OHOS::CameraStandard::ExposureInfo info)
{
    MEDIA_DEBUG_LOG("OnExposureInfoChanged is called, info: %{public}d", info.exposureDurationValue);
    OnExposureInfoChangedCallback(info);
}

void ExposureInfoCallbackListener::OnExposureInfoChangedCallback(OHOS::CameraStandard::ExposureInfo info) const
{
    MEDIA_DEBUG_LOG("OnExposureInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        ExposureInfo exposureInfo{ optional<int32_t>::make(info.exposureDurationValue) };
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<ExposureInfo const&>(
            "exposureInfoChange", 0, "Callback is OK", exposureInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnExposureInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void ProfessionalSessionImpl::RegisterApertureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (apertureInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        apertureInfoCallback_ = std::make_shared<ApertureInfoCallbackListener>(env);
        professionSession_->SetApertureInfoCallback(apertureInfoCallback_);
    }
    apertureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void ProfessionalSessionImpl::UnregisterApertureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(apertureInfoCallback_ == nullptr, "apertureInfoCallback is null");
    apertureInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void ApertureInfoCallbackListener::OnApertureInfoChanged(OHOS::CameraStandard::ApertureInfo info)
{
    MEDIA_DEBUG_LOG("OnApertureInfoChanged is called, apertureValue: %{public}f", info.apertureValue);
    OnApertureInfoChangedCallback(info);
}

void ApertureInfoCallbackListener::OnApertureInfoChangedCallback(OHOS::CameraStandard::ApertureInfo info) const
{
    MEDIA_DEBUG_LOG("OnApertureInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        ApertureInfo apertureInfo{  .aperture = optional<float>::make(info.apertureValue) };
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<ApertureInfo const&>(
            "apertureInfoChange", 0, "Callback is OK", apertureInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnApertureInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void ProfessionalSessionImpl::RegisterLuminationInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (luminationInfoCallback_ == nullptr) {
        OHOS::CameraStandard::ExposureHintMode mode = OHOS::CameraStandard::EXPOSURE_HINT_MODE_ON;
        professionSession_->LockForControl();
        professionSession_->SetExposureHintMode(mode);
        professionSession_->UnlockForControl();
        MEDIA_INFO_LOG("ProfessionalSessionImpl SetExposureHintMode set exposureHint %{public}d!", mode);
        ani_env *env = get_env();
        luminationInfoCallback_ = std::make_shared<LuminationInfoCallbackListener>(env);
        professionSession_->SetLuminationInfoCallback(luminationInfoCallback_);
    }
    luminationInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void ProfessionalSessionImpl::UnregisterLuminationInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (luminationInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("luminationInfoCallback is null");
    } else {
        OHOS::CameraStandard::ExposureHintMode mode = OHOS::CameraStandard::EXPOSURE_HINT_MODE_OFF;
        professionSession_->LockForControl();
        professionSession_->SetExposureHintMode(mode);
        professionSession_->UnlockForControl();
        MEDIA_INFO_LOG("ProfessionalSessionImpl SetExposureHintMode set exposureHint %{public}d!", mode);
        luminationInfoCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void LuminationInfoCallbackListener::OnLuminationInfoChanged(OHOS::CameraStandard::LuminationInfo info)
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChanged is called, luminationValue: %{public}f", info.luminationValue);
    OnLuminationInfoChangedCallback(info);
}

void LuminationInfoCallbackListener::OnLuminationInfoChangedCallback(OHOS::CameraStandard::LuminationInfo info) const
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        LuminationInfo luminationInfo{ optional<float>::make(info.luminationValue) };
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<LuminationInfo const&>(
            "luminationInfoChange", 0, "Callback is OK", luminationInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnLuminationInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}
} // namespace Ani
} // namespace Camera