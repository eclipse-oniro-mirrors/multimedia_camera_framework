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
#include "professional_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

void ProfessionalSessionImpl::SetFocusAssist(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(professionSession_ == nullptr, "professionSession_ is nullptr");
    OHOS::CameraStandard::FocusAssistFlashMode mode =
        OHOS::CameraStandard::FocusAssistFlashMode::FOCUS_ASSIST_FLASH_MODE_OFF;
    if (enabled == true) {
        mode = OHOS::CameraStandard::FocusAssistFlashMode::FOCUS_ASSIST_FLASH_MODE_AUTO;
    }
    professionSession_->LockForControl();
    professionSession_->SetFocusAssistFlashMode(mode);
    MEDIA_DEBUG_LOG("ProfessionalSessionImpl SetFocusAssistFlashMode set focusAssistFlash %{public}d!", mode);
    professionSession_->UnlockForControl();
}

array<int32_t> ProfessionalSessionImpl::GetIsoRange()
{
    CHECK_ERROR_RETURN_RET_LOG(professionSession_ == nullptr, array<int32_t>(nullptr, 0),
        "GetIsoRange failed, professionSession_ is nullptr!");
    std::vector<int32_t> vecIsoList;
    int32_t retCode = professionSession_->GetIsoRange(vecIsoList);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<int32_t>(nullptr, 0));
    MEDIA_INFO_LOG("ProfessionalSessionImpl::GetIsoRange len = %{public}zu", vecIsoList.size());
    return array<int32_t>(vecIsoList);
}

void ProfessionalSessionImpl::SetIso(int32_t iso)
{
    CHECK_ERROR_RETURN_LOG(professionSession_ == nullptr, "SetIso failed, professionSession_ is nullptr!");
    professionSession_->LockForControl();
    int32_t retCode = professionSession_->SetISO(iso);
    professionSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

int32_t ProfessionalSessionImpl::GetIso()
{
    int32_t iso = -1;
    CHECK_ERROR_RETURN_RET_LOG(professionSession_ == nullptr, iso,
        "GetIso failed, professionSession_ is nullptr!");
    int32_t ret = professionSession_->GetISO(iso);
    CHECK_ERROR_RETURN_RET_LOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, iso,
        "%{public}s: GetIso() Failed", __FUNCTION__);
    return iso;
}

bool ProfessionalSessionImpl::IsFocusAssistSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(professionSession_ == nullptr, false,
        "IsFocusAssistSupported failed, professionSession_ is nullptr!");
    return false;
}

bool ProfessionalSessionImpl::IsManualIsoSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsManualIsoSupported is called!");
    CHECK_ERROR_RETURN_RET_LOG(professionSession_ == nullptr, false,
        "IsManualIsoSupported failed, professionSession_ is nullptr!");
    return professionSession_->IsManualIsoSupported();
}

bool ProfessionalSessionImpl::IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode)
{
    CHECK_ERROR_RETURN_RET_LOG(professionSession_ == nullptr, false,
        "IsExposureMeteringModeSupported failed, professionSession_ is nullptr!");
    bool supported = false;
    int32_t ret = professionSession_->IsMeteringModeSupported(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()), supported);
    CHECK_ERROR_RETURN_RET_LOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: IsExposureMeteringModeSupported() Failed", __FUNCTION__);
    return supported;
}

void ProfessionalSessionImpl::SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode)
{
    CHECK_ERROR_RETURN_LOG(professionSession_ == nullptr, "professionSession_ is nullptr");
    professionSession_->LockForControl();
    professionSession_->SetMeteringMode(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()));
    professionSession_->UnlockForControl();
}

ExposureMeteringMode ProfessionalSessionImpl::GetExposureMeteringMode()
{
    ExposureMeteringMode errType = ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(professionSession_ == nullptr, errType,
        "GetExposureMeteringMode timeLapsePhotoSession_ is null");
    OHOS::CameraStandard::MeteringMode mode;
    int32_t ret = professionSession_->GetMeteringMode(mode);
    CHECK_ERROR_RETURN_RET_LOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, errType,
        "%{public}s: GetExposureMeteringMode() Failed", __FUNCTION__);
    return ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(mode));
}

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
        ApertureInfo apertureInfo{  .aperture = optional<double>::make(static_cast<double>(info.apertureValue)) };
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
        LuminationInfo luminationInfo{ optional<double>::make(static_cast<double>(info.luminationValue)) };
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<LuminationInfo const&>(
            "luminationInfoChange", 0, "Callback is OK", luminationInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnLuminationInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}
} // namespace Ani
} // namespace Camera