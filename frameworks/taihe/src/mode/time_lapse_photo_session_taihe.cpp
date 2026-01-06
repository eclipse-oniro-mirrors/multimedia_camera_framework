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

#include "camera_security_utils_taihe.h"
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
        LuminationInfo luminationInfo{ optional<double>::make(static_cast<double>(info.luminationValue)) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("luminationInfoChange", 0, "Callback is OK", luminationInfo));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
        auto timePreviewType = ohos::multimedia::camera::TimeLapsePreviewType::from_value(
            static_cast<int32_t>(info.previewType));
        TryAEInfo jsTryAEInfo = {
            .isTryAEDone = info.isTryAEDone,
            .isTryAEHintNeeded = optional<bool>::make(info.isTryAEHintNeeded),
            .previewType = optional<ohos::multimedia::camera::TimeLapsePreviewType>::make(timePreviewType),
            .captureInterval = optional<int32_t>::make(info.captureInterval) };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("tryAEInfoChange", 0, "Callback is OK", jsTryAEInfo));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnTryAEInfoChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TimeLapsePhotoSessionImpl::RegisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "timeLapsePhotoSession_ is null!");
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
    CHECK_RETURN_ELOG(isoInfoCallback_ == nullptr, "isoInfoCallback is null");
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
        CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "timeLapsePhotoSession_ is null!");
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
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "timeLapsePhotoSession_ is null!");
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
    CHECK_RETURN_ELOG(exposureInfoCallback_ == nullptr, "exposureInfoCallback is null");
    exposureInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void TimeLapsePhotoSessionImpl::RegisterTryAEInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "timeLapsePhotoSession_ is null!");
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
    CHECK_RETURN_ELOG(tryAEInfoCallback_ == nullptr, "tryAEInfoCallback is null");
    tryAEInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void TimeLapsePhotoSessionImpl::SetTimeLapsePreviewType(ohos::multimedia::camera::TimeLapsePreviewType type)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetTimeLapsePreviewType is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr,
        "SetTimeLapsePreviewType failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapsePhotoSession_->SetTimeLapsePreviewType(
        static_cast<OHOS::CameraStandard::TimeLapsePreviewType>(type.get_value()));
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetTimeLapsePreviewType() Failed", __FUNCTION__);
}

void TimeLapsePhotoSessionImpl::SetTimeLapseInterval(int32_t interval)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetTimeLapseInterval is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr,
        "SetTimeLapseInterval failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapsePhotoSession_->SetTimeLapseInterval(interval);
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetTimeLapseInterval() Failed", __FUNCTION__);
}

int32_t TimeLapsePhotoSessionImpl::GetTimeLapseInterval()
{
    int32_t interval = -1;
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), interval,
        "SystemApi GetTimeLapseInterval is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, interval,
        "GetTimeLapseInterval failed, timeLapsePhotoSession_ is nullptr!");
    int32_t ret = timeLapsePhotoSession_->GetTimeLapseInterval(interval);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, interval,
        "%{public}s: GetTimeLapseInterval() Failed", __FUNCTION__);
    return interval;
}

array<int32_t> TimeLapsePhotoSessionImpl::GetSupportedTimeLapseIntervalRange()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), array<int32_t>(nullptr, 0),
        "SystemApi GetSupportedTimeLapseIntervalRange is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, array<int32_t>(nullptr, 0),
        "GetSupportedTimeLapseIntervalRange failed, timeLapsePhotoSession_ is nullptr!");
    std::vector<int32_t> range;
    int32_t retCode = timeLapsePhotoSession_->GetSupportedTimeLapseIntervalRange(range);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<int32_t>(nullptr, 0));
    return array<int32_t>(range);
}

bool TimeLapsePhotoSessionImpl::IsWhiteBalanceModeSupported(WhiteBalanceMode mode)
{
    bool isSupported = false;
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr,
        isSupported, "SetWhiteBalance captureSession_ is null");
    int32_t retCode = timeLapsePhotoSession_->IsWhiteBalanceModeSupported(
        static_cast<OHOS::CameraStandard::WhiteBalanceMode>(mode.get_value()), isSupported);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), isSupported);
    return isSupported;
}

void TimeLapsePhotoSessionImpl::SetWhiteBalanceMode(WhiteBalanceMode mode)
{
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "SetWhiteBalanceMode captureSession_ is null");
    timeLapsePhotoSession_->LockForControl();
    timeLapsePhotoSession_->SetWhiteBalanceMode(static_cast<OHOS::CameraStandard::WhiteBalanceMode>(mode.get_value()));
    timeLapsePhotoSession_->UnlockForControl();
}

WhiteBalanceMode TimeLapsePhotoSessionImpl::GetWhiteBalanceMode()
{
    WhiteBalanceMode errType = WhiteBalanceMode(static_cast<WhiteBalanceMode::key_t>(-1));
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr,
        errType, "GetWhiteBalanceMode timeLapsePhotoSession_ is null");
    OHOS::CameraStandard::WhiteBalanceMode whiteBalanceMode;
    int32_t retCode = timeLapsePhotoSession_->GetWhiteBalanceMode(whiteBalanceMode);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return WhiteBalanceMode(static_cast<WhiteBalanceMode::key_t>(whiteBalanceMode));
}

void TimeLapsePhotoSessionImpl::SetWhiteBalance(int32_t whiteBalance)
{
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "SetWhiteBalance captureSession_ is null");
    timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapsePhotoSession_->SetManualWhiteBalance(whiteBalance);
    MEDIA_INFO_LOG("TimeLapsePhotoSessionImpl::SetWhiteBalance set wbValue:%{public}d", whiteBalance);
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetWhiteBalance Failed", __FUNCTION__);
}

int32_t TimeLapsePhotoSessionImpl::GetWhiteBalance()
{
    int32_t balance = -1;
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, balance,
        "GetWhiteBalance failed, timeLapsePhotoSession_ is nullptr!");
    int32_t ret = timeLapsePhotoSession_->GetWhiteBalance(balance);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, balance,
        "%{public}s: getWhiteBalance() Failed", __FUNCTION__);
    return balance;
}

void TimeLapsePhotoSessionImpl::SetTimeLapseRecordState(ohos::multimedia::camera::TimeLapseRecordState state)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetTimeLapseRecordState is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr,
        "SetTimeLapseRecordState failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapsePhotoSession_->SetTimeLapseRecordState(
        static_cast<OHOS::CameraStandard::TimeLapseRecordState>(state.get_value()));
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetTimeLapseRecordState() Failed", __FUNCTION__);
}

void TimeLapsePhotoSessionImpl::SetIso(int32_t iso)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetIso is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "SetIso failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t retCode = timeLapsePhotoSession_->SetIso(iso);
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

int32_t TimeLapsePhotoSessionImpl::GetIso()
{
    int32_t iso = -1;
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), iso,
        "SystemApi GetIso is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, iso,
        "GetIso failed, timeLapsePhotoSession_ is nullptr!");
    int32_t ret = timeLapsePhotoSession_->GetIso(iso);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, iso,
        "%{public}s: GetIso() Failed", __FUNCTION__);
    return iso;
}

int32_t TimeLapsePhotoSessionImpl::GetExposure()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), -1,
        "SystemApi GetExposure is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, -1,
        "GetExposure failed, timeLapsePhotoSession_ is nullptr!");
    uint32_t exposure;
    int32_t ret = timeLapsePhotoSession_->GetExposure(exposure);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, -1,
        "%{public}s: getExposure() Failed", __FUNCTION__);
    return static_cast<int32_t>(exposure);
}

void TimeLapsePhotoSessionImpl::SetExposure(int32_t exposure)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetExposure is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "SetExposure failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t retCode = timeLapsePhotoSession_->SetExposure(exposure);
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

bool TimeLapsePhotoSessionImpl::IsTryAENeeded()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsTryAENeeded is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, false,
        "IsTryAENeeded failed, timeLapsePhotoSession_ is nullptr!");
    bool needed = false;
    int32_t ret = timeLapsePhotoSession_->IsTryAENeeded(needed);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: IsTryAENeeded() Failed", __FUNCTION__);
    return needed;
}

void TimeLapsePhotoSessionImpl::StartTryAE()
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi StartTryAE is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "StartTryAE failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapsePhotoSession_->StartTryAE();
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: StartTryAE() Failed", __FUNCTION__);
}

void TimeLapsePhotoSessionImpl::StopTryAE()
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi StopTryAE is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "StopTryAE failed, timeLapsePhotoSession_ is nullptr!");
    timeLapsePhotoSession_->LockForControl();
    int32_t retCode = timeLapsePhotoSession_->StopTryAE();
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

array<int32_t> TimeLapsePhotoSessionImpl::GetIsoRange()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), array<int32_t>(nullptr, 0),
        "SystemApi GetIsoRange is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, array<int32_t>(nullptr, 0),
        "GetIsoRange failed, timeLapsePhotoSession_ is nullptr!");
    std::vector<int32_t> vecIsoList;
    int32_t retCode = timeLapsePhotoSession_->GetIsoRange(vecIsoList);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<int32_t>(nullptr, 0));
    MEDIA_INFO_LOG("TimeLapsePhotoSessionImpl::GetIsoRange len = %{public}zu", vecIsoList.size());
    return array<int32_t>(vecIsoList);
}

bool TimeLapsePhotoSessionImpl::IsManualIsoSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsManualIsoSupported is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, false,
        "IsManualIsoSupported failed, timeLapsePhotoSession_ is nullptr!");
    bool supported = false;
    int32_t ret = timeLapsePhotoSession_->IsManualIsoSupported(supported);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: isManualIsoSupported() Failed", __FUNCTION__);
    return supported;
}

void TimeLapsePhotoSessionImpl::SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetExposureMeteringMode is called!");
    CHECK_RETURN_ELOG(timeLapsePhotoSession_ == nullptr, "timeLapsePhotoSession_ is nullptr");
    timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapsePhotoSession_->SetExposureMeteringMode(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()));
    timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetExposureMeteringMode() Failed", __FUNCTION__);
}

ExposureMeteringMode TimeLapsePhotoSessionImpl::GetExposureMeteringMode()
{
    ExposureMeteringMode errType = ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(-1));
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), errType,
        "SystemApi GetExposureMeteringMode is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, errType,
        "GetExposureMeteringMode timeLapsePhotoSession_ is null");
    OHOS::CameraStandard::MeteringMode mode;
    int32_t ret = timeLapsePhotoSession_->GetExposureMeteringMode(mode);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, errType,
        "%{public}s: GetExposureMeteringMode() Failed", __FUNCTION__);
    return ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(mode));
}

bool TimeLapsePhotoSessionImpl::IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode)
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsExposureMeteringModeSupported is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, false,
        "IsExposureMeteringModeSupported failed, timeLapsePhotoSession_ is nullptr!");
    bool supported = false;
    int32_t ret = timeLapsePhotoSession_->IsExposureMeteringModeSupported(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()), supported);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: IsExposureMeteringModeSupported() Failed", __FUNCTION__);
    return supported;
}

array<int32_t> TimeLapsePhotoSessionImpl::GetSupportedExposureRange()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSupportedExposureRange is called!");
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, {},
        "GetSupportedExposureRange failed, timeLapsePhotoSession_ is nullptr!");
    std::vector<uint32_t> range;
    int32_t ret = timeLapsePhotoSession_->GetSupportedExposureRange(range);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, {},
        "%{public}s: GetSupportedExposureRange() Failed", __FUNCTION__);
    std::vector<int32_t> resRange;
    for (auto item : range) {
        resRange.push_back(static_cast<int32_t>(item));
    }
    return array<int32_t>(resRange);
}

array<int32_t> TimeLapsePhotoSessionImpl::GetWhiteBalanceRange()
{
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSession_ == nullptr, {},
        "GetWhiteBalanceRange failed, timeLapsePhotoSession_ is nullptr!");
    std::vector<int32_t> range;
    int32_t ret = timeLapsePhotoSession_->GetWhiteBalanceRange(range);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, {},
        "%{public}s: getWhiteBalanceRange() Failed", __FUNCTION__);
    return array<int32_t>(range);
}
} // namespace Ani
} // namespace Camera