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

#include "camera_ability_taihe.h"
#include "photo_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

void PhotoSessionImpl::Preconfig(PreconfigType preconfigType, optional_view<PreconfigRatio> preconfigRatio)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "photoSession_ is nullptr");
    OHOS::CameraStandard::ProfileSizeRatio profileSizeRatio = OHOS::CameraStandard::ProfileSizeRatio::UNSPECIFIED;
    if (preconfigRatio.has_value()) {
        profileSizeRatio = static_cast<OHOS::CameraStandard::ProfileSizeRatio>(preconfigRatio.value().get_value());
    }
    int32_t retCode = photoSession_->Preconfig(
        static_cast<OHOS::CameraStandard::PreconfigType>(preconfigType.get_value()), profileSizeRatio);
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

bool PhotoSessionImpl::CanPreconfig(PreconfigType preconfigType, optional_view<PreconfigRatio> preconfigRatio)
{
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, false, "photoSession_ is nullptr");
    OHOS::CameraStandard::ProfileSizeRatio profileSizeRatio = OHOS::CameraStandard::ProfileSizeRatio::UNSPECIFIED;
    if (preconfigRatio.has_value()) {
        profileSizeRatio = static_cast<OHOS::CameraStandard::ProfileSizeRatio>(preconfigRatio.value().get_value());
    }
    bool retCode = photoSession_->CanPreconfig(
        static_cast<OHOS::CameraStandard::PreconfigType>(preconfigType.get_value()), profileSizeRatio);
    return retCode;
}

bool PhotoSessionImpl::IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode)
{
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, false,
        "IsExposureMeteringModeSupported failed, photoSession_ is nullptr!");
    bool supported = false;
    int32_t ret = photoSession_->IsMeteringModeSupported(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()), supported);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: IsExposureMeteringModeSupported() Failed", __FUNCTION__);
    return supported;
}

array<PhotoFunctions> CreateFunctionsPhotoFunctionsArray(
    std::vector<sptr<OHOS::CameraStandard::CameraAbility>> functionsList)
{
    MEDIA_DEBUG_LOG("CreateFunctionsPhotoFunctionsArray is called");
    CHECK_PRINT_ELOG(functionsList.empty(), "functionsList is empty");
    std::vector<PhotoFunctions> functionsArray;
    for (size_t i = 0; i < functionsList.size(); i++) {
        functionsArray.push_back(make_holder<PhotoFunctionsImpl, PhotoFunctions>(functionsList[i]));
    }
    return array<PhotoFunctions>(functionsArray);
}

array<PhotoConflictFunctions> CreateFunctionsPhotoConflictFunctionsArray(
    std::vector<sptr<OHOS::CameraStandard::CameraAbility>> conflictFunctionsList)
{
    MEDIA_DEBUG_LOG("CreateFunctionsPhotoConflictFunctionsArray is called");
    CHECK_PRINT_ELOG(conflictFunctionsList.empty(), "conflictFunctionsList is empty");
    std::vector<PhotoConflictFunctions> functionsArray;
    for (size_t i = 0; i < conflictFunctionsList.size(); i++) {
        functionsArray.push_back(
            make_holder<PhotoConflictFunctionsImpl, PhotoConflictFunctions>(conflictFunctionsList[i]));
    }
    return array<PhotoConflictFunctions>(functionsArray);
}

taihe::array<PhotoFunctions> PhotoSessionImpl::GetSessionFunctions(CameraOutputCapability const& outputCapability)
{
    MEDIA_INFO_LOG("PhotoSessionImpl::GetSessionFunctions is called");
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSessionFunctions is called!");
    std::vector<OHOS::CameraStandard::Profile> previewProfiles;
    std::vector<OHOS::CameraStandard::Profile> photoProfiles;
    std::vector<OHOS::CameraStandard::VideoProfile> videoProfiles;

    CameraUtilsTaihe::ToNativeCameraOutputCapability(outputCapability, previewProfiles, photoProfiles, videoProfiles);
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, {}, "photoSession_ is nullptr");
    auto cameraFunctionsList = photoSession_->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles);
    auto result = CreateFunctionsPhotoFunctionsArray(cameraFunctionsList);
    return result;
}

array<int32_t> PhotoSessionImpl::GetSupportedISORange()
{
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, array<int32_t>(nullptr, 0),
        "GetIsoRange failed, photoSession_ is nullptr!");
    std::vector<int32_t> vecIsoList;
    int32_t retCode = photoSession_->GetSensorSensitivityRange(vecIsoList);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<int32_t>(nullptr, 0));
    MEDIA_INFO_LOG("PhotoSessionImpl::getSupportedISORange len = %{public}zu", vecIsoList.size());
    return array<int32_t>(vecIsoList);
}

void PhotoSessionImpl::SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "photoSession_ is nullptr");
    photoSession_->LockForControl();
    photoSession_->SetExposureMeteringMode(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()));
    photoSession_->UnlockForControl();
}

ExposureMeteringMode PhotoSessionImpl::GetExposureMeteringMode()
{
    ExposureMeteringMode errType = ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(-1));
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, errType,
        "GetExposureMeteringMode photoSession_ is null");
    OHOS::CameraStandard::MeteringMode mode;
    int32_t ret = photoSession_->GetMeteringMode(mode);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, errType,
        "%{public}s: GetExposureMeteringMode() Failed", __FUNCTION__);
    return ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(mode));
}

void PhotoSessionImpl::SetIso(int32_t iso)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "SetIso failed, photoSession_ is nullptr!");
    photoSession_->LockForControl();
    int32_t retCode = photoSession_->SetISO(iso);
    photoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

int32_t PhotoSessionImpl::GetIso()
{
    int32_t iso = 0;
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, iso,
        "GetIso failed, photoSession_ is nullptr!");
    int32_t retCode = photoSession_->GetISO(iso);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS, iso,
        "%{public}s: GetIso() Failed", __FUNCTION__);
    return iso;
}

double PhotoSessionImpl::GetFocusDistance()
{
    float distance = 0.0f;
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, distance, "GetFocusDistance failed, photoSession is nullptr!");
    int32_t retCode = photoSession_->GetFocusDistance(distance);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), distance);
    return static_cast<double>(distance);
}

void PhotoSessionImpl::SetFocusDistance(double distance)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "SetFocusDistance failed, photoSession is nullptr!");
    photoSession_->LockForControl();
    photoSession_->SetFocusDistance(static_cast<float>(distance));
    photoSession_->UnlockForControl();
}

bool PhotoSessionImpl::IsManualFocusSupported()
{
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, false,"IsManualFocusSupported failed, photoSession is nullptr!");
    bool isSupported = false;
    OHOS::CameraStandard::FocusMode focusMode =
        static_cast<OHOS::CameraStandard::FocusMode>(FocusMode::key_t::FOCUS_MODE_MANUAL);
    int32_t retCode = photoSession_->IsFocusModeSupported(focusMode, isSupported);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        false,
        "%{public}s: IsManualFocusSupported() Failed",
        __FUNCTION__);
    return isSupported;
}

int32_t PhotoSessionImpl::GetExposureDuration()
{
    uint32_t exposureDurationValue = 0;
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, exposureDurationValue,
        "GetExposureDuration failed, photoSession is nullptr!");
    int32_t retCode = photoSession_->GetSensorExposureTime(exposureDurationValue);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        exposureDurationValue,
        "%{public}s: GetExposureDuration() Failed",
        __FUNCTION__);
    return exposureDurationValue;
}

array<int32_t> PhotoSessionImpl::GetSupportedExposureDurationRange()
{
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr,
        array<int32_t>(nullptr, 0),
        "GetSupportedExposureDurationRange failed, photoSession is nullptr!");
    std::vector<uint32_t> vecExposureList;
    int32_t retCode = photoSession_->GetSensorExposureTimeRange(vecExposureList);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS || vecExposureList.empty(),
        array<int32_t>(nullptr, 0),
        "%{public}s: GetSupportedExposureDurationRange() Failed",
        __FUNCTION__);
    std::vector<int32_t> resRange;
    for (auto item : vecExposureList) {
        resRange.push_back(static_cast<int32_t>(item));
    }
    return array<int32_t>(resRange);
}

double PhotoSessionImpl::GetExposureBiasStep()
{
    float exposureBiasStep = 0.0f;
    CHECK_RETURN_RET_ELOG(
        photoSession_ == nullptr, exposureBiasStep, "GetExposureBiasStep failed, photoSession is nullptr!");
    int32_t retCode = photoSession_->GetExposureBiasStep(exposureBiasStep);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS, exposureBiasStep,
        "%{public}s: GetExposureBiasStep() Failed", __FUNCTION__);
    return static_cast<double>(exposureBiasStep);
}

void PhotoSessionImpl::SetExposureDuration(int32_t exposureDurationValue)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "SetExposureDuration failed, photoSession is nullptr!");
    photoSession_->LockForControl();
    MEDIA_DEBUG_LOG("SetExposureDuration exposureDuration:%{public}d", exposureDurationValue);
    int32_t retCode = photoSession_->SetSensorExposureTime(exposureDurationValue);
    photoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetExposureDuration() Failed", __FUNCTION__);
}


taihe::array<PhotoConflictFunctions> PhotoSessionImpl::GetSessionConflictFunctions()
{
    MEDIA_INFO_LOG("GetSessionConflictFunctions is called");
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSessionConflictFunctions is called!");
    CHECK_RETURN_RET_ELOG(photoSession_ == nullptr, {}, "photoSession_ is nullptr");
    auto conflictFunctionsList = photoSession_->GetSessionConflictFunctions();
    auto result = CreateFunctionsPhotoConflictFunctionsArray(conflictFunctionsList);
    return result;
}

void PhotoSessionImpl::RegisterPressureStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoSessionImpl::RegisterPressureStatusCallbackListener");
    CHECK_RETURN_ELOG(!photoSession_, "photoSession_ is null, cannot register pressure status callback listener");
    if (pressureCallback_ == nullptr) {
        ani_env *env = get_env();
        pressureCallback_ = std::make_shared<PressureCallbackListener>(env);
        photoSession_->SetPressureCallback(pressureCallback_);
    }
    pressureCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoSessionImpl::UnregisterPressureStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("PhotoSessionImpl::UnregisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        MEDIA_INFO_LOG("pressureCallback is null");
        return;
    }
    pressureCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoSessionImpl::RegisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "photoSession_ is null!");
    if (exposureInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        exposureInfoCallback_ = std::make_shared<ExposureInfoCallbackListener>(env, false);
        photoSession_->SetExposureInfoCallback(exposureInfoCallback_);
    }
    exposureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoSessionImpl::UnregisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(exposureInfoCallback_ == nullptr, "exposureInfoCallback is null");
    exposureInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoSessionImpl::RegisterFlashStateCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoSession_ == nullptr, "photoSession_ is null!");
    if (flashStateCallback_ == nullptr) {
        ani_env *env = get_env();
        flashStateCallback_ = std::make_shared<FlashStateCallbackListener>(env);
        photoSession_->SetFlashStateCallback(flashStateCallback_);
    }
    flashStateCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoSessionImpl::UnregisterFlashStateCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(flashStateCallback_ == nullptr, "flashStateCallback is null");
    flashStateCallback_->RemoveCallbackRef(eventName, callback);
}
} // namespace Camera
} // namespace Ani