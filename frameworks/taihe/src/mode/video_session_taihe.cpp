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
#include "video_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
void VideoSessionImpl::SetQualityPrioritization(QualityPrioritization quality)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "SetQualityPrioritization is failed, videoSession_ is nullptr");
    videoSession_->LockForControl();
    int32_t retCode = videoSession_->SetQualityPrioritization(
        static_cast<OHOS::CameraStandard::QualityPrioritization>(quality.get_value()));
    videoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

void VideoSessionImpl::Preconfig(PreconfigType preconfigType, optional_view<PreconfigRatio> preconfigRatio)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "videoSession_ is nullptr");
    OHOS::CameraStandard::ProfileSizeRatio profileSizeRatio = OHOS::CameraStandard::ProfileSizeRatio::UNSPECIFIED;
    if (preconfigRatio.has_value()) {
        profileSizeRatio = static_cast<OHOS::CameraStandard::ProfileSizeRatio>(preconfigRatio.value().get_value());
    }
    int32_t retCode = videoSession_->Preconfig(
        static_cast<OHOS::CameraStandard::PreconfigType>(preconfigType.get_value()), profileSizeRatio);
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

bool VideoSessionImpl::CanPreconfig(PreconfigType preconfigType, optional_view<PreconfigRatio> preconfigRatio)
{
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, false, "videoSession_ is nullptr");
    OHOS::CameraStandard::ProfileSizeRatio profileSizeRatio = OHOS::CameraStandard::ProfileSizeRatio::UNSPECIFIED;
    if (preconfigRatio.has_value()) {
        profileSizeRatio = static_cast<OHOS::CameraStandard::ProfileSizeRatio>(preconfigRatio.value().get_value());
    }
    bool retCode = videoSession_->CanPreconfig(
        static_cast<OHOS::CameraStandard::PreconfigType>(preconfigType.get_value()), profileSizeRatio);
    return retCode;
}

array<VideoFunctions> CreateFunctionsVideoFunctionsArray(
    std::vector<sptr<OHOS::CameraStandard::CameraAbility>> functionsList)
{
    MEDIA_DEBUG_LOG("CreateFunctionsVideoFunctionsArray is called");
    CHECK_PRINT_ELOG(functionsList.empty(), "functionsList is empty");
    std::vector<VideoFunctions> functionsArray;
    for (size_t i = 0; i < functionsList.size(); i++) {
        functionsArray.push_back(make_holder<VideoFunctionsImpl, VideoFunctions>(functionsList[i]));
    }
    return array<VideoFunctions>(functionsArray);
}

array<VideoConflictFunctions> CreateFunctionsVideoConflictFunctionsArray(
    std::vector<sptr<OHOS::CameraStandard::CameraAbility>> conflictFunctionsList)
{
    MEDIA_DEBUG_LOG("CreateFunctionsVideoConflictFunctionsArray is called");
    CHECK_PRINT_ELOG(conflictFunctionsList.empty(), "conflictFunctionsList is empty");
    std::vector<VideoConflictFunctions> functionsArray;
    for (size_t i = 0; i < conflictFunctionsList.size(); i++) {
        functionsArray.push_back(
            make_holder<VideoConflictFunctionsImpl, VideoConflictFunctions>(conflictFunctionsList[i]));
    }
    return array<VideoConflictFunctions>(functionsArray);
}

array<VideoFunctions> VideoSessionImpl::GetSessionFunctions(CameraOutputCapability const& outputCapability)
{
    MEDIA_INFO_LOG("VideoSessionImpl::GetSessionFunctions is called");
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSessionFunctions is called!");
    std::vector<OHOS::CameraStandard::Profile> previewProfiles;
    std::vector<OHOS::CameraStandard::Profile> photoProfiles;
    std::vector<OHOS::CameraStandard::VideoProfile> videoProfileList;

    CameraUtilsTaihe::ToNativeCameraOutputCapability(outputCapability, previewProfiles, photoProfiles,
        videoProfileList);
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, {}, "videoSession_ is nullptr");
    auto cameraFunctionsList = videoSession_->GetSessionFunctions(previewProfiles, photoProfiles, videoProfileList);
    auto result = CreateFunctionsVideoFunctionsArray(cameraFunctionsList);
    return result;
}

array<VideoConflictFunctions> VideoSessionImpl::GetSessionConflictFunctions()
{
    MEDIA_INFO_LOG("GetSessionConflictFunctions is called");
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSessionConflictFunctions is called!");
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, {}, "videoSession_ is nullptr");
    auto conflictFunctionsList = videoSession_->GetSessionConflictFunctions();
    auto result = CreateFunctionsVideoConflictFunctionsArray(conflictFunctionsList);
    return result;
}

void VideoSessionImpl::RegisterPressureStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("VideoSessionImpl::RegisterPressureStatusCallbackListener");
    CHECK_RETURN_ELOG(!videoSession_, "videoSession_ is null, cannot register pressure status callback listener");
    if (pressureCallback_ == nullptr) {
        ani_env *env = get_env();
        pressureCallback_ = std::make_shared<PressureCallbackListener>(env);
        videoSession_->SetPressureCallback(pressureCallback_);
    }
    pressureCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionImpl::UnregisterPressureStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("VideoSessionImpl::UnregisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        MEDIA_INFO_LOG("pressureCallback is null");
        return;
    }
    pressureCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoSessionImpl::RegisterControlCenterEffectStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("VideoSessionImpl::RegisterControlCenterEffectStatusCallbackListener");
    CHECK_RETURN_ELOG(!videoSession_, "videoSession_ is null, cannot register pressure status callback listener");
    if (controlCenterEffectStatusCallback_ == nullptr) {
        ani_env *env = get_env();
        controlCenterEffectStatusCallback_ = std::make_shared<ControlCenterEffectStatusCallbackListener>(env);
        videoSession_->SetControlCenterEffectStatusCallback(controlCenterEffectStatusCallback_);
    }
    controlCenterEffectStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionImpl::UnregisterControlCenterEffectStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("VideoSessionImpl::UnregisterControlCenterEffectStatusCallbackListener");
    if (controlCenterEffectStatusCallback_ == nullptr) {
        MEDIA_INFO_LOG("controlCenterEffectStatusCallback is null");
        return;
    }
    controlCenterEffectStatusCallback_->RemoveCallbackRef(eventName, callback);
}

bool VideoSessionImpl::IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode)
{
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, false,
        "IsExposureMeteringModeSupported failed, videoSession_ is nullptr!");
    bool supported = false;
    int32_t ret = videoSession_->IsMeteringModeSupported(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()), supported);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: IsExposureMeteringModeSupported() Failed", __FUNCTION__);
    return supported;
}
 
array<PhysicalAperture> VideoSessionImpl::GetSupportedPhysicalApertures()
{
    std::vector<std::vector<float>> physicalApertures = {};
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, array<PhysicalAperture>(nullptr, 0),
        "GetSupportedPhysicalApertures videoSession_ is null");
    int32_t retCode = videoSession_->GetSupportedPhysicalApertures(physicalApertures);
    MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<PhysicalAperture>(nullptr, 0));
    return CameraUtilsTaihe::ToTaiheArrayPhysicalAperture(physicalApertures);
}
 
void VideoSessionImpl::SetPhysicalAperture(double aperture)
{
    MEDIA_DEBUG_LOG("SetPhysicalAperture is called");
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "SetPhysicalAperture videoSession_ is null");
    videoSession_->LockForControl();
    int32_t retCode = videoSession_->SetPhysicalAperture(static_cast<float>(aperture));
    MEDIA_INFO_LOG(
        "SetPhysicalAperture set physicalAperture %{public}f!", OHOS::CameraStandard::ConfusingNumber(aperture));
    videoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}
 
double VideoSessionImpl::GetPhysicalAperture()
{
    float physicalAperture = -1.0;
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
    CHECK_RETURN_RET_ELOG(
        videoSession_ == nullptr, physicalAperture, "GetPhysicalAperture captureSessionForSys_ is null");
    int32_t retCode = videoSession_->GetPhysicalAperture(physicalAperture);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), physicalAperture);
    return static_cast<double>(physicalAperture);
}
 
array<double> VideoSessionImpl::GetRAWCaptureZoomRatioRange()
{
    std::vector<float> vecZoomRatioList;
    int32_t retCode = videoSession_->GetRAWZoomRatioRange(vecZoomRatioList);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<double>(nullptr, 0));
    MEDIA_INFO_LOG("VideoSessionImpl::GetRAWCaptureZoomRatioRange len = %{public}zu", vecZoomRatioList.size());
    if (!vecZoomRatioList.empty()) {
        std::vector<double> doubleVec(vecZoomRatioList.begin(), vecZoomRatioList.end());
        return array<double>(doubleVec);
    }
    return array<double>(nullptr, 0);
}

array<int32_t> VideoSessionImpl::GetSupportedIsoRange()
{
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, array<int32_t>(nullptr, 0),
        "GetIsoRange failed, videoSession_ is nullptr!");
    std::vector<int32_t> vecIsoList;
    int32_t retCode = videoSession_->GetSensorSensitivityRange(vecIsoList);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<int32_t>(nullptr, 0));
    MEDIA_INFO_LOG("VideoSessionImpl::GetSupportedIsoRange len = %{public}zu", vecIsoList.size());
    return array<int32_t>(vecIsoList);
}
 
void VideoSessionImpl::SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "videoSession_ is nullptr");
    videoSession_->LockForControl();
    videoSession_->SetExposureMeteringMode(
        static_cast<OHOS::CameraStandard::MeteringMode>(aeMeteringMode.get_value()));
    videoSession_->UnlockForControl();
}
 
ExposureMeteringMode VideoSessionImpl::GetExposureMeteringMode()
{
    ExposureMeteringMode errType = ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(-1));
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, errType,
        "GetExposureMeteringMode videoSession_ is null");
    OHOS::CameraStandard::MeteringMode mode;
    int32_t ret = videoSession_->GetMeteringMode(mode);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, errType,
        "%{public}s: GetExposureMeteringMode() Failed", __FUNCTION__);
    return ExposureMeteringMode(static_cast<ExposureMeteringMode::key_t>(mode));
}
 
void VideoSessionImpl::SetIso(int32_t iso)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "SetIso failed, videoSession_ is nullptr!");
    videoSession_->LockForControl();
    int32_t retCode = videoSession_->SetISO(iso);
    videoSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}
 
int32_t VideoSessionImpl::GetIso()
{
    int32_t iso = 0;
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, iso,
        "GetIso failed, videoSession_ is nullptr!");
    int32_t retCode = videoSession_->GetISO(iso);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS, iso,
        "%{public}s: GetIso() Failed", __FUNCTION__);
    return iso;
}
 
double VideoSessionImpl::GetFocusDistance()
{
    float distance = 0.0f;
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, distance, "GetFocusDistance failed, videoSession is nullptr!");
    int32_t retCode = videoSession_->GetFocusDistance(distance);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), distance);
    return static_cast<double>(distance);
}
 
void VideoSessionImpl::SetFocusDistance(double distance)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "SetFocusDistance failed, videoSession is nullptr!");
    videoSession_->LockForControl();
    videoSession_->SetFocusDistance(static_cast<float>(distance));
    videoSession_->UnlockForControl();
}
 
bool VideoSessionImpl::IsFocusDistanceSupported()
{
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, false, "IsFocusDistanceSupported failed, videoSession is nullptr!");
    bool isSupported = false;
    int32_t retCode = videoSession_->IsFocusDistanceSupported(isSupported);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS, false,
        "%{public}s: IsFocusDistanceSupported() Failed", __FUNCTION__);
    return isSupported;
}
 
int32_t VideoSessionImpl::GetExposureDuration()
{
    uint32_t exposureDurationValue = 0;
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr, exposureDurationValue,
        "GetExposureDuration failed, videoSession is nullptr!");
    int32_t retCode = videoSession_->GetSensorExposureTime(exposureDurationValue);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        exposureDurationValue,
        "%{public}s: GetExposureDuration() Failed",
        __FUNCTION__);
    return exposureDurationValue;
}
 
array<int32_t> VideoSessionImpl::GetSupportedExposureDurationRange()
{
    CHECK_RETURN_RET_ELOG(videoSession_ == nullptr,
        array<int32_t>(nullptr, 0),
        "GetSupportedExposureDurationRange failed, videoSession is nullptr!");
    std::vector<uint32_t> vecExposureList;
    int32_t retCode = videoSession_->GetSensorExposureTimeRange(vecExposureList);
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
 
double VideoSessionImpl::GetExposureBiasStep()
{
    float exposureBiasStep = 0.0f;
    CHECK_RETURN_RET_ELOG(
        videoSession_ == nullptr, exposureBiasStep, "GetExposureBiasStep failed, videoSession is nullptr!");
    int32_t retCode = videoSession_->GetExposureBiasStep(exposureBiasStep);
    CHECK_RETURN_RET_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS, exposureBiasStep,
        "%{public}s: GetExposureBiasStep() Failed", __FUNCTION__);
    return static_cast<double>(exposureBiasStep);
}
 
void VideoSessionImpl::SetExposureDuration(int32_t exposureDurationValue)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "SetExposureDuration failed, videoSession is nullptr!");
    videoSession_->LockForControl();
    MEDIA_DEBUG_LOG("SetExposureDuration exposureDuration:%{public}d", exposureDurationValue);
    int32_t retCode = videoSession_->SetSensorExposureTime(exposureDurationValue);
    videoSession_->UnlockForControl();
    CHECK_RETURN_ELOG(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        "%{public}s: SetExposureDuration() Failed", __FUNCTION__);
}

void VideoSessionImpl::RegisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "videoSession_ is null!");
    if (exposureInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        exposureInfoCallback_ = std::make_shared<ExposureInfoCallbackListener>(env, false);
        videoSession_->SetExposureInfoCallback(exposureInfoCallback_);
    }
    exposureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}
 
void VideoSessionImpl::UnregisterExposureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(exposureInfoCallback_ == nullptr, "exposureInfoCallback is null");
    exposureInfoCallback_->RemoveCallbackRef(eventName, callback);
}
 
void VideoSessionImpl::RegisterFlashStateCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "videoSession_ is null!");
    if (flashStateCallback_ == nullptr) {
        ani_env *env = get_env();
        flashStateCallback_ = std::make_shared<FlashStateCallbackListener>(env);
        videoSession_->SetFlashStateCallback(flashStateCallback_);
    }
    flashStateCallback_->SaveCallbackReference(eventName, callback, isOnce);
}
 
void VideoSessionImpl::UnregisterFlashStateCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(flashStateCallback_ == nullptr, "flashStateCallback is null");
    flashStateCallback_->RemoveCallbackRef(eventName, callback);
}
 
void VideoSessionImpl::RegisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "videoSession_ is null!");
    if (isoInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        isoInfoCallback_ = std::make_shared<IsoInfoSyncCallbackListener>(env);
        videoSession_->SetIsoInfoCallback(isoInfoCallback_);
    }
    isoInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}
 
void VideoSessionImpl::UnregisterIsoInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(isoInfoCallback_ == nullptr, "isoInfoCallback is null");
    isoInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoSessionImpl::RegisterApertureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoSession_ == nullptr, "videoSession_ is null!");
    if (apertureInfoCallback_ == nullptr) {
        ani_env *env = get_env();
        apertureInfoCallback_ = std::make_shared<ApertureInfoCallbackListener>(env);
        videoSession_->SetApertureInfoCallback(apertureInfoCallback_);
    }
    apertureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionImpl::UnregisterApertureInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(apertureInfoCallback_ == nullptr, "apertureInfoCallback is null");
    apertureInfoCallback_->RemoveCallbackRef(eventName, callback);
}
} // namespace Camera
} // namespace Ani