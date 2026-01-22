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

} // namespace Camera
} // namespace Ani