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
#include "camera_log.h"
#include "camera_utils_taihe.h"
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
} // namespace Camera
} // namespace Ani