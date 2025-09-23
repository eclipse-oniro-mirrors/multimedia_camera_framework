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
#include "portrait_photo_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

array<PortraitPhotoFunctions> CreateFunctionsPortraitPhotoFunctionsArray(
    std::vector<sptr<OHOS::CameraStandard::CameraAbility>> functionsList)
{
    MEDIA_DEBUG_LOG("CreateFunctionsJSArray is called");
    CHECK_PRINT_ELOG(functionsList.empty(), "functionsList is empty");
    std::vector<PortraitPhotoFunctions> functionsArray;
    for (size_t i = 0; i < functionsList.size(); i++) {
        functionsArray.push_back(make_holder<PortraitPhotoFunctionsImpl, PortraitPhotoFunctions>(functionsList[i]));
    }
    return array<PortraitPhotoFunctions>(functionsArray);
}

array<PortraitPhotoConflictFunctions> CreateFunctionsPortraitPhotoConflictFunctionsArray(
    std::vector<sptr<OHOS::CameraStandard::CameraAbility>> conflictFunctionsList)
{
    MEDIA_DEBUG_LOG("CreateFunctionsJSArray is called");
    CHECK_PRINT_ELOG(conflictFunctionsList.empty(), "conflictFunctionsList is empty");
    std::vector<PortraitPhotoConflictFunctions> functionsArray;
    for (size_t i = 0; i < conflictFunctionsList.size(); i++) {
        functionsArray.push_back(
            make_holder<PortraitPhotoConflictFunctionsImpl, PortraitPhotoConflictFunctions>(conflictFunctionsList[i]));
    }
    return array<PortraitPhotoConflictFunctions>(functionsArray);
}

array<PortraitPhotoFunctions> PortraitPhotoSessionImpl::GetSessionFunctions(
    CameraOutputCapability const& outputCapability)
{
    MEDIA_INFO_LOG("PortraitPhotoSessionImpl::GetSessionFunctions is called");
    std::vector<OHOS::CameraStandard::Profile> previewProfiles;
    std::vector<OHOS::CameraStandard::Profile> photoProfiles;
    std::vector<OHOS::CameraStandard::VideoProfile> videoProfiles;

    CameraUtilsTaihe::ToNativeCameraOutputCapability(outputCapability, previewProfiles, photoProfiles, videoProfiles);
    CHECK_RETURN_RET_ELOG(portraitSession_ == nullptr, {}, "portraitSession_ is nullptr");
    auto cameraFunctionsList = portraitSession_->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles);
    auto result = CreateFunctionsPortraitPhotoFunctionsArray(cameraFunctionsList);
    return result;
}

array<PortraitPhotoConflictFunctions> PortraitPhotoSessionImpl::GetSessionConflictFunctions()
{
    MEDIA_INFO_LOG("GetSessionConflictFunctions is called");
    CHECK_RETURN_RET_ELOG(portraitSession_ == nullptr, {}, "portraitSession_ is nullptr");
    auto conflictFunctionsList = portraitSession_->GetSessionConflictFunctions();
    auto result = CreateFunctionsPortraitPhotoConflictFunctionsArray(conflictFunctionsList);
    return result;
}

array<PortraitEffect> PortraitPhotoSessionImpl::GetSupportedPortraitEffects()
{
    CHECK_RETURN_RET_ELOG(portraitSession_ == nullptr, array<PortraitEffect>(nullptr, 0),
        "GetSupportedPortraitEffects portraitSession_ is null");
    std::vector<OHOS::CameraStandard::PortraitEffect> PortraitEffects = portraitSession_->GetSupportedPortraitEffects();
    return CameraUtilsTaihe::ToTaiheArrayEnum<PortraitEffect, OHOS::CameraStandard::PortraitEffect>(PortraitEffects);
}

void PortraitPhotoSessionImpl::SetPortraitEffect(PortraitEffect effect)
{
    MEDIA_DEBUG_LOG("SetPortraitEffect is called");
    CHECK_RETURN_ELOG(portraitSession_ == nullptr, "SetPortraitEffect portraitSession_ is null");
    portraitSession_->LockForControl();
    portraitSession_->SetPortraitEffect(static_cast<OHOS::CameraStandard::PortraitEffect>(effect.get_value()));
    portraitSession_->UnlockForControl();
}

PortraitEffect PortraitPhotoSessionImpl::GetPortraitEffect()
{
    MEDIA_DEBUG_LOG("GetPortraitEffect is called");
    PortraitEffect errType = PortraitEffect(static_cast<PortraitEffect::key_t>(-1));
    CHECK_RETURN_RET_ELOG(portraitSession_ == nullptr, errType, "GetPortraitEffect portraitSession_ is null");
    OHOS::CameraStandard::PortraitEffect portaitEffect = portraitSession_->GetPortraitEffect();
    return PortraitEffect(static_cast<PortraitEffect::key_t>(portaitEffect));
}
} // namespace Camera
} // namespace Ani