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

#include "camera_log.h"
#include "camera_utils_taihe.h"
#include "camera_security_utils_taihe.h"
#include "light_painting_photo_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
array<LightPaintingType> LightPaintingPhotoSessionImpl::GetSupportedLightPaintingTypes()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<LightPaintingType>(nullptr, 0), "SystemApi GetSupportedLightPaintings is called!");
    if (lightPaintingSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to SetLightPaintingType, lightPaintingSession_ is nullptr");
        return array<LightPaintingType>(nullptr, 0);
    }
    std::vector<OHOS::CameraStandard::LightPaintingType> lightPaintingTypes;
    int32_t retCode = lightPaintingSession_->GetSupportedLightPaintings(lightPaintingTypes);
    CHECK_RETURN_RET_ELOG(!CameraUtilsTaihe::CheckError(retCode), array<LightPaintingType>(nullptr, 0),
        "GetSupportedLightPaintings fail %{public}d", retCode);
    return CameraUtilsTaihe::ToTaiheArrayEnum<LightPaintingType, OHOS::CameraStandard::LightPaintingType>(
        lightPaintingTypes);
}

void LightPaintingPhotoSessionImpl::SetLightPaintingType(LightPaintingType type)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetLightPaintingType on is called!");
    if (lightPaintingSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to SetLightPaintingType, lightPaintingSession_ is nullptr");
        return;
    }
    lightPaintingSession_->LockForControl();
    MEDIA_INFO_LOG("SetLightPainting is called native");
    int32_t retCode = lightPaintingSession_->SetLightPainting(
        static_cast<OHOS::CameraStandard::LightPaintingType>(type.get_value()));
    lightPaintingSession_->UnlockForControl();
    CHECK_RETURN_ELOG(!CameraUtilsTaihe::CheckError(retCode), "SetLightPainting fail %{public}d", retCode);
}

LightPaintingType LightPaintingPhotoSessionImpl::GetLightPaintingType()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        LightPaintingType(static_cast<LightPaintingType::key_t>(-1)), "SystemApi GetLightPaintingType is called!");
    if (lightPaintingSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to SetLightPaintingType, lightPaintingSession_ is nullptr");
        return LightPaintingType(static_cast<LightPaintingType::key_t>(-1));
    }
    OHOS::CameraStandard::LightPaintingType lightPainting;
    int32_t retCode = lightPaintingSession_->GetLightPainting(lightPainting);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode), "GetLightPainting fail %{public}d", retCode);
    return LightPaintingType(static_cast<LightPaintingType::key_t>(lightPainting));
}
} // namespace Camera
} // namespace Ani