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
#include "night_photo_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
int32_t NightPhotoSessionImpl::GetExposure()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), -1,
        "SystemApi GetExposure is called!");
    CHECK_RETURN_RET_ELOG(nightSession_ == nullptr, -1, "GetExposure failed, nightSession_ is nullptr!");
    uint32_t exposure;
    int32_t ret = nightSession_->GetExposure(exposure);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, -1,
        "%{public}s: getExposure() Failed", __FUNCTION__);
    return static_cast<int32_t>(exposure);
}

void NightPhotoSessionImpl::SetExposure(int32_t exposure)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetExposure is called!");
    CHECK_RETURN_ELOG(nightSession_ == nullptr, "SetExposure failed, nightSession_ is nullptr!");
    nightSession_->LockForControl();
    int32_t retCode = nightSession_->SetExposure(exposure);
    nightSession_->UnlockForControl();
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

array<int32_t> NightPhotoSessionImpl::GetSupportedExposureRange()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSupportedExposureRange is called!");
    CHECK_RETURN_RET_ELOG(nightSession_ == nullptr, {},
        "GetSupportedExposureRange failed, nightSession_ is nullptr!");
    std::vector<uint32_t> range;
    int32_t ret = nightSession_->GetExposureRange(range);
    CHECK_RETURN_RET_ELOG(ret != OHOS::CameraStandard::CameraErrorCode::SUCCESS, {},
        "%{public}s: GetSupportedExposureRange() Failed", __FUNCTION__);
    std::vector<int32_t> resRange;
    for (auto item : range) {
        resRange.push_back(static_cast<int32_t>(item));
    }
    return array<int32_t>(resRange);
}
} // namespace Camera
} // namespace Ani