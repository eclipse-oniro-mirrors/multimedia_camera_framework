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
#include "video_capability_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_security_utils_taihe.h"
#include "camera_error_code.h"

using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

namespace Ani {
namespace Camera {
VideoCapabilityImpl::VideoCapabilityImpl(sptr<OHOS::CameraStandard::VideoCapability> videoCapability)
{
    videoCapability_ = videoCapability;
}

bool VideoCapabilityImpl::IsBFrameSupported()
{
    bool isBFrameSupported = false;
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), isBFrameSupported,
        "SystemApi IsBFrameSupported is called!");
    if (videoCapability_ == nullptr) {
        MEDIA_ERR_LOG("VideoCapabilityImpl::IsBFrameSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return false;
    }
    isBFrameSupported = videoCapability_->IsBFrameSupported();
    return isBFrameSupported;
}
} // namespace Camera
} // namespace Ani
