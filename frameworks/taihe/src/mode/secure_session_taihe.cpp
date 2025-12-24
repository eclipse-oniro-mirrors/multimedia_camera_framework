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
#include "preview_output_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_output_taihe.h"
#include "secure_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

void SecureSessionImpl::AddSecureOutput(ohos::multimedia::camera::weak::PreviewOutput previewOutput)
{
    MEDIA_INFO_LOG("AddSecureOutput is called");
    CHECK_RETURN_ELOG(secureCameraSession_ == nullptr, "secureCameraSession_ is nullptr");
    Ani::Camera::PreviewOutputImpl* outputImpl =
        reinterpret_cast<PreviewOutputImpl*>(CameraOutput(PreviewOutput(previewOutput))->GetSpecificImplPtr());
    CHECK_RETURN_ELOG(outputImpl == nullptr, "AddSecureOutput outputImpl is null");
    sptr<OHOS::CameraStandard::PreviewOutput> previewOutputImpl = outputImpl->GetPreviewOutput();
    CHECK_RETURN_ELOG(previewOutputImpl == nullptr, "AddSecureOutput previewOutputImpl is null");
    sptr<OHOS::CameraStandard::CaptureOutput> captureOutput = previewOutputImpl;
    int32_t retCode = secureCameraSession_->AddSecureOutput(captureOutput);
    CHECK_RETURN_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "SecureSessionImpl::AddSecureOutput fail %{public}d", retCode);
}
} // namespace Camera
} // namespace Ani