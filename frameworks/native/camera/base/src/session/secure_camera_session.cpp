/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "session/secure_camera_session.h"
#include "istream_repeat.h"
#include "camera_log.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
SecureCameraSession::~SecureCameraSession()
{
}
int32_t SecureCameraSession::AddSecureOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter Into SecureCameraSession::AddSecureOutput");
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged() || output == nullptr || isSetSecureOutput_,
        CAMERA_OPERATION_NOT_ALLOWED, "SecureCameraSession::CanAddOutput operation is not allowed!");
    sptr<IStreamCommon> stream = output->GetStream();
    IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    repeatStream->EnableSecure(true);
    isSetSecureOutput_ = true;
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
