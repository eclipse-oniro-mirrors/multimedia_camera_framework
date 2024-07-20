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

#include "session/aperture_video_session.h"

#include <cstddef>
#include <cstdint>

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "capture_session.h"
#include "metadata_common_utils.h"

namespace OHOS {
namespace CameraStandard {
ApertureVideoSession::ApertureVideoSession(sptr<ICaptureSession>& captureSession) : CaptureSession(captureSession) {}

bool ApertureVideoSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    MEDIA_DEBUG_LOG("Enter Into ApertureVideoSession::CanAddOutput");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionConfiged() || output == nullptr, false,
        "ApertureVideoSession::CanAddOutput operation is not allowed!");
    CHECK_ERROR_RETURN_RET_LOG(output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO, false,
        "ApertureVideoSession::CanAddOutput add photo output is not allowed!");
    return CaptureSession::CanAddOutput(output);
}

int32_t ApertureVideoSession::CommitConfig()
{
    int32_t ret = CaptureSession::CommitConfig();
    CHECK_ERROR_RETURN_RET(ret != CameraErrorCode::SUCCESS, ret);

    auto ability = GetMetadata();
    auto item = GetMetadataItem(ability->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES);
    // Not support stabilization, return success.
    CHECK_ERROR_RETURN_RET(item == nullptr || item->count == 0, CameraErrorCode::SUCCESS);
    bool isSupportAuto = false;
    for (uint32_t i = 0; i < item->count; i++) {
        if (static_cast<camera_video_stabilization_mode>(item->data.u8[i]) == OHOS_CAMERA_VIDEO_STABILIZATION_AUTO) {
            isSupportAuto = true;
        }
    }
    // Not support OHOS_CONTROL_VIDEO_STABILIZATION_MODE, return success.
    CHECK_ERROR_RETURN_RET(!isSupportAuto, CameraErrorCode::SUCCESS);

    bool updateStabilizationAutoResult = false;
    LockForControl();
    uint8_t autoStabilization = OHOS_CAMERA_VIDEO_STABILIZATION_AUTO;
    updateStabilizationAutoResult =
        AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &autoStabilization, 1);
    UnlockForControl();
    CHECK_ERROR_RETURN_RET(updateStabilizationAutoResult, CameraErrorCode::SUCCESS);
    MEDIA_ERR_LOG("ApertureVideoSession::CommitConfig add STABILIZATION fail");
    return CameraErrorCode::SERVICE_FATL_ERROR;
}
} // namespace CameraStandard
} // namespace OHOS