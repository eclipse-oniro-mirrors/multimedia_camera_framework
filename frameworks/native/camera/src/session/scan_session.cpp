/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
 
#include "session/scan_session.h"
#include "input/camera_input.h"
#include "mode/mode_manager.h"
#include "output/camera_output_capability.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_util.h"
 
namespace OHOS {
namespace CameraStandard {
ScanSession::~ScanSession()
{
}
 
int32_t ScanSession::AddOutput(sptr<CaptureOutput> &output)
{
    int32_t result = CAMERA_UNKNOWN_ERROR;
    if (inputDevice_) {
        sptr<CameraDevice> device = inputDevice_->GetCameraDeviceInfo();
        sptr<ModeManager> modeManager = ModeManager::GetInstance();
        sptr<CameraOutputCapability> outputCapability = nullptr;
        if (device != nullptr && modeManager != nullptr) {
            outputCapability = modeManager->GetSupportedOutputCapability(device, CameraMode::SCAN);
        } else {
            MEDIA_ERR_LOG("ScanSession::AddOutput get nullptr to device or modeManager");
            return CameraErrorCode::DEVICE_DISABLED;
        }
        if ((outputCapability != nullptr && outputCapability->GetPreviewProfiles().size() != 0 &&
            output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW)) {
            result = CaptureSession::AddOutput(output);
        } else {
            MEDIA_ERR_LOG("ScanSession::AddOutput can not add current type of output");
            return CameraErrorCode::SESSION_NOT_CONFIG;
        }
    } else {
        MEDIA_ERR_LOG("ScanSession::AddOutput get nullptr to inputDevice_");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS