/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "camera_device_utils.h"

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraDeviceUtils {
constexpr int32_t CAPTURE_ROTATION_BASE = 360;
constexpr int32_t ROTATION_45 = 45;
constexpr int32_t ROTATION_0 = 0;
constexpr int32_t ROTATION_90 = 90;
constexpr int32_t ROTATION_180 = 180;

int32_t CalculateImageRotation(sptr<CaptureInput> inputDevice, int32_t imageRotation, bool isMirror)
{
    auto cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, imageRotation, "CalculateImageRotation error!, cameraObj is nullptr");
    auto cameraPosition = cameraObj->GetPosition();
    CHECK_RETURN_RET_ELOG(cameraPosition == CAMERA_POSITION_UNSPECIFIED, imageRotation,
        "CalculateImageRotation error!, cameraPosition is unspecified");
    auto sensorOrientation = static_cast<int32_t>(cameraObj->GetCameraOrientation());
    imageRotation = (imageRotation + ROTATION_45) / ROTATION_90 * ROTATION_90;
    int result = imageRotation;
    if (cameraPosition == CAMERA_POSITION_BACK) {
        result = ((imageRotation + sensorOrientation) % CAPTURE_ROTATION_BASE);
    } else if (cameraPosition == CAMERA_POSITION_FRONT || cameraPosition == CAMERA_POSITION_FOLD_INNER) {
        result = ((sensorOrientation - imageRotation + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE);
    }
    if (isMirror && result != ROTATION_0 && result != ROTATION_180) {
        result = ((result + ROTATION_180) % CAPTURE_ROTATION_BASE);
    }

    MEDIA_INFO_LOG("CalculateImageRotation :result %{public}d, sensorOrientation:%{public}d, "
                   "isMirrorEnabled%{public}d",
        result, sensorOrientation, isMirror);
    return result;
}
} // namespace CameraDeviceUtils
} // namespace CameraStandard
} // namespace OHOS
