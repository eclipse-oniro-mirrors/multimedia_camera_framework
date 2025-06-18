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

#ifndef OHOS_CAMERA_MECH_PHOTO_PROCESSOR_H
#define OHOS_CAMERA_MECH_PHOTO_PROCESSOR_H

#include <refbase.h>

#include "metadata_output.h"
#include "input/camera_death_recipient.h"

namespace OHOS {
namespace CameraStandard {
struct CameraAppInfo {
    uint32_t tokenId = 0;
    std::string cameraId = "";
    uint32_t opmode = 0;
    float zoomValue = 1.0f; // default zoom;
    uint32_t equivalentFocus = 0;
    int32_t width = 0;
    int32_t height = 0;
    bool videoStatus = false;
    int32_t position = 0;
};

class MechSessionCallback : public RefBase {
public:
    MechSessionCallback() = default;
    virtual ~MechSessionCallback() = default;
    virtual void OnFocusTrackingInfo(FocusTrackingMetaInfo info) = 0;
    virtual void OnCameraAppInfo(const std::vector<CameraAppInfo>& cameraAppInfos) = 0;
};

class MechSession : public RefBase {
public:
    MechSession();
    virtual ~MechSession();
 
    /**
     * @brief EnableMechDelivery.
     * @return Returns errCode.
     */
    int32_t EnableMechDelivery(bool isEnableMech);
 
    /**
     * @brief Set the session callback for the MechSession.
     *
     * @param callback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<MechSessionCallback> callback);
 
    /**
     * @brief Get the Callback.
     *
     * @return Returns the pointer to Callback.
     */
    std::shared_ptr<MechSessionCallback> GetCallback();
 
    /**
     * @brief Releases MechSession instance.
     * @return Returns errCode.
     */
    int32_t Release();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_MECH_PHOTO_PROCESSOR_H