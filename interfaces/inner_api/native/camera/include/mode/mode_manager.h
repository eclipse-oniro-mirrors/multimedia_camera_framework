/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MODE_MANAGER_H
#define OHOS_CAMERA_MODE_MANAGER_H

#include <refbase.h>
#include <iostream>
#include <vector>
#include "input/camera_input.h"
#include "input/camera_info.h"
#include "input/camera_device.h"
#include "input/camera_manager.h"
#include "hcamera_service_proxy.h"
#include "icamera_device_service.h"
#include "session/capture_session.h"
#include "session/portrait_session.h"
#include "session/scan_session.h"
#include "output/camera_output_capability.h"
#include "output/metadata_output.h"
#include "output/photo_output.h"
#include "output/video_output.h"
#include "output/preview_output.h"
#include "hcamera_listener_stub.h"
#include "input/camera_death_recipient.h"
#include "hcamera_service_callback_stub.h"
#include "camera_stream_info_parse.h"

namespace OHOS {
namespace CameraStandard {
enum CameraMode {
    NORMAL = 0,
    CAPTURE = 1,
    VIDEO = 2,
    PORTRAIT = 3,
    NIGHT = 4,
    PROFESSIONAL = 5,
    SLOW_MOTION = 6,
    SCAN = 7,
};

class ModeManager : public RefBase {
public:
    ~ModeManager();
    /**
    * @brief Get mode manager instance.
    *
    * @return Returns pointer to mode manager instance.
    */
    static sptr<ModeManager> &GetInstance();

    /**
    * @brief Get support modes.
    *
    * @return Returns array the mode of current CameraDevice.
    */
    std::vector<CameraMode> GetSupportedModes(sptr<CameraDevice>& camera);

    /**
    * @brief Create capture session.
    *
    * @return Returns pointer to capture session.
    */
    sptr<CaptureSession> CreateCaptureSession(CameraMode mode);

    /**
    * @brief Get extend output capaility of the mode of the given camera.
    *
    * @param Camera device for which extend capability need to be fetched.
    * @return Returns vector the ability of the mode of cameraDevice of available camera.
    */
    sptr<CameraOutputCapability> GetSupportedOutputCapability(sptr<CameraDevice>& camera, CameraMode mode);
    void CreateProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
        uint32_t streamIndex, ExtendInfo extendInfo);
protected:
    explicit ModeManager(sptr<ICameraService> serviceProxy) : serviceProxy_(serviceProxy) {}

private:
    ModeManager();
    void Init();
    static sptr<ModeManager> modeManager_;
    sptr<ICameraService> serviceProxy_;
    static const std::unordered_map<camera_format_t, CameraFormat> metaToFwFormat_;
    static const std::unordered_map<CameraFormat, camera_format_t> fwToMetaFormat_;
    std::vector<Profile> photoProfiles_ = {};
    std::vector<Profile> previewProfiles_ = {};
    std::vector<VideoProfile> vidProfiles_ = {};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_MODE_MANAGER_H
