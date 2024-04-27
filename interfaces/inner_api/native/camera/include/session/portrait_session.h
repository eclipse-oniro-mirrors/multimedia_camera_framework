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

#ifndef OHOS_CAMERA_PORTRAIT_SESSION_H
#define OHOS_CAMERA_PORTRAIT_SESSION_H

#include <iostream>
#include <set>
#include <vector>
#include "camera_error_code.h"
#include "input/capture_input.h"
#include "output/capture_output.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
enum PortraitEffect {
    OFF_EFFECT = 0,
    CIRCLES = 1,
    HEART = 2,
    ROTATED = 3,
    STUDIO = 4,
    THEATER = 5,
};

class CaptureOutput;
class PortraitSession : public CaptureSession {
public:
    explicit PortraitSession(sptr<ICaptureSession> &PortraitSession): CaptureSession(PortraitSession) {}
    ~PortraitSession();

    /**
     * @brief Get the supported portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    std::vector<PortraitEffect> GetSupportedPortraitEffects();

    /**
     * @brief Get the portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    PortraitEffect GetPortraitEffect();

    /**
     * @brief Set the portrait effects.
     */
    void SetPortraitEffect(PortraitEffect effect);

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    bool CanAddOutput(sptr<CaptureOutput>& output) override;

    /**
     * @brief Get the supported virtual apertures.
     *
     * @return Returns the array of virtual aperture.
     */
    std::vector<float> GetSupportedVirtualApertures();

    /**
     * @brief Get the virtual aperture.
     *
     * @return Returns the current virtual aperture.
     */
    float GetVirtualAperture();

    /**
     * @brief Set the virtual aperture.
     */
    void SetVirtualAperture(const float virtualAperture);

    /**
     * @brief Get the supported physical apertures.
     *
     * @return Returns the array of physical aperture.
     */
    std::vector<std::vector<float>> GetSupportedPhysicalApertures();

    /**
     * @brief Get the physical aperture.
     *
     * @return Returns current physical aperture.
     */
    float GetPhysicalAperture();

    /**
     * @brief Set the physical aperture.
     */
    void SetPhysicalAperture(const float virtualAperture);

private:
    static const std::unordered_map<camera_portrait_effect_type_t, PortraitEffect> metaToFwPortraitEffect_;
    static const std::unordered_map<PortraitEffect, camera_portrait_effect_type_t> fwToMetaPortraitEffect_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PORTRAIT_SESSION_H
