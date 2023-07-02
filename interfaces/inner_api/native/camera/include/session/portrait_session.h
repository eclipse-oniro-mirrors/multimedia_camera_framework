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
};

class CaptureOutput;
class PortraitSession : public CaptureSession {
public:
    explicit PortraitSession(sptr<ICaptureSession> &PortraitSession);
    PortraitSession() {};
    ~PortraitSession();

    /**
     * @brief Get the supported portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    std::vector<PortraitEffect> getSupportedPortraitEffects();

    /**
     * @brief Get the portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    PortraitEffect getPortraitEffect();

    /**
     * @brief Set the portrait effects.
     */
    void setPortraitEffect(PortraitEffect effect);

private:
    sptr<ICaptureSession> portraitSession_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PORTRAIT_SESSION_H
