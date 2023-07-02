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

#include "session/portrait_session.h"
#include "camera_util.h"
#include "hcapture_session_callback_stub.h"
#include "input/camera_input.h"
#include "camera_log.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"

namespace OHOS {
namespace CameraStandard {
PortraitSession::PortraitSession(sptr<ICaptureSession> &portraitSession)
{
    portraitSession_ = portraitSession;
}

PortraitSession::~PortraitSession()
{
}

std::vector<PortraitEffect> PortraitSession::getSupportedPortraitEffects()
{
    std::vector<PortraitEffect> supportedPortraitEffects(PortraitEffect::OFF_EFFECT);
    return supportedPortraitEffects;
}

PortraitEffect PortraitSession::getPortraitEffect()
{
    return PortraitEffect::OFF_EFFECT;
}

void PortraitSession::setPortraitEffect(PortraitEffect effect)
{
    return;
}
} // CameraStandard
} // OHOS
