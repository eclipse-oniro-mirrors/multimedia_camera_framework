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

std::vector<FilterType> PortraitSession::getSupportedFilters()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("PortraitSession::getSupportedFilters Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("PortraitSession::getSupportedFilters camera device is null");
        return {};
    }
    std::vector<FilterType> supportedFilters;
    return supportedFilters;
}

FilterType PortraitSession::getFilter()
{
    return FilterType::NONE;
}

void PortraitSession::setFilter(FilterType filter)
{
}

std::vector<PortraitEffect> PortraitSession::getSupportedPortraitEffects()
{
    std::vector<PortraitEffect> supportedPortraitEffects;
    return supportedPortraitEffects;
}

PortraitEffect PortraitSession::getPortraitEffect()
{
    return PortraitEffect::OFF_EFFECT;
}

void PortraitSession::setPortraitEffect(PortraitEffect effect)
{
}

std::vector<BeautyType> PortraitSession::getSupportedBeautyTypes()
{
    std::vector<BeautyType> supportedBeautyTypes;
    return supportedBeautyTypes;
}

std::vector<int32_t> PortraitSession::getSupportedBeautyRange(BeautyType type)
{
    std::vector<int32_t> supportedBeautyRange;
    return supportedBeautyRange;
}

void PortraitSession::setBeauty(BeautyType type, int value)
{
}
int32_t PortraitSession::getBeauty(BeautyType type)
{
    return 0;
}
} // CameraStandard
} // OHOS
