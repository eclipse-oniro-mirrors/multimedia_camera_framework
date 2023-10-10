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
const std::unordered_map<camera_portrait_effect_type_t, PortraitEffect> PortraitSession::metaToFwPortraitEffect_ = {
    {OHOS_CAMERA_PORTRAIT_EFFECT_OFF, OFF_EFFECT},
    {OHOS_CAMERA_PORTRAIT_CIRCLES, CIRCLES},
    {OHOS_CAMERA_PORTRAIT_HEART, HEART},
    {OHOS_CAMERA_PORTRAIT_ROTATED, ROTATED},
    {OHOS_CAMERA_PORTRAIT_STUDIO, STUDIO},
    {OHOS_CAMERA_PORTRAIT_THEATOR, THEATOR},
};

const std::unordered_map<PortraitEffect, camera_portrait_effect_type_t> PortraitSession::fwToMetaPortraitEffect_ = {
    {OFF_EFFECT, OHOS_CAMERA_PORTRAIT_EFFECT_OFF},
    {CIRCLES, OHOS_CAMERA_PORTRAIT_CIRCLES},
    {HEART, OHOS_CAMERA_PORTRAIT_HEART},
    {ROTATED, OHOS_CAMERA_PORTRAIT_ROTATED},
    {STUDIO, OHOS_CAMERA_PORTRAIT_STUDIO},
    {THEATOR, OHOS_CAMERA_PORTRAIT_THEATOR},
};

PortraitSession::~PortraitSession()
{
}

std::vector<PortraitEffect> PortraitSession::GetSupportedPortraitEffects()
{
    std::vector<PortraitEffect> supportedPortraitEffects = {};
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("PortraitSession::GetSupportedPortraitEffects Session is not Commited");
        return supportedPortraitEffects;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("PortraitSession::GetSupportedPortraitEffects camera device is null");
        return supportedPortraitEffects;
    }

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES));
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("PortraitSession::GetSupportedPortraitEffects abilityId is NULL");
        return supportedPortraitEffects;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("PortraitSession::GetSupportedPortraitEffects Failed with return code %{public}d", ret);
        return supportedPortraitEffects;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwPortraitEffect_.find(static_cast<camera_portrait_effect_type_t>(item.data.u8[i]));
        if (itr != metaToFwPortraitEffect_.end()) {
            supportedPortraitEffects.emplace_back(itr->second);
        }
    }
    return supportedPortraitEffects;
}

PortraitEffect PortraitSession::GetPortraitEffect()
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetPortraitEffect Session is not Commited");
        return PortraitEffect::OFF_EFFECT;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetPortraitEffect camera device is null");
        return PortraitEffect::OFF_EFFECT;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetPortraitEffect Failed with return code %{public}d", ret);
        return PortraitEffect::OFF_EFFECT;
    }
    auto itr = metaToFwPortraitEffect_.find(static_cast<camera_portrait_effect_type_t>(item.data.u8[0]));
    if (itr != metaToFwPortraitEffect_.end()) {
        return itr->second;
    }
    return PortraitEffect::OFF_EFFECT;
}

void PortraitSession::SetPortraitEffect(PortraitEffect portraitEffect)
{
    CAMERA_SYNC_TRACE;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetPortraitEffect Session is not Commited");
        return;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetPortraitEffect changedMetadata_ is NULL");
        return;
    }

    std::vector<PortraitEffect> portraitEffects= GetSupportedPortraitEffects();
    auto itr = std::find(portraitEffects.begin(), portraitEffects.end(), portraitEffect);
    if (itr == portraitEffects.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetPortraitEffect::GetSupportedPortraitEffects abilityId is NULL");
        return;
    }
    uint8_t effect = 0;
    for (auto itr2 = fwToMetaPortraitEffect_.cbegin(); itr2 != fwToMetaPortraitEffect_.cend(); itr2++) {
        if (portraitEffect == itr2->first) {
            effect = static_cast<uint8_t>(itr2->second);
            break;
        }
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("CaptureSession::SetPortraitEffect: %{public}d", portraitEffect);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &effect, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &effect, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetPortraitEffect Failed to set effect");
    }
    return;
}
} // CameraStandard
} // OHOS
