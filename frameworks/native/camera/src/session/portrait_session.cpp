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
#include "camera_log.h"
#include "camera_util.h"
#include "hcapture_session_callback_stub.h"
#include "input/camera_input.h"
#include "metadata_common_utils.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"

namespace OHOS {
namespace CameraStandard {

const std::unordered_map<PortraitEffect, camera_portrait_effect_type_t> PortraitSession::fwToMetaPortraitEffect_ = {
    {OFF_EFFECT, OHOS_CAMERA_PORTRAIT_EFFECT_OFF},
    {CIRCLES, OHOS_CAMERA_PORTRAIT_CIRCLES},
    {HEART, OHOS_CAMERA_PORTRAIT_HEART},
    {ROTATED, OHOS_CAMERA_PORTRAIT_ROTATED},
    {STUDIO, OHOS_CAMERA_PORTRAIT_STUDIO},
    {THEATER, OHOS_CAMERA_PORTRAIT_THEATER},
};

PortraitSession::~PortraitSession()
{
}

std::vector<PortraitEffect> PortraitSession::GetSupportedPortraitEffects()
{
    std::vector<PortraitEffect> supportedPortraitEffects = {};
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), supportedPortraitEffects,
        "PortraitSession::GetSupportedPortraitEffects Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, supportedPortraitEffects,
        "PortraitSession::GetSupportedPortraitEffects camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, supportedPortraitEffects,
        "PortraitSession::GetSupportedPortraitEffects camera deviceInfo is null");
    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES));
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, supportedPortraitEffects,
        "PortraitSession::GetSupportedPortraitEffects abilityId is NULL");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, supportedPortraitEffects);
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &item);
    CHECK_ERROR_RETURN_RET(ret != CAM_META_SUCCESS || item.count == 0, supportedPortraitEffects);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaToFwPortraitEffect_.find(static_cast<camera_portrait_effect_type_t>(item.data.u8[i]));
        if (itr != g_metaToFwPortraitEffect_.end()) {
            supportedPortraitEffects.emplace_back(itr->second);
        }
    }
    return supportedPortraitEffects;
}

PortraitEffect PortraitSession::GetPortraitEffect()
{
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), PortraitEffect::OFF_EFFECT,
        "CaptureSession::GetPortraitEffect Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, PortraitEffect::OFF_EFFECT,
        "CaptureSession::GetPortraitEffect camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, PortraitEffect::OFF_EFFECT,
        "CaptureSession::GetPortraitEffect camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, PortraitEffect::OFF_EFFECT);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, PortraitEffect::OFF_EFFECT,
        "CaptureSession::GetPortraitEffect Failed with return code %{public}d", ret);
    auto itr = g_metaToFwPortraitEffect_.find(static_cast<camera_portrait_effect_type_t>(item.data.u8[0]));
    if (itr != g_metaToFwPortraitEffect_.end()) {
        return itr->second;
    }
    return PortraitEffect::OFF_EFFECT;
}

void PortraitSession::SetPortraitEffect(PortraitEffect portraitEffect)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_LOG(!(IsSessionCommited() || IsSessionConfiged()),
        "CaptureSession::SetPortraitEffect Session is not Commited");
    CHECK_ERROR_RETURN_LOG(changedMetadata_ == nullptr,
        "CaptureSession::SetPortraitEffect changedMetadata_ is NULL");

    std::vector<PortraitEffect> portraitEffects= GetSupportedPortraitEffects();
    auto itr = std::find(portraitEffects.begin(), portraitEffects.end(), portraitEffect);
    CHECK_ERROR_RETURN_LOG(itr == portraitEffects.end(),
        "CaptureSession::SetPortraitEffect::GetSupportedPortraitEffects abilityId is NULL");
    uint8_t effect = 0;
    auto itr2 = fwToMetaPortraitEffect_.find(portraitEffect);
    if (itr2 != fwToMetaPortraitEffect_.end()) {
        effect = static_cast<uint8_t>(itr2->second);
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetPortraitEffect Failed to set effect");
    return;
}
bool PortraitSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into PortraitSession::CanAddOutput");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionConfiged() || output == nullptr, false,
        "PortraitSession::CanAddOutput operation is Not allowed!");
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}
} // CameraStandard
} // OHOS
