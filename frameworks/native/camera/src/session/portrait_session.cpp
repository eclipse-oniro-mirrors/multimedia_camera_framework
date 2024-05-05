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
const std::unordered_map<camera_portrait_effect_type_t, PortraitEffect> PortraitSession::metaToFwPortraitEffect_ = {
    {OHOS_CAMERA_PORTRAIT_EFFECT_OFF, OFF_EFFECT},
    {OHOS_CAMERA_PORTRAIT_CIRCLES, CIRCLES},
    {OHOS_CAMERA_PORTRAIT_HEART, HEART},
    {OHOS_CAMERA_PORTRAIT_ROTATED, ROTATED},
    {OHOS_CAMERA_PORTRAIT_STUDIO, STUDIO},
    {OHOS_CAMERA_PORTRAIT_THEATER, THEATER},
};

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
    if (metadata == nullptr) {
        return supportedPortraitEffects;
    }
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
    if (metadata == nullptr) {
        return PortraitEffect::OFF_EFFECT;
    }
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
bool PortraitSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into PortraitSession::CanAddOutput");
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("PortraitSession::CanAddOutput operation is Not allowed!");
        return false;
    }
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}

std::vector<float> PortraitSession::GetSupportedVirtualApertures()
{
    std::vector<float> supportedVirtualApertures = {};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures Session is not Commited");
        return supportedVirtualApertures;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures camera device is null");
        return supportedVirtualApertures;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return supportedVirtualApertures;
    }
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures Failed with return code %{public}d", ret);
        return supportedVirtualApertures;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        supportedVirtualApertures.emplace_back(item.data.f[i]);
    }
    return supportedVirtualApertures;
}

float PortraitSession::GetVirtualAperture()
{
    float virtualAperture = 0.0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetVirtualAperture Session is not Commited");
        return virtualAperture;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetVirtualAperture camera device is null");
        return virtualAperture;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return virtualAperture;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetVirtualAperture Failed with return code %{public}d", ret);
        return virtualAperture;
    }
    virtualAperture = item.data.f[0];
    return virtualAperture;
}

void PortraitSession::SetVirtualAperture(const float virtualAperture)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("SetVirtualAperture Session is not Commited");
        return;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("SetVirtualAperture changedMetadata_ is NULL");
        return;
    }
    std::vector<float> supportedVirtualApertures = GetSupportedVirtualApertures();
    auto res = std::find_if(supportedVirtualApertures.begin(), supportedVirtualApertures.end(),
        [&virtualAperture](const float item) {return FloatIsEqual(virtualAperture, item);});
    if (res == supportedVirtualApertures.end()) {
        MEDIA_ERR_LOG("current virtualAperture is not supported");
        return;
    }
    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("SetVirtualAperture virtualAperture: %{public}f", virtualAperture);

    int32_t ret = Camera::FindCameraMetadataItem(changedMetadata_->get(),
        OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualAperture, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualAperture, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("SetVirtualAperture Failed to set virtualAperture");
    }
    return;
}

std::vector<std::vector<float>> PortraitSession::GetSupportedPhysicalApertures()
{
    // The data structure of the supportedPhysicalApertures object is { {zoomMin, zoomMax,
    // physicalAperture1, physicalAperture2···}, }.
    std::vector<std::vector<float>> supportedPhysicalApertures = {};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Session is not Commited");
        return supportedPhysicalApertures;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures camera device is null");
        return supportedPhysicalApertures;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return supportedPhysicalApertures;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Failed with return code %{public}d", ret);
        return supportedPhysicalApertures;
    }
    std::vector<float> chooseModeRange = ParsePhysicalApertureRangeByMode(item, GetMode());
    constexpr int32_t minPhysicalApertureMetaSize = 3;
    if (chooseModeRange.size() < minPhysicalApertureMetaSize) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Failed meta format error");
        return supportedPhysicalApertures;
    }
    int32_t deviceCntPos = 1;
    int32_t supportedDeviceCount = static_cast<int32_t>(chooseModeRange[deviceCntPos]);
    if (supportedDeviceCount == 0) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Failed meta device count is 0");
        return supportedPhysicalApertures;
    }
    std::vector<float> tempPhysicalApertures = {};
    for (uint32_t i = 2; i < chooseModeRange.size(); i++) {
        if (chooseModeRange[i] == -1) {
            supportedPhysicalApertures.emplace_back(tempPhysicalApertures);
            vector<float>().swap(tempPhysicalApertures);
            continue;
        }
        tempPhysicalApertures.emplace_back(chooseModeRange[i]);
    }
    return supportedPhysicalApertures;
}

float PortraitSession::GetPhysicalAperture()
{
    float physicalAperture = 0.0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetPhysicalAperture Session is not Commited");
        return physicalAperture;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetPhysicalAperture camera device is null");
        return physicalAperture;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return physicalAperture;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetPhysicalAperture Failed with return code %{public}d", ret);
        return physicalAperture;
    }
    physicalAperture = item.data.f[0];
    return physicalAperture;
}

void PortraitSession::SetPhysicalAperture(const float physicalAperture)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("SetPhysicalAperture Session is not Commited");
        return;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("SetPhysicalAperture changedMetadata_ is NULL");
        return;
    }
    std::vector<std::vector<float>> physicalApertures = GetSupportedPhysicalApertures();
    float currentZoomRatio = GetZoomRatio();
    int zoomMinIndex = 0;
    int zoomMaxIndex = 1;
    auto it = std::find_if(physicalApertures.begin(), physicalApertures.end(),
        [&currentZoomRatio, &zoomMinIndex, &zoomMaxIndex](const std::vector<float> physicalApertureRange) {
            return physicalApertureRange[zoomMaxIndex] > currentZoomRatio >= physicalApertureRange[zoomMinIndex];
        });
    if (it == physicalApertures.end()) {
        MEDIA_ERR_LOG("current zoomRatio not supported in physical apertures zoom ratio");
        return;
    }
    int physicalAperturesIndex = 2;
    auto res = std::find_if(std::next((*it).begin(), physicalAperturesIndex), (*it).end(),
        [&physicalAperture](const float physicalApertureTemp) {
            return FloatIsEqual(physicalAperture, physicalApertureTemp);
        });
    if (res == (*it).end()) {
        MEDIA_ERR_LOG("current physicalAperture is not supported");
        return;
    }
    uint32_t count = 1;
    bool status = false;
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(changedMetadata_->get(),
        OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalAperture, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalAperture, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("SetPhysicalAperture Failed to set physical aperture");
    }
    return;
}
} // CameraStandard
} // OHOS
