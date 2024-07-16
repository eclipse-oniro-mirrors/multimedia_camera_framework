/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
 
 
#include "light_painting_session.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
namespace OHOS {
namespace CameraStandard {
LightPaintingSession::~LightPaintingSession()
{
    MEDIA_DEBUG_LOG("Enter Into LightPaintingSession::~LightPaintingSession()");
}
 
int32_t LightPaintingSession::GetSupportedLightPaintings(std::vector<LightPaintingType>& lightPaintings)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("LightPaintingSession::GetSupportedLightPaintings Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("LightPaintingSession::GetSupportedLightPaintings camera device is null");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LIGHT_PAINTING_TYPE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("LightPaintingSession::GetSupportedLightPaintings Failed with return code %{public}d.", ret);
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    lightPaintings.clear();
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaLightPaintingTypeMap_.find(static_cast<CameraLightPaintingType>(item.data.u8[i]));
        if (itr != metaLightPaintingTypeMap_.end()) {
            lightPaintings.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}
 
int32_t LightPaintingSession::GetLightPainting(LightPaintingType& lightPaintingType)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("LightPaintingSession::GetLightPainting Session is not Commited.");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto itr = fwkLightPaintingTypeMap_.find(currentLightPaintingType_);
    if (itr != fwkLightPaintingTypeMap_.end()) {
        lightPaintingType = itr->first;
    }
    return CameraErrorCode::SUCCESS;
}
 
int32_t LightPaintingSession::SetLightPainting(const LightPaintingType type)
{
    MEDIA_INFO_LOG("SetLightPainting native is called");
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("LightPaintingSession::SetLightPainting Session is not Commited.");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("LightPaintingSession::SetLightPainting Need to call"
            "LockForControl() before setting camera properties.");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t lightPainting = LightPaintingType::CAR;
    auto itr = fwkLightPaintingTypeMap_.find(type);
    if (itr != fwkLightPaintingTypeMap_.end()) {
        lightPainting = itr->second;
    } else {
        MEDIA_ERR_LOG("LightPaintingSession::SetLightPainting unknown type of LightPainting.");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
 
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("LightPaintingSession::SetLightPainting: %{public}d", type);
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_LIGHT_PAINTING_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_DEBUG_LOG("LightPaintingSession::SetLightPainting failed to find OHOS_CONTROL_LIGHT_PAINTING_TYPE");
        status = changedMetadata_->addEntry(OHOS_CONTROL_LIGHT_PAINTING_TYPE, &lightPainting, count);
    } else if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("LightPaintingSession::SetLightPainting success to find OHOS_CONTROL_LIGHT_PAINTING_TYPE");
        status = changedMetadata_->updateEntry(OHOS_CONTROL_LIGHT_PAINTING_TYPE, &lightPainting, count);
    }
    if (status) {
        currentLightPaintingType_ = type;
    } else {
        MEDIA_ERR_LOG("LightPaintingSession::SetLightPainting Failed to set LightPainting type");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    return CameraErrorCode::SUCCESS;
}
 
int32_t LightPaintingSession::TriggerLighting()
{
    MEDIA_INFO_LOG("TriggerLighting native is called");
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("LightPaintingSession::TriggerLighting Session is not Commited.");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("LightPaintingSession::SetLightPainting Need to call"
            "LockForControl() before setting camera properties.");
        return CameraErrorCode::SUCCESS;
    }
 
    if (currentLightPaintingType_ != LightPaintingType::LIGHT) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
 
    uint8_t enableTrigger = 1;
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("LightPaintingSession::TriggerLighting once.");
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_LIGHT_PAINTING_FLASH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_DEBUG_LOG("LightPaintingSession::TriggerLighting failed to find OHOS_CONTROL_LIGHT_PAINTING_FLASH");
        status = changedMetadata_->addEntry(OHOS_CONTROL_LIGHT_PAINTING_FLASH, &enableTrigger, count);
    } else if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("LightPaintingSession::TriggerLighting success to find OHOS_CONTROL_LIGHT_PAINTING_FLASH");
        status = changedMetadata_->updateEntry(OHOS_CONTROL_LIGHT_PAINTING_FLASH, &enableTrigger, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("LightPaintingSession::TriggerLighting Failed to trigger lighting");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    return CameraErrorCode::SUCCESS;
}
} // CameraStandard
} // OHOS