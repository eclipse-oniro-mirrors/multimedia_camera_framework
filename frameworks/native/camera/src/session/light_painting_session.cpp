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
#include "metadata_common_utils.h"

namespace OHOS {
namespace CameraStandard {
LightPaintingSession::~LightPaintingSession()
{
    MEDIA_DEBUG_LOG("Enter Into LightPaintingSession::~LightPaintingSession()");
}
 
int32_t LightPaintingSession::GetSupportedLightPaintings(std::vector<LightPaintingType>& lightPaintings)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "LightPaintingSession::GetSupportedLightPaintings Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice,
        CameraErrorCode::SESSION_NOT_CONFIG,
        "LightPaintingSession::GetSupportedLightPaintings camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::SESSION_NOT_CONFIG,
        "LightPaintingSession::GetSupportedLightPaintings camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LIGHT_PAINTING_TYPE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "LightPaintingSession::GetSupportedLightPaintings Failed with return code %{public}d.", ret);
    lightPaintings.clear();
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaLightPaintingTypeMap_.find(static_cast<CameraLightPaintingType>(item.data.u8[i]));
        CHECK_EXECUTE(itr != metaLightPaintingTypeMap_.end(), lightPaintings.emplace_back(itr->second));
    }
    return CameraErrorCode::SUCCESS;
}
 
int32_t LightPaintingSession::GetLightPainting(LightPaintingType& lightPaintingType)
{
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "LightPaintingSession::GetLightPainting Session is not Commited.");
    auto itr = fwkLightPaintingTypeMap_.find(currentLightPaintingType_);
    if (itr != fwkLightPaintingTypeMap_.end()) {
        lightPaintingType = itr->first;
    }
    return CameraErrorCode::SUCCESS;
}
 
int32_t LightPaintingSession::SetLightPainting(const LightPaintingType type)
{
    MEDIA_INFO_LOG("SetLightPainting native is called");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "LightPaintingSession::SetLightPainting Session is not Commited.");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "LightPaintingSession::SetLightPainting Need to call LockForControl() before setting camera properties.");
    uint8_t lightPainting = LightPaintingType::CAR;
    auto itr = fwkLightPaintingTypeMap_.find(type);
    CHECK_ERROR_RETURN_RET_LOG(itr == fwkLightPaintingTypeMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "LightPaintingSession::SetLightPainting unknown type of LightPainting.");
    lightPainting = itr->second;
    MEDIA_DEBUG_LOG("LightPaintingSession::SetLightPainting: %{public}d", type);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LIGHT_PAINTING_TYPE, &lightPainting, 1);
    CHECK_ERROR_RETURN_RET_LOG(!status, CameraErrorCode::SERVICE_FATL_ERROR,
        "LightPaintingSession::SetLightPainting Failed to set LightPainting type");
        currentLightPaintingType_ = type;
    return CameraErrorCode::SUCCESS;
}
 
int32_t LightPaintingSession::TriggerLighting()
{
    MEDIA_INFO_LOG("TriggerLighting native is called");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "LightPaintingSession::TriggerLighting Session is not Commited.");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "LightPaintingSession::TriggerLighting Need to call LockForControl() before setting camera properties.");
    CHECK_ERROR_RETURN_RET(currentLightPaintingType_ != LightPaintingType::LIGHT, CameraErrorCode::INVALID_ARGUMENT);
    uint8_t enableTrigger = 1;
    MEDIA_DEBUG_LOG("LightPaintingSession::TriggerLighting once.");
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LIGHT_PAINTING_FLASH, &enableTrigger, 1);
    CHECK_ERROR_RETURN_RET_LOG(!status, CameraErrorCode::SERVICE_FATL_ERROR,
        "LightPaintingSession::TriggerLighting Failed to trigger lighting");
    return CameraErrorCode::SUCCESS;
}
} // CameraStandard
} // OHOS