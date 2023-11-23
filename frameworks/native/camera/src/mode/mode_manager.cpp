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

#include "mode/mode_manager.h"


#include "camera_util.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "camera_log.h"
#include "system_ability_definition.h"
#include "camera_error_code.h"
#include "icamera_util.h"
#include "device_manager_impl.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
using namespace OHOS::HDI::Camera::V1_2;
using OHOS::HDI::Camera::V1_2::OperationMode_V1_2;
sptr<ModeManager> ModeManager::modeManager_;
const std::unordered_map<camera_format_t, CameraFormat> ModeManager::metaToFwFormat_ = {
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, CAMERA_FORMAT_YUV_420_SP},
    {OHOS_CAMERA_FORMAT_JPEG, CAMERA_FORMAT_JPEG},
    {OHOS_CAMERA_FORMAT_RGBA_8888, CAMERA_FORMAT_RGBA_8888}
};

const std::unordered_map<CameraFormat, camera_format_t> ModeManager::fwToMetaFormat_ = {
    {CAMERA_FORMAT_YUV_420_SP, OHOS_CAMERA_FORMAT_YCRCB_420_SP},
    {CAMERA_FORMAT_JPEG, OHOS_CAMERA_FORMAT_JPEG},
    {CAMERA_FORMAT_RGBA_8888, OHOS_CAMERA_FORMAT_RGBA_8888},
};

const std::unordered_map<OperationMode_V1_2, CameraMode> g_metaToFwSupportedMode_ = {
    {OperationMode_V1_2::NORMAL, NORMAL},
    {OperationMode_V1_2::CAPTURE, CAPTURE},
    {OperationMode_V1_2::VIDEO, VIDEO},
    {OperationMode_V1_2::PORTRAIT, PORTRAIT},
    {OperationMode_V1_2::NIGHT, NIGHT},
    {OperationMode_V1_2::PROFESSIONAL, PROFESSIONAL},
    {OperationMode_V1_2::SLOW_MOTION, SLOW_MOTION},
    {OperationMode_V1_2::SCAN_CODE, SCAN}
};

const std::unordered_map<CameraMode, OperationMode_V1_2> g_fwToMetaSupportedMode_ = {
    {NORMAL, OperationMode_V1_2::NORMAL},
    {CAPTURE,  OperationMode_V1_2::CAPTURE},
    {VIDEO,  OperationMode_V1_2::VIDEO},
    {PORTRAIT,  OperationMode_V1_2::PORTRAIT},
    {NIGHT,  OperationMode_V1_2::NIGHT},
    {PROFESSIONAL,  OperationMode_V1_2::PROFESSIONAL},
    {SLOW_MOTION,  OperationMode_V1_2::SLOW_MOTION},
    {SCAN, OperationMode_V1_2::SCAN_CODE}
};
ModeManager::ModeManager()
{
    Init();
}

ModeManager::~ModeManager()
{
    serviceProxy_ = nullptr;
    ModeManager::modeManager_ = nullptr;
}

sptr<ModeManager> &ModeManager::GetInstance()
{
    if (ModeManager::modeManager_ == nullptr) {
        MEDIA_INFO_LOG("Initializing mode manager for first time!");
        ModeManager::modeManager_ = new(std::nothrow) ModeManager();
        CHECK_AND_PRINT_LOG(ModeManager::modeManager_ != nullptr, "Failed to new ModeManager");
    }
    return ModeManager::modeManager_;
}

void ModeManager::Init()
{
    CAMERA_SYNC_TRACE;
    sptr<IRemoteObject> object = nullptr;
    MEDIA_DEBUG_LOG("ModeManager:init srart");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("ModeManager get System ability manager failed");
        return;
    }
    MEDIA_DEBUG_LOG("ModeManager:GetSystemAbility srart");
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("object is null");
        return;
    }
    serviceProxy_ = iface_cast<ICameraService>(object);
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return;
    }
    return;
}

sptr<CaptureSession> ModeManager::CreateCaptureSession(CameraMode mode)
{
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;
    sptr<CaptureSession> captureSession = nullptr;

    int32_t retCode = CAMERA_OK;
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return nullptr;
    }
    OperationMode_V1_2 opMode = OperationMode_V1_2::NORMAL;
    for (auto itr = g_fwToMetaSupportedMode_.cbegin(); itr != g_fwToMetaSupportedMode_.cend(); itr++) {
        if (mode == itr->first) {
            opMode = itr->second;
        }
    }
    MEDIA_ERR_LOG("ModeManager CreateCaptureSession E");
    retCode = serviceProxy_->CreateCaptureSession(session, opMode);
    MEDIA_ERR_LOG("ModeManager CreateCaptureSession X, %{public}d", retCode);
    if (retCode == CAMERA_OK && session != nullptr) {
        switch (mode) {
            case CameraMode::PORTRAIT:
                captureSession = new(std::nothrow) PortraitSession(session);
                break;
            case CameraMode::SCAN:
                captureSession = new(std::nothrow) ScanSession(session);
                break;
            case CameraMode::NIGHT:
                captureSession = new(std::nothrow) NightSession(session);
                break;
            default:
                captureSession = new(std::nothrow) CaptureSession(session);
                break;
        }
    } else {
        MEDIA_ERR_LOG("Failed to get capture session object from hcamera service!, %{public}d", retCode);
        return nullptr;
    }
    captureSession->SetMode(static_cast<int32_t>(mode));
    return captureSession;
}

std::vector<CameraMode> ModeManager::GetSupportedModes(sptr<CameraDevice>& camera)
{
    std::vector<CameraMode> supportedModes = {};

    std::shared_ptr<Camera::CameraMetadata> metadata = camera->GetMetadata();
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedModes Failed with return code %{public}d", ret);
        return supportedModes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaToFwSupportedMode_.find(static_cast<OperationMode_V1_2>(item.data.u8[i]));
        if (itr != g_metaToFwSupportedMode_.end()) {
            supportedModes.emplace_back(itr->second);
        }
    }
    MEDIA_INFO_LOG("CaptureSession::GetSupportedModes supportedModes size: %{public}zu", supportedModes.size());
    return supportedModes;
}

sptr<CameraOutputCapability> ModeManager::GetSupportedOutputCapability(sptr<CameraDevice>& camera,
    CameraMode modeName)
{
    sptr<CameraOutputCapability> cameraOutputCapability = nullptr;
    cameraOutputCapability = new(std::nothrow) CameraOutputCapability();
    std::shared_ptr<Camera::CameraMetadata> metadata = camera->GetMetadata();
    vector<MetadataObjectType> objectTypes = {};
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ExtendInfo extendInfo = {};
    camera_metadata_item_t item;
    photoProfiles_.clear();
    previewProfiles_.clear();
    vidProfiles_.clear();
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS,
                                                 &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("Failed get extend stream info %{public}d %{public}d", ret, item.count);
        return nullptr;
    }
    std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
    modeStreamParse->getModeInfo(item.data.i32, item.count, extendInfo); // 解析tag中带的数据信息意义
    for (uint32_t i = 0; i < extendInfo.modeCount; i++) {
        if (modeName != 0 && modeName == extendInfo.modeInfo[i].modeName) {
            for (uint32_t j = 0; j < extendInfo.modeInfo[i].streamTypeCount; j++) {
                OutputCapStreamType streamType =
                    static_cast<OutputCapStreamType>(extendInfo.modeInfo[i].streamInfo[j].streamType);
                CreateProfile4StreamType(streamType, i, j, extendInfo);
            }
            break;
        }
    }

    cameraOutputCapability->SetPhotoProfiles(photoProfiles_);
    MEDIA_INFO_LOG("SetPhotoProfiles camera[%{public}s] size = %{public}zu",
                   camera->GetID().c_str(), photoProfiles_.size());
    cameraOutputCapability->SetPreviewProfiles(previewProfiles_);
    MEDIA_INFO_LOG("SetPreviewProfiles camera[%{public}s] size = %{public}zu",
                   camera->GetID().c_str(), previewProfiles_.size());
    cameraOutputCapability->SetVideoProfiles(vidProfiles_);
    MEDIA_INFO_LOG("SetVideoProfiles size = %{public}zu",
                   vidProfiles_.size());
    camera_metadata_item_t metadataItem;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_STATISTICS_FACE_DETECT_MODE, &metadataItem);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t index = 0; index < metadataItem.count; index++) {
            if (metadataItem.data.u8[index] == OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE) {
                objectTypes.push_back(MetadataObjectType::FACE);
            }
        }
    }
    cameraOutputCapability->SetSupportedMetadataObjectType(objectTypes);
    return cameraOutputCapability;
}

void ModeManager::CreateProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
    uint32_t streamIndex, ExtendInfo extendInfo)
{
    for (uint32_t k = 0; k < extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfoCount; k++) {
        CameraFormat format;
        auto itr = metaToFwFormat_.find(static_cast<camera_format_t>(
            extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].format));
        if (itr != metaToFwFormat_.end()) {
            format = itr->second;
        } else {
            format = CAMERA_FORMAT_INVALID;
            continue;
        }
        Size size;
        size.width = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].width;
        size.height = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].height;
        Fps fps;
        fps.fixedFps = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].fixedFps;
        fps.minFps = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].minFps;
        fps.maxFps = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].maxFps;
        std::vector<uint32_t> abilityId;
        abilityId = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].abilityId;
        std::string abilityIds = "";
        for (auto id : abilityId) {
            abilityIds += std::to_string(id) + ",";
        }
        if (streamType == OutputCapStreamType::PREVIEW) {
            Profile previewProfile = Profile(format, size, fps, abilityId);
            MEDIA_ERR_LOG("preview format : %{public}d, width: %{public}d, height: %{public}d"
                          "support ability: %{public}s",
                          previewProfile.GetCameraFormat(), previewProfile.GetSize().width,
                          previewProfile.GetSize().height,
                          abilityIds.c_str());
            previewProfiles_.push_back(previewProfile);
        } else if (streamType == OutputCapStreamType::STILL_CAPTURE) {
            Profile snapProfile = Profile(format, size, fps, abilityId);
            MEDIA_ERR_LOG("photo format : %{public}d, width: %{public}d, height: %{public}d"
                          "support ability: %{public}s",
                          snapProfile.GetCameraFormat(), snapProfile.GetSize().width, snapProfile.GetSize().height,
                          abilityIds.c_str());
            photoProfiles_.push_back(snapProfile);
        } else if (streamType == OutputCapStreamType::VIDEO_STREAM) {
            std::vector<int32_t> frameRates = {fps.fixedFps, fps.fixedFps};
            VideoProfile vidProfile = VideoProfile(format, size, frameRates);
            MEDIA_ERR_LOG("video format : %{public}d, width: %{public}d, height: %{public}d"
                          "support ability: %{public}s",
                          vidProfile.GetCameraFormat(), vidProfile.GetSize().width, vidProfile.GetSize().height,
                          abilityIds.c_str());
            vidProfiles_.push_back(vidProfile);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS
