/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "session/control_center_session.h"
#include "ability/camera_ability_const.h"
#include "camera_log.h"
#include "camera_manager.h"
#include <cstdint>
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {

ControlCenterSession::ControlCenterSession()
{
    MEDIA_INFO_LOG("Enter Into ControlCenterSession::ControlCenterSession()");
}

ControlCenterSession::~ControlCenterSession()
{
    MEDIA_INFO_LOG("Enter Into ControlCenterSession::~ControlCenterSession()");
}

int32_t ControlCenterSession::Release()
{
    MEDIA_INFO_LOG("ControlCenterSession::Release()");
    return CAMERA_OK;
}

int32_t ControlCenterSession::GetSupportedVirtualApertures(std::vector<float>& apertures)
{
    MEDIA_INFO_LOG("ControlCenterSession::GetSupportedVirtualApertures");
    CHECK_RETURN_RET_ELOG(!CheckIsSupportControlCenter(), CAMERA_INVALID_STATE,
        "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_INVALID_ARG,
        "ControlCenterSession::GetSupportedVirtualApertures serviceProxy is null");
    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || session == nullptr, ret,
        "ControlCenterSession::GetSupportedVirtualApertures failed, session is nullptr.");
    ret = session->GetVirtualApertureMetadate(apertures);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret,
        "ControlCenterSession::GetSupportedVirtualApertures failed, get apertures failed.");
    return CAMERA_OK;
}

int32_t ControlCenterSession::GetVirtualAperture(float& aperture)
{
    MEDIA_INFO_LOG("ControlCenterSession::GetVirtualAperture");
    CHECK_RETURN_RET_ELOG(!CheckIsSupportControlCenter(), CAMERA_INVALID_STATE,
        "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_INVALID_ARG,
        "ControlCenterSession::GetVirtualAperture serviceProxy is null");
    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || session == nullptr, ret,
        "ControlCenterSession::GetVirtualAperture failed, session is nullptr.");
    ret = session->GetVirtualApertureValue(aperture);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret,
        "ControlCenterSession::GetVirtualAperture failed, get aperture failed.");
    return CAMERA_OK;
}

int32_t ControlCenterSession::SetVirtualAperture(const float virtualAperture)
{
    MEDIA_INFO_LOG("ControlCenterSession::SetVirtualAperture");
    CHECK_RETURN_RET_ELOG(!CheckIsSupportControlCenter(), CAMERA_INVALID_STATE,
        "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_INVALID_ARG,
        "ControlCenterSession::SetVirtualAperture serviceProxy is null");

    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || session == nullptr, ret,
        "ControlCenterSession::SetVirtualAperture failed, session is nullptr.");
    
    ret = session->SetVirtualApertureValue(virtualAperture, true);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret,
        "ControlCenterSession::SetVirtualAperture failed, set apertures failed.");
    MEDIA_INFO_LOG("SetVirtualAperture success, value: %{public}f", virtualAperture);
    return CAMERA_OK;
}

int32_t ControlCenterSession::GetSupportedPhysicalApertures(std::vector<std::vector<float>>& apertures)
{
    return CameraErrorCode::INVALID_ARGUMENT;
}

int32_t ControlCenterSession::GetPhysicalAperture(float& aperture)
{
    return CameraErrorCode::INVALID_ARGUMENT;
}

int32_t ControlCenterSession::SetPhysicalAperture(float physicalAperture)
{
    return CameraErrorCode::INVALID_ARGUMENT;
}

std::vector<int32_t> ControlCenterSession::GetSupportedBeautyTypes()
{
    MEDIA_INFO_LOG("ControlCenterSession::GetSupportedBeautyTypes");
    CHECK_RETURN_RET_ELOG(!CheckIsSupportControlCenter(), {},
        "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    std::vector<int32_t> metadata = {};
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, metadata,
        "ControlCenterSession::GetSupportedBeautyTypes serviceProxy is null");
    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || session == nullptr, metadata,
        "ControlCenterSession::GetSupportedBeautyTypes failed, session is nullptr.");
    ret = session->GetBeautyMetadata(metadata);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, metadata,
        "ControlCenterSession::GetSupportedBeautyTypes failed, get beauty metadata failed.");
    return metadata;
}

std::vector<int32_t> ControlCenterSession::GetSupportedBeautyRange(BeautyType type)
{
    MEDIA_INFO_LOG("ControlCenterSession::GetSupportedBeautyRange");
    CHECK_RETURN_RET_ELOG(!CheckIsSupportControlCenter(), {},
        "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    std::vector<int32_t> metadata = {};
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, metadata,
        "ControlCenterSession::GetSupportedBeautyRange serviceProxy is null");
    
    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || session == nullptr, metadata,
        "ControlCenterSession::GetSupportedBeautyRange failed, session is nullptr.");
    ret = session->GetBeautyRange(metadata, type);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, metadata,
        "ControlCenterSession::GetSupportedBeautyRange failed, get beauty range failed.");
    return metadata;
}


void ControlCenterSession::SetBeauty(BeautyType type, int value)
{
    MEDIA_INFO_LOG("ControlCenterSession::SetBeauty");
    CHECK_RETURN_ELOG(!CheckIsSupportControlCenter(), "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr,
        "ControlCenterSession::SetBeauty serviceProxy is null");
    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_ELOG(ret != CAMERA_OK || session == nullptr,
        "ControlCenterSession::SetBeauty failed, session is nullptr.");
    ret = session->SetBeautyValue(type, value, true);
    CHECK_RETURN_ELOG(ret != CAMERA_OK,
        "ControlCenterSession::SetBeauty failed, set beauty failed.");
    MEDIA_INFO_LOG("SetBeauty success value: %{public}d", value);
}

int32_t ControlCenterSession::GetBeauty(BeautyType type)
{
    MEDIA_INFO_LOG("ControlCenterSession::GetBeauty");
    CHECK_RETURN_RET_ELOG(!CheckIsSupportControlCenter(), 0, "Current status does not support control center.");
    sptr<ICaptureSession> session = nullptr;
    int32_t value = 0;
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, value,
        "ControlCenterSession::GetBeauty serviceProxy is null");
    auto ret = serviceProxy->GetVideoSessionForControlCenter(session);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || session == nullptr, value,
        "ControlCenterSession::GetBeauty failed, session is nullptr.");
    ret = session->GetBeautyValue(type, value);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, value,
        "ControlCenterSession::GetBeauty failed, get beauty failed.");
    MEDIA_INFO_LOG("GetBeauty success value:%{public}d", value);
    return value;
}

int32_t ControlCenterSession::GetSupportedPortraitThemeTypes(std::vector<PortraitThemeType>& types)
{
    return CameraErrorCode::INVALID_ARGUMENT;
}

int32_t ControlCenterSession::IsPortraitThemeSupported(bool &isSupported)
{
    return CameraErrorCode::INVALID_ARGUMENT;
}

bool ControlCenterSession::IsPortraitThemeSupported()
{
    return false;
}

int32_t ControlCenterSession::SetPortraitThemeType(PortraitThemeType type)
{
    return CameraErrorCode::INVALID_ARGUMENT;
}

bool ControlCenterSession::CheckIsSupportControlCenter()
{
    return CameraManager::GetInstance()->GetIsControlCenterSupported();
}

} // namespace CameraStandard
} // namespace OHOS