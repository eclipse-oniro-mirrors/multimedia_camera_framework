/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "camera_const_ability_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "session/camera_session_taihe.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_input_taihe.h"
#include "camera_output_taihe.h"
#include "camera_input.h"
#include "camera_security_utils_taihe.h"
#include "camera_query_taihe.h"

namespace Ani {
namespace Camera {
bool FlashQueryImpl::HasFlash()
{
    MEDIA_DEBUG_LOG("HasFlash is called");
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false, "HasFlash failed, captureSession is nullptr");
        bool isSupported = false;
        int retCode = captureSession_->HasFlash(isSupported);
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "HasFlash failed, cameraAbility_ is nullptr");
        return cameraAbility_->HasFlash();
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

bool FlashQueryImpl::IsFlashModeSupported(FlashMode flashMode)
{
    OHOS::CameraStandard::FlashMode mode = static_cast<OHOS::CameraStandard::FlashMode>(flashMode.get_value());
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false,
            "IsFlashModeSupported failed, captureSession_ is nullptr");
        bool isSupported = false;
        captureSession_->LockForControl();
        int retCode = captureSession_->IsFlashModeSupported(mode, isSupported);
        captureSession_->UnlockForControl();
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsFlashModeSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsFlashModeSupported(mode);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

bool FlashQueryImpl::IsLcdFlashSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsLcdFlashSupported is called!");
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false, "IsLcdFlashSupported captureSession_ is null");
        return captureSession_->IsLcdFlashSupported();
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsLcdFlashSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsLcdFlashSupported();
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

void FlashImpl::EnableLcdFlash(bool enabled)
{
    MEDIA_DEBUG_LOG("EnableLcdFlash is called");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableLcdFlash is called!");

    if (captureSession_ != nullptr) {
        MEDIA_INFO_LOG("EnableLcdFlash:%{public}d", enabled);
        captureSession_->LockForControl();
        int32_t retCode = captureSession_->EnableLcdFlash(enabled);
        captureSession_->UnlockForControl();
        CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
            "FlashImpl::EnableLcdFlash fail %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("EnableLcdFlash get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
    }
}

void FlashImpl::SetFlashMode(FlashMode flashMode)
{
    MEDIA_DEBUG_LOG("SetFlashMode is called");
    captureSession_->LockForControl();
    int retCode = captureSession_->SetFlashMode(static_cast<OHOS::CameraStandard::FlashMode>(flashMode.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

FlashMode FlashImpl::GetFlashMode()
{
    MEDIA_DEBUG_LOG("GetFlashMode is called");
    FlashMode errType = FlashMode(static_cast<FlashMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, errType, "GetFlashMode captureSession_ is null");
    OHOS::CameraStandard::FlashMode flashMode;
    int32_t retCode = captureSession_->GetFlashMode(flashMode);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return FlashMode(static_cast<FlashMode::key_t>(flashMode));
}

array<double> ZoomQueryImpl::GetZoomRatioRange()
{
    MEDIA_DEBUG_LOG("GetZoomRatioRange is called");
    std::vector<float> vecZoomRatioList;
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, array<double>(0.0),
            "GetZoomRatioRange failed, captureSession is nullptr");

        int retCode = captureSession_->GetZoomRatioRange(vecZoomRatioList);
        MEDIA_INFO_LOG("GetZoomRatioRange vecZoomRatioList len = %{public}zu", vecZoomRatioList.size());
        if (retCode != 0) {
            CameraUtilsTaihe::ThrowError(retCode, "failed to GetZoomRatioRange, inner GetZoomRatioRange failed");
            return array<double>(0.0);
        }
        std::vector<double> doubleVec(vecZoomRatioList.begin(), vecZoomRatioList.end());
        return array<double>(doubleVec);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<double>(0.0),
            "GetZoomRatioRange failed, cameraAbility_ is nullptr");
        vecZoomRatioList = cameraAbility_->GetZoomRatioRange();
        std::vector<double> doubleVec(vecZoomRatioList.begin(), vecZoomRatioList.end());
        return array<double>(doubleVec);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<double>(0.0);
    }
}

array<ZoomPointInfo> ZoomQueryImpl::GetZoomPointInfos()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<ZoomPointInfo>(nullptr, 0), "SystemApi GetZoomPointInfos is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
        array<ZoomPointInfo>(nullptr, 0), "GetZoomPointInfos captureSession_ is null");
    std::vector<OHOS::CameraStandard::ZoomPointInfo> vecZoomPointInfoList;
    int32_t retCode = captureSession_->GetZoomPointInfos(vecZoomPointInfoList);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<ZoomPointInfo>(nullptr, 0));
    return CameraUtilsTaihe::ToTaiheArrayZoomPointInfo(vecZoomPointInfoList);
}

double ZoomImpl::GetZoomRatio()
{
    float zoomRatio = -1.0;
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, zoomRatio, "GetZoomRatio failed, captureSession is nullptr");
    int32_t retCode = captureSession_->GetZoomRatio(zoomRatio);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), zoomRatio);
    return static_cast<double>(zoomRatio);
}

void ZoomImpl::SetZoomRatio(double zoomRatio)
{
    MEDIA_DEBUG_LOG("SetZoomRatio is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetZoomRatio captureSession_ is null");
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetZoomRatio(static_cast<float>(zoomRatio));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "SetZoomRatio is failed called!");
}

void ZoomImpl::PrepareZoom()
{
    MEDIA_DEBUG_LOG("PrepareZoom is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "PrepareZoom captureSession_ is null");
    captureSession_->LockForControl();
    int retCode = captureSession_->PrepareZoom();
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "PrepareZoom is failed called!");
}

void ZoomImpl::UnprepareZoom()
{
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "UnprepareZoom captureSession_ is null");
    captureSession_->LockForControl();
    int retCode = captureSession_->UnPrepareZoom();
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "UnprepareZoom is failed called!");
}

void ZoomImpl::SetSmoothZoom(double targetRatio, optional_view<SmoothZoomMode> mode)
{
    MEDIA_DEBUG_LOG("SetSmoothZoom is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetSmoothZoom captureSession_ is null");
    if (mode.has_value()) {
        int32_t retCode = captureSession_->SetSmoothZoom(
            static_cast<float>(targetRatio), static_cast<int32_t>(mode.value().get_value()));
        CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "SetSmoothZoom is failed called!");
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "SmoothZoomMode is null");
    }
}

void ColorReservationImpl::SetColorReservation(ColorReservationType type)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetColorReservation is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetColorReservation captureSession_ is null");
    captureSession_->LockForControl();
    int retCode = captureSession_->SetColorReservation(
        static_cast<OHOS::CameraStandard::ColorReservationType>(type.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "SystemApi SetColorReservation is failed called!");
}

ColorReservationType ColorReservationImpl::GetColorReservation()
{
    ColorReservationType errType = ColorReservationType(static_cast<ColorReservationType::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        errType, "SystemApi GetColorReservation is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
        errType, "GetColorReservation captureSession_ is null");
    OHOS::CameraStandard::ColorReservationType colorReservationType =
        OHOS::CameraStandard::ColorReservationType::COLOR_RESERVATION_TYPE_NONE;
    int32_t retCode = captureSession_->GetColorReservation(colorReservationType);
    CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode), errType,
        "SystemApi GetColorReservation is failed called!");
    return ColorReservationType(static_cast<ColorReservationType::key_t>(colorReservationType));
}

array<ColorReservationType> ColorReservationQueryImpl::GetSupportedColorReservationTypes()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<ColorReservationType>(nullptr, 0), "SystemApi GetSupportedColorReservationTypes is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
        array<ColorReservationType>(nullptr, 0), "GetSupportedColorReservationTypes captureSession_ is null");
    std::vector<OHOS::CameraStandard::ColorReservationType> colorReservationTypes;
    int32_t retCode = captureSession_->GetSupportedColorReservationTypes(colorReservationTypes);
    CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode), array<ColorReservationType>(nullptr, 0),
        "SystemApi GetSupportedColorReservationTypes is failed called!");
    return CameraUtilsTaihe::ToTaiheArrayEnum<ColorReservationType, OHOS::CameraStandard::ColorReservationType>(
        colorReservationTypes);
}

bool FocusQueryImpl::IsFocusRangeTypeSupported(FocusRangeType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsFocusRangeTypeSupported is called!");
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(
            captureSession_ == nullptr, false, "IsFocusRangeTypeSupported captureSession_ is null");
        bool isSupported = false;
        int32_t retCode = captureSession_->IsFocusRangeTypeSupported(
            static_cast<OHOS::CameraStandard::FocusRangeType>(type.get_value()), isSupported);
        CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode),
            false, "SystemApi IsFocusRangeTypeSupported is failed called!");
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsFocusRangeTypeSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsFocusRangeTypeSupported(
            static_cast<OHOS::CameraStandard::FocusRangeType>(type.get_value()));
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

bool FocusQueryImpl::IsFocusDrivenTypeSupported(FocusDrivenType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsFocusDrivenTypeSupported is called!");
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false,
            "IsFocusDrivenTypeSupported captureSession_ is null");
        bool isSupported = false;
        int32_t retCode = captureSession_->IsFocusDrivenTypeSupported(
            static_cast<OHOS::CameraStandard::FocusDrivenType>(type.get_value()), isSupported);
        CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode),
            false, "SystemApi IsFocusDrivenTypeSupported is failed called!");
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsFocusDrivenTypeSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsFocusDrivenTypeSupported(
            static_cast<OHOS::CameraStandard::FocusDrivenType>(type.get_value()));
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

bool FocusQueryImpl::IsFocusModeSupported(FocusMode afMode)
{
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false, "IsFocusModeSupported captureSession_ is null");
        bool isSupported = false;
        int32_t retCode = captureSession_->IsFocusModeSupported(
            static_cast<OHOS::CameraStandard::FocusMode>(afMode.get_value()), isSupported);
        CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode),
            false, "IsFocusModeSupported is failed called!");
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsFocusModeSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsFocusModeSupported(static_cast<OHOS::CameraStandard::FocusMode>(afMode.get_value()));
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

bool FocusQueryImpl::IsFocusAssistSupported()
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not IsFocusAssistSupported in current session!");
    return false;
}

void FocusImpl::SetFocusDriven(FocusDrivenType type)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetFocusDriven is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetFocusDriven captureSession_ is null");
    captureSession_->LockForControl();
    int retCode = captureSession_->SetFocusDriven(static_cast<OHOS::CameraStandard::FocusDrivenType>(type.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "SystemApi SetFocusDriven is failed called!");
}

FocusDrivenType FocusImpl::GetFocusDriven()
{
    FocusDrivenType errType = FocusDrivenType(static_cast<FocusDrivenType::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        errType, "SystemApi GetFocusDriven is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, errType, "GetFocusDriven captureSession_ is null");
    OHOS::CameraStandard::FocusDrivenType focusDrivenType =
        OHOS::CameraStandard::FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO;
    int32_t retCode = captureSession_->GetFocusDriven(focusDrivenType);
    CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode),
        errType, "SystemApi GetFocusDriven is failed called!");
    return FocusDrivenType(static_cast<FocusDrivenType::key_t>(focusDrivenType));
}

void FocusImpl::SetFocusRange(FocusRangeType type)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetFocusRange is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetFocusRange captureSession_ is null");
    captureSession_->LockForControl();
    int retCode = captureSession_->SetFocusRange(static_cast<OHOS::CameraStandard::FocusRangeType>(type.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "SystemApi SetFocusRange is failed called!");
}

FocusRangeType FocusImpl::GetFocusRange()
{
    FocusRangeType errType = FocusRangeType(static_cast<FocusRangeType::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        errType, "SystemApi GetFocusRange is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, errType, "GetFocusRange captureSession_ is null");
    OHOS::CameraStandard::FocusRangeType focusRangeType =
        OHOS::CameraStandard::FocusRangeType::FOCUS_RANGE_TYPE_AUTO;
    int32_t retCode = captureSession_->GetFocusRange(focusRangeType);
    CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode),
        errType, "SystemApi GetFocusRange is failed called!");
    return FocusRangeType(static_cast<FocusRangeType::key_t>(focusRangeType));
}

void FocusImpl::SetFocusAssist(bool enabled)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not SetFocusAssist in current session!");
}

Point FocusImpl::GetFocusPoint()
{
    MEDIA_DEBUG_LOG("GetFocusPoint is called");
    OHOS::CameraStandard::Point focusPoint {
        .x = -1,
        .y = -1,
    };
    Point taiheFocusPoint {
        .x = -1,
        .y = -1,
    };
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, taiheFocusPoint, "GetFocusPoint captureSession_ is null");
    int32_t retCode = captureSession_->GetFocusPoint(focusPoint);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), taiheFocusPoint);
    taiheFocusPoint.x =  static_cast<double>(focusPoint.x);
    taiheFocusPoint.y = static_cast<double>(focusPoint.y);
    return taiheFocusPoint;
}

void FocusImpl::SetFocusPoint(Point const& point)
{
    MEDIA_DEBUG_LOG("SetFocusPoint is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetFocusPoint captureSession_ is null!");
    OHOS::CameraStandard::Point focusPoint {
        .x = static_cast<float>(point.x),
        .y = static_cast<float>(point.y),
    };
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetFocusPoint(focusPoint);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

double FocusImpl::GetFocalLength()
{
    float focalLength = -1.0;
    MEDIA_DEBUG_LOG("GetFocalLength is called");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, focalLength, "GetFocalLength captureSession_ is null");
    int32_t retCode = captureSession_->GetFocalLength(focalLength);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), focalLength);
    return static_cast<double>(focalLength);
}

void FocusImpl::SetFocusMode(FocusMode afMode)
{
    MEDIA_DEBUG_LOG("SetFocusMode is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "FocusImpl::SetFocusMode captureSession_ is null!");
    captureSession_->LockForControl();
    int retCode = captureSession_->
            SetFocusMode(static_cast<OHOS::CameraStandard::FocusMode>(afMode.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "FlashImpl::SetFocusMode fail %{public}d", retCode);
}

FocusMode FocusImpl::GetFocusMode()
{
    MEDIA_DEBUG_LOG("GetFocusMode is called");
    FocusMode errType = FocusMode(static_cast<FocusMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, errType, "GetFocusMode captureSession_ is null");
    OHOS::CameraStandard::FocusMode focusMode;
    int32_t retCode = captureSession_->GetFocusMode(focusMode);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return FocusMode(static_cast<FocusMode::key_t>(focusMode));
}

bool StabilizationQueryImpl::IsVideoStabilizationModeSupported(VideoStabilizationMode vsMode)
{
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false,
            "IsVideoStabilizationModeSupported captureSession_ is null");
        bool isSupported = false;
        int32_t retCode = captureSession_->IsVideoStabilizationModeSupported(
            static_cast<OHOS::CameraStandard::VideoStabilizationMode>(vsMode.get_value()), isSupported);
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsVideoStabilizationModeSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsVideoStabilizationModeSupported(
            static_cast<OHOS::CameraStandard::VideoStabilizationMode>(vsMode.get_value()));
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

VideoStabilizationMode StabilizationImpl::GetActiveVideoStabilizationMode()
{
    MEDIA_DEBUG_LOG("GetActiveVideoStabilizationMode is called");
    VideoStabilizationMode errType = VideoStabilizationMode(static_cast<VideoStabilizationMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, errType,
        "GetActiveVideoStabilizationMode captureSession_ is null");
    OHOS::CameraStandard::VideoStabilizationMode videoStabilizationMode;
    int32_t retCode = captureSession_->GetActiveVideoStabilizationMode(videoStabilizationMode);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return VideoStabilizationMode(static_cast<VideoStabilizationMode::key_t>(videoStabilizationMode));
}

void StabilizationImpl::SetVideoStabilizationMode(VideoStabilizationMode mode)
{
    MEDIA_DEBUG_LOG("SetVideoStabilizationMode is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetVideoStabilizationMode captureSession_ is null!");
    int retCode = captureSession_->SetVideoStabilizationMode(
        static_cast<OHOS::CameraStandard::VideoStabilizationMode>(mode.get_value()));
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode), "SetVideoStabilizationMode call Failed!");
}

array<PortraitThemeType> BeautyQueryImpl::GetSupportedPortraitThemeTypes()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<PortraitThemeType>(nullptr, 0), "SystemApi GetSupportedPortraitThemeTypes is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, array<PortraitThemeType>(nullptr, 0),
        "GetSupportedPortraitThemeTypes captureSession_ is null");
    std::vector<OHOS::CameraStandard::PortraitThemeType> themeTypes;
    int32_t retCode = captureSession_->GetSupportedPortraitThemeTypes(themeTypes);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<PortraitThemeType>(nullptr, 0));
    return CameraUtilsTaihe::ToTaiheArrayEnum<PortraitThemeType, OHOS::CameraStandard::PortraitThemeType>(themeTypes);
}

array<BeautyType> BeautyQueryImpl::GetSupportedBeautyTypes()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<BeautyType>(nullptr, 0), "SystemApi GetSupportedBeautyTypes is called!");
    std::vector<OHOS::CameraStandard::BeautyType> beautyTypes;
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, array<BeautyType>(nullptr, 0),
            "GetSupportedBeautyTypes captureSession_ is null");
        beautyTypes = captureSession_->GetSupportedBeautyTypes();
        return CameraUtilsTaihe::ToTaiheArrayEnum<BeautyType, OHOS::CameraStandard::BeautyType>(beautyTypes);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<BeautyType>(nullptr, 0),
            "GetSupportedBeautyTypes failed, cameraAbility_ is nullptr");
        beautyTypes = cameraAbility_->GetSupportedBeautyTypes();
        return CameraUtilsTaihe::ToTaiheArrayEnum<BeautyType, OHOS::CameraStandard::BeautyType>(beautyTypes);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<BeautyType>(nullptr, 0);
    }
}

array<int32_t> BeautyQueryImpl::GetSupportedBeautyRange(BeautyType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), array<int32_t>(0),
        "SystemApi GetSupportedBeautyRange is called!");
    std::vector<int32_t> beautyRanges;
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(
            captureSession_ == nullptr, array<int32_t>(0), "GetSupportedBeautyRange captureSession_ is null");
        beautyRanges =
            captureSession_->GetSupportedBeautyRange(static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()));
        return array<int32_t>(beautyRanges);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<int32_t>(0),
            "GetSupportedBeautyRange failed, cameraAbility_ is nullptr");
            beautyRanges = cameraAbility_->GetSupportedBeautyRange(
                static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()));
        return array<int32_t>(beautyRanges);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<int32_t>(0);
    }
}

bool BeautyQueryImpl::IsPortraitThemeSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsPortraitThemeSupported is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false, "IsPortraitThemeSupported captureSession_ is null");
    bool isSupported;
    int32_t retCode = captureSession_->IsPortraitThemeSupported(isSupported);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    return false;
}

void BeautyImpl::SetPortraitThemeType(PortraitThemeType type)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetPortraitThemeType is called!");
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to SetPortraitThemeType, captureSession_ is nullptr");
        return;
    }
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetPortraitThemeType(
        static_cast<OHOS::CameraStandard::PortraitThemeType>(type.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "BeautyImpl::SetPortraitThemeType fail %{public}d", retCode);
}

int32_t BeautyImpl::GetBeauty(BeautyType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        0, "SystemApi GetBeauty is called!");
    MEDIA_DEBUG_LOG("GetBeauty is called");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, 0, "BeautyImpl::GetBeauty captureSession_ is null!");
    int32_t beautyStrength =
        captureSession_->GetBeauty(static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()));
    return beautyStrength;
}

void BeautyImpl::SetBeauty(BeautyType type, int32_t value)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetBeauty is called!");
    MEDIA_DEBUG_LOG("SetBeauty is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetBeauty captureSession_ is null!");
    captureSession_->LockForControl();
    captureSession_->SetBeauty(static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()), value);
    captureSession_->UnlockForControl();
}

array<double> AutoExposureQueryImpl::GetExposureBiasRange()
{
    std::vector<float> vecExposureBiasList;
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
            array<double>(nullptr, 0), "GetExposureBiasRange captureSession_ is null");
        int32_t retCode = captureSession_->GetExposureBiasRange(vecExposureBiasList);
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<double>(nullptr, 0));
        std::vector<double> doubleVec(vecExposureBiasList.begin(), vecExposureBiasList.end());
        return array<double>(doubleVec);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<double>(nullptr, 0),
            "GetExposureBiasRange failed, cameraAbility_ is nullptr");
            vecExposureBiasList = cameraAbility_->GetExposureBiasRange();
        std::vector<double> doubleVec(vecExposureBiasList.begin(), vecExposureBiasList.end());
        return array<double>(doubleVec);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<double>(nullptr, 0);
    }
}

bool AutoExposureQueryImpl::IsExposureModeSupported(ExposureMode aeMode)
{
    OHOS::CameraStandard::ExposureMode exposureMode =
        static_cast<OHOS::CameraStandard::ExposureMode>(aeMode.get_value());
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false,
            "IsExposureModeSupported captureSession_ is null");
        bool isSupported = false;
        int32_t retCode = captureSession_->IsExposureModeSupported(exposureMode, isSupported);
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
        return isSupported;
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsExposureModeSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsExposureModeSupported(exposureMode);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

bool AutoExposureQueryImpl::IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not IsExposureMeteringModeSupported in current session!");
    return false;
}

void AutoExposureImpl::SetExposureBias(double exposureBias)
{
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to SetExposureBias, captureSession_ is nullptr");
        return;
    }
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetExposureBias(static_cast<float>(exposureBias));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "AutoExposureImpl::SetExposureBias fail %{public}d", retCode);
}

void AutoExposureImpl::SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not SetExposureMeteringMode in current session!");
    return;
}

ExposureMeteringMode AutoExposureImpl::GetExposureMeteringMode()
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not SetExposureMeteringMode in current session!");
    ExposureMeteringMode meteringMode = static_cast<ExposureMeteringMode::key_t>(-1);
    return meteringMode;
}

double AutoExposureImpl::GetExposureValue()
{
    float exposureValue = -1.0;
    MEDIA_DEBUG_LOG("GetExposureValue is called");
    CHECK_ERROR_RETURN_RET_LOG(
        captureSession_ == nullptr, exposureValue, "GetExposureValue captureSession_ is null");
    int32_t retCode = captureSession_->GetExposureValue(exposureValue);
    CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode), exposureValue,
        "AutoExposureImpl::GetExposureValue fail %{public}d", retCode);
    return static_cast<double>(exposureValue);
}

Point AutoExposureImpl::GetMeteringPoint()
{
    MEDIA_DEBUG_LOG("GetMeteringPoint is called");
    OHOS::CameraStandard::Point exposurePoint {
        .x = -1,
        .y = -1,
    };
    Point taiheExposurePoint {
        .x = -1,
        .y = -1,
    };
    CHECK_ERROR_RETURN_RET_LOG(
        captureSession_ == nullptr, taiheExposurePoint, "GetMeteringPoint captureSession_ is null");
    int32_t retCode = captureSession_->GetMeteringPoint(exposurePoint);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), taiheExposurePoint);
    taiheExposurePoint.x = static_cast<double>(exposurePoint.x);
    taiheExposurePoint.y = static_cast<double>(exposurePoint.y);
    return taiheExposurePoint;
}

void AutoExposureImpl::SetMeteringPoint(Point const& point)
{
    MEDIA_DEBUG_LOG("SetMeteringPoint is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetMeteringPoint captureSession_ is null");
    OHOS::CameraStandard::Point meteringPoint {
        .x = static_cast<float>(point.x),
        .y = static_cast<float>(point.y),
    };
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetMeteringPoint(meteringPoint);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

void AutoExposureImpl::SetExposureMode(ExposureMode aeMode)
{
    MEDIA_DEBUG_LOG("SetExposureMode is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetExposureMode captureSession_ is null!");
    captureSession_->LockForControl();
    int retCode =
        captureSession_->SetExposureMode(static_cast<OHOS::CameraStandard::ExposureMode>(aeMode.get_value()));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

ExposureMode AutoExposureImpl::GetExposureMode()
{
    MEDIA_DEBUG_LOG("GetExposureMode is called");
    ExposureMode errType = ExposureMode(static_cast<ExposureMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
        errType, "GetExposureMode captureSession_ is null");
    OHOS::CameraStandard::ExposureMode exposureMode;
    int32_t retCode = captureSession_->GetExposureMode(exposureMode);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return ExposureMode(static_cast<ExposureMode::key_t>(exposureMode));
}

array<uintptr_t> ColorManagementQueryImpl::GetSupportedColorSpaces()
{
    std::vector<OHOS::CameraStandard::ColorSpace> colorSpaces;
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
            array<uintptr_t>(nullptr, 0), "GetSupportedColorSpaces captureSession_ is null");
        colorSpaces = captureSession_->GetSupportedColorSpaces();
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<uintptr_t>(nullptr, 0),
            "GetSupportedColorSpaces failed, cameraAbility_ is nullptr");
        colorSpaces = cameraAbility_->GetSupportedColorSpaces();
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<uintptr_t>(nullptr, 0);
    }
    std::vector<uintptr_t> vec;
    ani_enum aniEnum {};
    ani_enum_item aniEnumItem {};
    ani_env* env = get_env();
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr,
        array<uintptr_t>(nullptr, 0), "GetSupportedColorSpaces env is null");
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->FindEnum(ENUM_NAME_COLORSPACE, &aniEnum),
        array<uintptr_t>(nullptr, 0), "Find Enum Fail");
    for (auto item : colorSpaces) {
        CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Enum_GetEnumItemByIndex(
            aniEnum, reinterpret_cast<ani_int>(static_cast<int32_t>(item)), &aniEnumItem),
            array<uintptr_t>(nullptr, 0), "Find Enum item Fail");
        vec.push_back(reinterpret_cast<uintptr_t>(aniEnumItem));
    }
    return array<uintptr_t>(vec);
}

uintptr_t ColorManagementImpl::GetActiveColorSpace()
{
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, 0, "GetActiveColorSpace captureSession_ is null");
    OHOS::CameraStandard::ColorSpace colorSpace;
    int32_t retCode = captureSession_->GetActiveColorSpace(colorSpace);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), 0);
    ani_enum aniEnum {};
    ani_enum_item aniEnumItem {};
    ani_env* env = get_env();
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr, 0, "GetActiveColorSpace env is null");
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Enum_GetEnumItemByIndex(
        aniEnum, reinterpret_cast<ani_int>(static_cast<int32_t>(colorSpace)), &aniEnumItem), 0, "Find Enum item Fail");
    return reinterpret_cast<uintptr_t>(aniEnumItem);
}

void ColorManagementImpl::SetColorSpace(uintptr_t colorSpace)
{
    int32_t colorSpaceVar = CameraUtilsTaihe::EnumGetValueInt32(get_env(), reinterpret_cast<ani_enum_item>(colorSpace));
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetColorSpace captureSession_ is null");
    int32_t retCode = captureSession_->SetColorSpace(static_cast<OHOS::CameraStandard::ColorSpace>(colorSpaceVar));
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "ColorManagementImpl::SetColorSpace fail %{public}d", retCode);
}

bool SceneDetectionQueryImpl::IsSceneFeatureSupported(SceneFeatureType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsSceneFeatureSupported is called!");
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
            false, "IsSceneFeatureSupported captureSession_ is null");
        return captureSession_->IsFeatureSupported(static_cast<OHOS::CameraStandard::SceneFeature>(type.get_value()));
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsSceneFeatureSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsFeatureSupported(static_cast<OHOS::CameraStandard::SceneFeature>(type.get_value()));
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

void SceneDetectionImpl::EnableSceneFeature(SceneFeatureType type, bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableSceneFeature is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetColorSpace captureSession_ is null");
    int32_t retCode =
        captureSession_->EnableFeature(static_cast<OHOS::CameraStandard::SceneFeature>(type.get_value()), enabled);
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "SceneDetectionImpl::EnableSceneFeature fail %{public}d", retCode);
}

bool WhiteBalanceQueryImpl::IsWhiteBalanceModeSupported(WhiteBalanceMode mode)
{
    bool isSupported = false;
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, isSupported, "SetWhiteBalance captureSession_ is null");
    int32_t retCode = captureSession_->IsWhiteBalanceModeSupported(
        static_cast<OHOS::CameraStandard::WhiteBalanceMode>(mode.get_value()), isSupported);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), isSupported);
    return isSupported;
}

array<int32_t> WhiteBalanceQueryImpl::GetWhiteBalanceRange()
{
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, {}, "SetWhiteBalance captureSession_ is null");
    std::vector<int32_t> whiteBalanceRange = {};
    int32_t retCode = captureSession_->GetManualWhiteBalanceRange(whiteBalanceRange);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), {});
    return array<int32_t>(whiteBalanceRange);
}

void WhiteBalanceImpl::SetWhiteBalance(int32_t whiteBalance)
{
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetWhiteBalance captureSession_ is null");
    captureSession_->LockForControl();
    captureSession_->SetManualWhiteBalance(whiteBalance);
    MEDIA_INFO_LOG("WhiteBalanceImpl::SetManualWhiteBalance set wbValue:%{public}d", whiteBalance);
    captureSession_->UnlockForControl();
}

int32_t WhiteBalanceImpl::GetWhiteBalance()
{
    WhiteBalanceMode errType = WhiteBalanceMode(static_cast<WhiteBalanceMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
        errType, "GetWhiteBalanceMode captureSession_ is null");
    OHOS::CameraStandard::WhiteBalanceMode whiteBalanceMode;
    int32_t retCode = captureSession_->GetWhiteBalanceMode(whiteBalanceMode);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return WhiteBalanceMode(static_cast<WhiteBalanceMode::key_t>(whiteBalanceMode));
}

void WhiteBalanceImpl::SetWhiteBalanceMode(WhiteBalanceMode mode)
{
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetWhiteBalanceMode captureSession_ is null");
    captureSession_->LockForControl();
    captureSession_->SetWhiteBalanceMode(static_cast<OHOS::CameraStandard::WhiteBalanceMode>(mode.get_value()));
    captureSession_->UnlockForControl();
}

WhiteBalanceMode WhiteBalanceImpl::GetWhiteBalanceMode()
{
    WhiteBalanceMode errType = WhiteBalanceMode(static_cast<WhiteBalanceMode::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
        errType, "GetWhiteBalanceMode captureSession_ is null");
    OHOS::CameraStandard::WhiteBalanceMode whiteBalanceMode;
    int32_t retCode = captureSession_->GetWhiteBalanceMode(whiteBalanceMode);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), errType);
    return WhiteBalanceMode(static_cast<WhiteBalanceMode::key_t>(whiteBalanceMode));
}

array<int32_t> ManualExposureQueryImpl::GetSupportedExposureRange()
{
    if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<int32_t>(0),
            "GetSupportedExposureRange failed, cameraAbility_ is nullptr");
        std::vector<uint32_t> range;
        range = cameraAbility_->GetSupportedExposureRange();
        std::vector<int32_t> resRange;
        for (auto item : range) {
            resRange.push_back(static_cast<int32_t>(item));
        }
        return array<int32_t>(resRange);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
            "can not GetSupportedExposureRange in current session!");
        return array<int32_t>(0);
    }
}

int32_t ManualExposureImpl::GetExposure()
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not GetExposure in current session!");
    return -1;
}

void ManualExposureImpl::SetExposure(int32_t exposure)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not SetExposure in current session!");
    return;
}

array<ColorEffectType> ColorEffectQueryImpl::GetSupportedColorEffects()
{
    std::vector<OHOS::CameraStandard::ColorEffect> colorEffects;
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
            array<ColorEffectType>(nullptr, 0), "GetSupportedColorEffects captureSession_ is null");
        colorEffects = captureSession_->GetSupportedColorEffects();
        return CameraUtilsTaihe::ToTaiheArrayEnum<ColorEffectType, OHOS::CameraStandard::ColorEffect>(colorEffects);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<ColorEffectType>(nullptr, 0),
            "GetSupportedColorEffects failed, cameraAbility_ is nullptr");
            colorEffects = cameraAbility_->GetSupportedColorEffects();
        return CameraUtilsTaihe::ToTaiheArrayEnum<ColorEffectType, OHOS::CameraStandard::ColorEffect>(colorEffects);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<ColorEffectType>(nullptr, 0);
    }
}

void ColorEffectImpl::SetColorEffect(ColorEffectType type)
{
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetColorEffect captureSession_ is null");
    captureSession_->LockForControl();
    captureSession_->SetColorEffect(static_cast<OHOS::CameraStandard::ColorEffect>(type.get_value()));
    captureSession_->UnlockForControl();
}

ColorEffectType ColorEffectImpl::GetColorEffect()
{
    MEDIA_DEBUG_LOG("GetColorEffect is called");
    ColorEffectType errType = ColorEffectType(static_cast<ColorEffectType::key_t>(-1));
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, errType, "GetColorEffect captureSession_ is null");
    OHOS::CameraStandard::ColorEffect colorEffect = captureSession_->GetColorEffect();
    return ColorEffectType(static_cast<ColorEffectType::key_t>(colorEffect));
}

array<int32_t> ManualIsoQueryImpl::GetIsoRange()
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not GetIsoRange in current session!");
    return array<int32_t>(nullptr, 0);
}

bool ManualIsoQueryImpl::IsManualIsoSupported()
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not IsManualIsoSupported in current session!");
    return false;
}

void ManualIsoImpl::SetIso(int32_t iso)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not SetIso in current session!");
    return ;
}

int32_t ManualIsoImpl::GetIso()
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not GetIso in current session!");
    return -1;
}

array<PhysicalAperture> ApertureQueryImpl::GetSupportedPhysicalApertures()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<PhysicalAperture>(nullptr, 0), "SystemApi GetSupportedPhysicalApertures is called!");
    std::vector<std::vector<float>> physicalApertures = {};
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
            array<PhysicalAperture>(nullptr, 0), "GetSupportedPhysicalApertures captureSession_ is null");
        int32_t retCode = captureSession_->GetSupportedPhysicalApertures(physicalApertures);
        MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<PhysicalAperture>(nullptr, 0));
        return CameraUtilsTaihe::ToTaiheArrayPhysicalAperture(physicalApertures);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<PhysicalAperture>(nullptr, 0),
            "GetSupportedPhysicalApertures failed, cameraAbility_ is nullptr");
            physicalApertures = cameraAbility_->GetSupportedPhysicalApertures();
        return CameraUtilsTaihe::ToTaiheArrayPhysicalAperture(physicalApertures);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<PhysicalAperture>(nullptr, 0);
    }
}

array<double> ApertureQueryImpl::GetSupportedVirtualApertures()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<double>(nullptr, 0), "SystemApi GetSupportedVirtualApertures is called!");
    std::vector<float> virtualApertures = {};
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr,
            array<double>(nullptr, 0), "GetSupportedVirtualApertures captureSession_ is null");
        
        int32_t retCode = captureSession_->GetSupportedVirtualApertures(virtualApertures);
        MEDIA_INFO_LOG("GetSupportedVirtualApertures virtualApertures len = %{public}zu", virtualApertures.size());
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<double>(nullptr, 0));
        std::vector<double> doubleVec(virtualApertures.begin(), virtualApertures.end());
        return array<double>(doubleVec);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<double>(0.0),
            "GetSupportedVirtualApertures failed, cameraAbility_ is nullptr");
            virtualApertures = cameraAbility_->GetSupportedVirtualApertures();
        std::vector<double> doubleVec(virtualApertures.begin(), virtualApertures.end());
        return array<double>(doubleVec);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<double>(0.0);
    }
}

void ApertureImpl::SetVirtualAperture(double aperture)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetVirtualAperture is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "GetSupportedPhysicalApertures captureSession_ is null");
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetVirtualAperture(static_cast<float>(aperture));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

double ApertureImpl::GetVirtualAperture()
{
    float virtualAperture = -1.0;
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), virtualAperture,
        "SystemApi GetVirtualAperture is called!");
    MEDIA_DEBUG_LOG("GetVirtualAperture is called");
    CHECK_ERROR_RETURN_RET_LOG(
        captureSession_ == nullptr, virtualAperture, "GetVirtualAperture captureSession_ is null");
    int32_t retCode = captureSession_->GetVirtualAperture(virtualAperture);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), virtualAperture);
    return static_cast<double>(virtualAperture);
}

void ApertureImpl::SetPhysicalAperture(double aperture)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetPhysicalAperture is called!");
    MEDIA_DEBUG_LOG("SetPhysicalAperture is called");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetPhysicalAperture captureSession_ is null");
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetPhysicalAperture(static_cast<float>(aperture));
    MEDIA_INFO_LOG(
        "SetPhysicalAperture set physicalAperture %{public}f!", OHOS::CameraStandard::ConfusingNumber(aperture));
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

double ApertureImpl::GetPhysicalAperture()
{
    float physicalAperture = -1.0;
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), physicalAperture,
        "SystemApi GetPhysicalAperture is called!");
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
    CHECK_ERROR_RETURN_RET_LOG(
        captureSession_ == nullptr, physicalAperture, "SetPhysicalAperture captureSession_ is null");
    int32_t retCode = captureSession_->GetPhysicalAperture(physicalAperture);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), physicalAperture);
    return static_cast<double>(physicalAperture);
}

void EffectSuggestionImpl::SetEffectSuggestionStatus(array_view<EffectSuggestionStatus> status)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetEffectSuggestionStatus is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetEffectSuggestionStatus captureSession_ is null");
    std::vector<OHOS::CameraStandard::EffectSuggestionStatus> effectSuggestionStatusList;
    for (auto item : status) {
        OHOS::CameraStandard::EffectSuggestionStatus res {};
        res.status = item.status;
        res.type = static_cast<OHOS::CameraStandard::EffectSuggestionType>((item.type).get_value());
        effectSuggestionStatusList.push_back(res);
    }
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->SetEffectSuggestionStatus(effectSuggestionStatusList);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "EffectSuggestionImpl::SetEffectSuggestionStatus fail %{public}d", retCode);
}

void EffectSuggestionImpl::UpdateEffectSuggestion(EffectSuggestionType type, bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false),
        "SystemApi UpdateEffectSuggestion is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "UpdateEffectSuggestion captureSession_ is null");
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->UpdateEffectSuggestion(
        static_cast<OHOS::CameraStandard::EffectSuggestionType>(type.get_value()), enabled);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "EffectSuggestionImpl::UpdateEffectSuggestion fail %{public}d", retCode);
}

void EffectSuggestionImpl::EnableEffectSuggestion(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false),
        "SystemApi EnableEffectSuggestion is called!");
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "EnableEffectSuggestion captureSession_ is null");
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->EnableEffectSuggestion(enabled);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "EffectSuggestionImpl::EnableEffectSuggestion fail %{public}d", retCode);
}

bool EffectSuggestionImpl::IsEffectSuggestionSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsEffectSuggestionSupported is called!");
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false,
        "IsEffectSuggestionSupported captureSession_ is null");
    return captureSession_->IsEffectSuggestionSupported();
}

array<EffectSuggestionType> EffectSuggestionImpl::GetSupportedEffectSuggestionTypes()
{
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, {},
        "GetSupportedEffectSuggestionTypes captureSession_ is null");
    std::vector<OHOS::CameraStandard::EffectSuggestionType> effectSuggestionTypeList =
        captureSession_->GetSupportedEffectSuggestionType();
    return CameraUtilsTaihe::ToTaiheArrayEnum<EffectSuggestionType, OHOS::CameraStandard::EffectSuggestionType>(
        effectSuggestionTypeList);
}

bool MacroQueryImpl::IsMacroSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsMacroSupported is called!");
    if (isSessionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, false, "IsMacroSupported captureSession_ is null");
        return captureSession_->IsMacroSupported();
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsMacroSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsMacroSupported();
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

void MacroImpl::EnableMacro(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableMacro is called!");
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to EnableMacro, captureSession_ is nullptr");
        return;
    }
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->EnableMacro(enabled);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "MacroImpl::EnableMacro fail %{public}d", retCode);
}

double ManualFocusImpl::GetFocusDistance()
{
    float distance = -1.0;
    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, distance, "GetFocusDistance captureSession_ is null");
    int32_t retCode = captureSession_->GetFocusDistance(distance);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), distance);
    return static_cast<double>(distance);
}

void ManualFocusImpl::SetFocusDistance(double distance)
{
    CHECK_ERROR_RETURN_LOG(captureSession_ == nullptr, "SetFocusDistance captureSession_ is null");
    captureSession_->LockForControl();
    captureSession_->SetFocusDistance(static_cast<float>(distance));
    captureSession_->UnlockForControl();
}

array<PortraitEffect> PortraitQueryImpl::GetSupportedPortraitEffects()
{
    if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<PortraitEffect>(nullptr, 0),
            "GetSupportedPortraitEffects failed, cameraAbility_ is nullptr");
        std::vector<OHOS::CameraStandard::PortraitEffect> PortraitEffects =
            cameraAbility_->GetSupportedPortraitEffects();
        return CameraUtilsTaihe::ToTaiheArrayEnum<PortraitEffect, OHOS::CameraStandard::PortraitEffect>(
            PortraitEffects);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
            "can not GetSupportedPortraitEffects in current session!");
        return array<PortraitEffect>(nullptr, 0);
    }
}

void PortraitImpl::SetPortraitEffect(PortraitEffect effect)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not SetPortraitEffect in current session!");
}

PortraitEffect PortraitImpl::GetPortraitEffect()
{
    PortraitEffect errType = PortraitEffect(static_cast<PortraitEffect::key_t>(-1));
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED,
        "can not GetPortraitEffect in current session!");
    return errType;
}

bool DepthFusionQueryImpl::IsDepthFusionSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDepthFusionSupported is called!");
    if (isSessionBase_) {
        if (captureSession_ == nullptr) {
            CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
                "failed to IsDepthFusionSupported, captureSession_ is nullptr");
            return false;
        }
        return captureSession_->IsDepthFusionEnabled();
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, false,
            "IsDepthFusionSupported failed, cameraAbility_ is nullptr");
        return cameraAbility_->IsDepthFusionSupported();
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return false;
    }
}

array<double> DepthFusionQueryImpl::GetDepthFusionThreshold()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<double>(0.0), "SystemApi GetDepthFusionThreshold is called!");
    std::vector<float> vecDepthFusionThreshold;
    if (isSessionBase_) {
        if (captureSession_ == nullptr) {
            CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
                "failed to GetDepthFusionThreshold, captureSession_ is nullptr");
            return array<double>(0.0);
        }
        int32_t retCode = captureSession_->GetDepthFusionThreshold(vecDepthFusionThreshold);
        CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<double>(0.0));
        std::vector<double> doubleVec(vecDepthFusionThreshold.begin(), vecDepthFusionThreshold.end());
        return array<double>(doubleVec);
    } else if (isFunctionBase_) {
        CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, array<double>(0.0),
            "GetDepthFusionThreshold failed, cameraAbility_ is nullptr");
            vecDepthFusionThreshold = cameraAbility_->GetDepthFusionThreshold();
        std::vector<double> doubleVec(vecDepthFusionThreshold.begin(), vecDepthFusionThreshold.end());
        return array<double>(doubleVec);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::OPERATION_NOT_ALLOWED, "static binding failed");
        return array<double>(0.0);
    }
}

void DepthFusionImpl::EnableDepthFusion(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableDepthFusion is called!");
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to EnableDepthFusion, captureSession_ is nullptr");
        return;
    }
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->EnableDepthFusion(enabled);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "DepthFusionImpl::EnableDepthFusion fail %{public}d", retCode);
}

bool DepthFusionImpl::IsDepthFusionEnabled()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDepthFusionEnabled is called!");
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to IsDepthFusionEnabled, captureSession_ is nullptr");
        return false;
    }
    return captureSession_->IsDepthFusionEnabled();
}

bool AutoDeviceSwitchQueryImpl::IsAutoDeviceSwitchSupported()
{
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to IsAutoDeviceSwitchSupported, captureSession_ is nullptr");
        return false;
    }
    return captureSession_->IsAutoDeviceSwitchSupported();
}

void AutoDeviceSwitchImpl::EnableAutoDeviceSwitch(bool enabled)
{
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "failed to EnableAutoDeviceSwitch, captureSession_ is nullptr");
        return;
    }
    captureSession_->LockForControl();
    int32_t retCode = captureSession_->EnableAutoDeviceSwitch(enabled);
    captureSession_->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "AutoDeviceSwitchImpl::EnableAutoDeviceSwitch fail %{public}d", retCode);
}
} // namespace Ani
} // namespace Camera