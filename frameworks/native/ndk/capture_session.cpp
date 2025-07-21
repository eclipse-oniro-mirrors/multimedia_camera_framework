/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "kits/native/include/camera/capture_session.h"
#include "camera.h"
#include "impl/capture_session_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

Camera_ErrorCode OH_CaptureSession_RegisterCallback(Camera_CaptureSession* session, CaptureSession_Callbacks* callback)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    CHECK_RETURN_RET_ELOG(callback->onFocusStateChange == nullptr && callback->onError == nullptr,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, callback onFocusStateChange and onError are null!");

    session->RegisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_UnregisterCallback(Camera_CaptureSession* session,
    CaptureSession_Callbacks* callback)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    CHECK_RETURN_RET_ELOG(callback->onFocusStateChange == nullptr && callback->onError == nullptr,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, callback onFocusStateChange and onError are null!");

    session->UnregisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_RegisterSmoothZoomInfoCallback(Camera_CaptureSession* session,
    OH_CaptureSession_OnSmoothZoomInfo smoothZoomInfoCallback)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(smoothZoomInfoCallback == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->RegisterSmoothZoomInfoCallback(smoothZoomInfoCallback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_UnregisterSmoothZoomInfoCallback(Camera_CaptureSession* session,
    OH_CaptureSession_OnSmoothZoomInfo smoothZoomInfoCallback)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(smoothZoomInfoCallback == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->UnregisterSmoothZoomInfoCallback(smoothZoomInfoCallback);
    return CAMERA_OK;
}

/**
 * @since 20
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_RegisterSystemPressureLevelChangeCallback(Camera_CaptureSession* session,
    OH_CaptureSession_OnSystemPressureLevelChange systemPressureLevel)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(systemPressureLevel == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->RegisterSystemPressureLevelCallback(systemPressureLevel);
    return CAMERA_OK;
}

/**
 * @since 20
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_UnregisterSystemPressureLevelChangeCallback(Camera_CaptureSession* session,
    OH_CaptureSession_OnSystemPressureLevelChange systemPressureLevel)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(systemPressureLevel == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->UnRegisterSystemPressureLevelCallback(systemPressureLevel);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_SetSessionMode(Camera_CaptureSession* session, Camera_SceneMode sceneMode)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->SetSessionMode(sceneMode);
}

Camera_ErrorCode OH_CaptureSession_AddSecureOutput(Camera_CaptureSession* session, Camera_PreviewOutput* previewOutput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(previewOutput == nullptr,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, previewOutput is null!");
    return session->AddSecureOutput(previewOutput);
}

Camera_ErrorCode OH_CaptureSession_BeginConfig(Camera_CaptureSession* session)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->BeginConfig();
}

Camera_ErrorCode OH_CaptureSession_CommitConfig(Camera_CaptureSession* session)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->CommitConfig();
}

Camera_ErrorCode OH_CaptureSession_AddInput(Camera_CaptureSession* session, Camera_Input* cameraInput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");

    return session->AddInput(cameraInput);
}

Camera_ErrorCode OH_CaptureSession_RemoveInput(Camera_CaptureSession* session, Camera_Input* cameraInput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");

    return session->RemoveInput(cameraInput);
}

Camera_ErrorCode OH_CaptureSession_AddPreviewOutput(Camera_CaptureSession* session,
    Camera_PreviewOutput* previewOutput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(previewOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, previewOutput is null!");

    return session->AddPreviewOutput(previewOutput);
}

Camera_ErrorCode OH_CaptureSession_RemovePreviewOutput(Camera_CaptureSession* session,
    Camera_PreviewOutput* previewOutput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(previewOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, previewOutput is null!");

    return session->RemovePreviewOutput(previewOutput);
}

Camera_ErrorCode OH_CaptureSession_AddPhotoOutput(Camera_CaptureSession* session, Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_AddPhotoOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, photoOutput is null!");

    return session->AddPhotoOutput(photoOutput);
}

Camera_ErrorCode OH_CaptureSession_RemovePhotoOutput(Camera_CaptureSession* session, Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_RemovePhotoOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, photoOutput is null!");

    return session->RemovePhotoOutput(photoOutput);
}

Camera_ErrorCode OH_CaptureSession_AddMetadataOutput(Camera_CaptureSession* session,
    Camera_MetadataOutput* metadataOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_AddMetadataOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(metadataOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, metadataOutput is null!");

    return session->AddMetaDataOutput(metadataOutput);
}

Camera_ErrorCode OH_CaptureSession_RemoveMetadataOutput(Camera_CaptureSession* session,
    Camera_MetadataOutput* metadataOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_RemoveMetadataOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(metadataOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, metadataOutput is null!");

    return session->RemoveMetaDataOutput(metadataOutput);
}

Camera_ErrorCode OH_CaptureSession_IsVideoStabilizationModeSupported(Camera_CaptureSession* session,
    Camera_VideoStabilizationMode mode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsVideoStabilizationModeSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(isSupported == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSupported is null!");
    CHECK_RETURN_RET_ELOG(mode != STABILIZATION_MODE_OFF &&
        mode != STABILIZATION_MODE_LOW &&
        mode != STABILIZATION_MODE_MIDDLE &&
        mode != STABILIZATION_MODE_HIGH &&
        mode != STABILIZATION_MODE_AUTO,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, mode is invaid!");

    return session->IsVideoStabilizationModeSupported(mode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetVideoStabilizationMode(Camera_CaptureSession* session,
    Camera_VideoStabilizationMode* mode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetVideoStabilizationMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(mode == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, mode is null!");

    return session->GetVideoStabilizationMode(mode);
}

Camera_ErrorCode OH_CaptureSession_SetVideoStabilizationMode(Camera_CaptureSession* session,
    Camera_VideoStabilizationMode mode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetVideoStabilizationMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(mode != STABILIZATION_MODE_OFF &&
        mode != STABILIZATION_MODE_LOW &&
        mode != STABILIZATION_MODE_MIDDLE &&
        mode != STABILIZATION_MODE_HIGH &&
        mode != STABILIZATION_MODE_AUTO,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, mode is invaid!");

    return session->SetVideoStabilizationMode(mode);
}

Camera_ErrorCode OH_CaptureSession_GetZoomRatioRange(Camera_CaptureSession* session, float* minZoom, float* maxZoom)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetZoomRatioRange is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(minZoom == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, minZoom is null!");
    CHECK_RETURN_RET_ELOG(maxZoom == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, maxZoom is null!");

    return session->GetZoomRatioRange(minZoom, maxZoom);
}

Camera_ErrorCode OH_CaptureSession_GetZoomRatio(Camera_CaptureSession* session, float* zoom)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetZoomRatio is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(zoom == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, zoom is null!");

    return session->GetZoomRatio(zoom);
}

Camera_ErrorCode OH_CaptureSession_SetZoomRatio(Camera_CaptureSession* session, float zoom)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetZoomRatio is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->SetZoomRatio(zoom);
}

Camera_ErrorCode OH_CaptureSession_IsFocusModeSupported(Camera_CaptureSession* session,
    Camera_FocusMode focusMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsFocusModeSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(focusMode != FOCUS_MODE_MANUAL &&
        focusMode != FOCUS_MODE_CONTINUOUS_AUTO &&
        focusMode != FOCUS_MODE_AUTO &&
        focusMode != FOCUS_MODE_LOCKED,
        CAMERA_INVALID_ARGUMENT, "Invalid argument,focusMode is invaild!");
    CHECK_RETURN_RET_ELOG(isSupported == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSupported is null!");

    return session->IsFocusModeSupported(focusMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetFocusMode(Camera_CaptureSession* session, Camera_FocusMode* focusMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetFocusMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(focusMode == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, focusMode is null!");

    return session->GetFocusMode(focusMode);
}

Camera_ErrorCode OH_CaptureSession_SetFocusMode(Camera_CaptureSession* session, Camera_FocusMode focusMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetFocusMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(focusMode != FOCUS_MODE_MANUAL &&
        focusMode != FOCUS_MODE_CONTINUOUS_AUTO &&
        focusMode != FOCUS_MODE_AUTO &&
        focusMode != FOCUS_MODE_LOCKED,
        CAMERA_INVALID_ARGUMENT, "Invalid argument,focusMode is invaild!");

    return session->SetFocusMode(focusMode);
}

Camera_ErrorCode OH_CaptureSession_SetFocusPoint(Camera_CaptureSession* session, Camera_Point focusPoint)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetFocusPoint is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->SetFocusPoint(focusPoint);
}

Camera_ErrorCode OH_CaptureSession_GetFocusPoint(Camera_CaptureSession* session, Camera_Point* focusPoint)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetFocusPoint is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(focusPoint == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, focusPoint is null!");

    return session->GetFocusPoint(focusPoint);
}

Camera_ErrorCode OH_CaptureSession_AddVideoOutput(Camera_CaptureSession* session, Camera_VideoOutput* videoOutput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(videoOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, videoOutput is null!");

    return session->AddVideoOutput(videoOutput);
}

Camera_ErrorCode OH_CaptureSession_RemoveVideoOutput(Camera_CaptureSession* session, Camera_VideoOutput* videoOutput)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(videoOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, videoOutput is null!");

    return session->RemoveVideoOutput(videoOutput);
}

Camera_ErrorCode OH_CaptureSession_Start(Camera_CaptureSession* session)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->Start();
}

Camera_ErrorCode OH_CaptureSession_Stop(Camera_CaptureSession* session)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->Stop();
}

Camera_ErrorCode OH_CaptureSession_Release(Camera_CaptureSession* session)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    Camera_ErrorCode retCode = session->Release();
    if (session != nullptr) {
        delete session;
    }
    return retCode;
}

Camera_ErrorCode OH_CaptureSession_HasFlash(Camera_CaptureSession* session, bool* hasFlash)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(hasFlash == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, hasFlash is null!");

    return session->HasFlash(hasFlash);
}

Camera_ErrorCode OH_CaptureSession_IsFlashModeSupported(Camera_CaptureSession* session,
    Camera_FlashMode flashMode, bool* isSupported)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(isSupported == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSupported is null!");

    return session->IsFlashModeSupported(flashMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetFlashMode(Camera_CaptureSession* session, Camera_FlashMode* flashMode)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(flashMode == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, flashMode is null!");

    return session->GetFlashMode(flashMode);
}

Camera_ErrorCode OH_CaptureSession_SetFlashMode(Camera_CaptureSession* session, Camera_FlashMode flashMode)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(flashMode != FLASH_MODE_CLOSE &&
        flashMode != FLASH_MODE_OPEN &&
        flashMode != FLASH_MODE_AUTO &&
        flashMode != FLASH_MODE_ALWAYS_OPEN,
        CAMERA_INVALID_ARGUMENT, "Invalid argument,flashMode is invaild!");
    return session->SetFlashMode(flashMode);
}

Camera_ErrorCode OH_CaptureSession_IsExposureModeSupported(Camera_CaptureSession* session,
    Camera_ExposureMode exposureMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsExposureModeSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(isSupported == nullptr,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, isSupported is null!");
    CHECK_RETURN_RET_ELOG(exposureMode != EXPOSURE_MODE_LOCKED &&
        exposureMode != EXPOSURE_MODE_AUTO &&
        exposureMode != EXPOSURE_MODE_CONTINUOUS_AUTO,
        CAMERA_INVALID_ARGUMENT, "Invalid argument,exposureMode is invaild!");
    return session->IsExposureModeSupported(exposureMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetExposureMode(Camera_CaptureSession* session, Camera_ExposureMode* exposureMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(exposureMode == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, exposureMode is null!");
    return session->GetExposureMode(exposureMode);
}

Camera_ErrorCode OH_CaptureSession_SetExposureMode(Camera_CaptureSession* session, Camera_ExposureMode exposureMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetExposureMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(exposureMode != EXPOSURE_MODE_LOCKED &&
        exposureMode != EXPOSURE_MODE_AUTO &&
        exposureMode != EXPOSURE_MODE_CONTINUOUS_AUTO,
        CAMERA_INVALID_ARGUMENT, "Invalid argument,exposureMode is invaild!");

    return session->SetExposureMode(exposureMode);
}

Camera_ErrorCode OH_CaptureSession_GetMeteringPoint(Camera_CaptureSession* session, Camera_Point* point)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetMeteringPoint is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(point == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, point is null!");
    return session->GetMeteringPoint(point);
}

Camera_ErrorCode OH_CaptureSession_SetMeteringPoint(Camera_CaptureSession* session, Camera_Point point)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetMeteringPoint is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(point.x < 0 || point.y < 0,
        CAMERA_INVALID_ARGUMENT, "Invalid argument, point is invaild!");

    return session->SetMeteringPoint(point);
}

Camera_ErrorCode OH_CaptureSession_GetExposureBiasRange(Camera_CaptureSession* session,
    float* minExposureBias, float* maxExposureBias, float* step)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureBiasRange is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(minExposureBias == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, minExposureBias is null!");
    CHECK_RETURN_RET_ELOG(maxExposureBias == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, maxExposureBias is null!");
    CHECK_RETURN_RET_ELOG(step == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, step is null!");
    return session->GetExposureBiasRange(minExposureBias, maxExposureBias, step);
}

Camera_ErrorCode OH_CaptureSession_SetExposureBias(Camera_CaptureSession* session, float exposureBias)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetExposureBias is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->SetExposureBias(exposureBias);
}
Camera_ErrorCode OH_CaptureSession_GetExposureBias(Camera_CaptureSession* session, float* exposureBias)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureBias is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(exposureBias == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, exposureBias is null!");
    return session->GetExposureBias(exposureBias);
}

Camera_ErrorCode OH_CaptureSession_CanAddInput(Camera_CaptureSession* session,
    Camera_Input* cameraInput, bool* isSuccessful)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_CanAddInput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(isSuccessful == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSuccessful is null!");

    return session->CanAddInput(cameraInput, isSuccessful);
}

Camera_ErrorCode OH_CaptureSession_CanAddPreviewOutput(Camera_CaptureSession* session,
    Camera_PreviewOutput* cameraOutput, bool* isSuccessful)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_CanAddPreviewOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(cameraOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutput is null!");
    CHECK_RETURN_RET_ELOG(isSuccessful == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSuccessful is null!");

    return session->CanAddPreviewOutput(cameraOutput, isSuccessful);
}

Camera_ErrorCode OH_CaptureSession_CanAddPhotoOutput(Camera_CaptureSession* session,
    Camera_PhotoOutput* cameraOutput, bool* isSuccessful)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_CanAddPhotoOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(cameraOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutput is null!");
    CHECK_RETURN_RET_ELOG(isSuccessful == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSuccessful is null!");

    return session->CanAddPhotoOutput(cameraOutput, isSuccessful);
}

Camera_ErrorCode OH_CaptureSession_CanAddVideoOutput(Camera_CaptureSession* session,
    Camera_VideoOutput* cameraOutput, bool* isSuccessful)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_CanAddVideoOutput is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(cameraOutput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutput is null!");
    CHECK_RETURN_RET_ELOG(isSuccessful == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isSuccessful is null!");

    return session->CanAddVideoOutput(cameraOutput, isSuccessful);
}

Camera_ErrorCode OH_CaptureSession_CanPreconfig(Camera_CaptureSession* session,
    Camera_PreconfigType preconfigType, bool* canPreconfig)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_CanPreconfig is called.");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(canPreconfig == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, canPreconfig is null!");

    return session->CanPreconfig(preconfigType, canPreconfig);
}

Camera_ErrorCode OH_CaptureSession_CanPreconfigWithRatio(Camera_CaptureSession* session,
    Camera_PreconfigType preconfigType, Camera_PreconfigRatio preconfigRatio, bool* canPreconfig)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_CanPreconfigWithRatio is called.");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(canPreconfig == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, canPreconfig is null!");

    return session->CanPreconfigWithRatio(preconfigType, preconfigRatio, canPreconfig);
}

Camera_ErrorCode OH_CaptureSession_Preconfig(Camera_CaptureSession* session, Camera_PreconfigType preconfigType)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_Preconfig is called.");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");

    return session->Preconfig(preconfigType);
}

Camera_ErrorCode OH_CaptureSession_PreconfigWithRatio(Camera_CaptureSession* session,
    Camera_PreconfigType preconfigType, Camera_PreconfigRatio preconfigRatio)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_PreconfigWithRatio is called.");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");

    return session->PreconfigWithRatio(preconfigType, preconfigRatio);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_GetExposureValue(Camera_CaptureSession* session, float* exposureValue)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureValue is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(exposureValue == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, exposureValue is null!");

    return session->GetExposureValue(exposureValue);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_GetFocalLength(Camera_CaptureSession* session, float* focalLength)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetFocalLength is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(focalLength == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, focalLength is null!");

    return session->GetFocalLength(focalLength);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_SetSmoothZoom(Camera_CaptureSession *session, float targetZoom,
    Camera_SmoothZoomMode smoothZoomMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetSmoothZoom is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");

    return session->SetSmoothZoom(targetZoom, smoothZoomMode);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_GetSupportedColorSpaces(Camera_CaptureSession* session,
    OH_NativeBuffer_ColorSpace** colorSpace, uint32_t* size)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetSupportedColorSpaces is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(colorSpace == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, colorSpace is null!");
    CHECK_RETURN_RET_ELOG(size == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, size is null!");

    return session->GetSupportedColorSpaces(colorSpace, size);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_DeleteColorSpaces(Camera_CaptureSession* session,
    OH_NativeBuffer_ColorSpace* colorSpace)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_DeleteSupportedColorSpaces is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(colorSpace == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, colorSpace is null!");

    return session->DeleteColorSpaces(colorSpace);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_GetActiveColorSpace(Camera_CaptureSession* session,
    OH_NativeBuffer_ColorSpace* colorSpace)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetActiveColorSpace is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(colorSpace == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, colorSpace is null!");

    return session->GetActiveColorSpace(colorSpace);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_SetActiveColorSpace(Camera_CaptureSession* session,
    OH_NativeBuffer_ColorSpace colorSpace)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetActiveColorSpace is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");

    return session->SetActiveColorSpace(colorSpace);
}

/**
 * @since 13
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_RegisterAutoDeviceSwitchStatusCallback(Camera_CaptureSession* session,
    OH_CaptureSession_OnAutoDeviceSwitchStatusChange autoDeviceSwitchStatusChange)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(autoDeviceSwitchStatusChange == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->RegisterAutoDeviceSwitchStatusCallback(autoDeviceSwitchStatusChange);
    return CAMERA_OK;
}

/**
 * @since 13
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_UnregisterAutoDeviceSwitchStatusCallback(Camera_CaptureSession* session,
    OH_CaptureSession_OnAutoDeviceSwitchStatusChange autoDeviceSwitchStatusChange)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(autoDeviceSwitchStatusChange == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->UnregisterAutoDeviceSwitchStatusCallback(autoDeviceSwitchStatusChange);
    return CAMERA_OK;
}

/**
 * @since 13
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_IsAutoDeviceSwitchSupported(Camera_CaptureSession* session, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsAutoDeviceSwitchSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    return session->IsAutoDeviceSwitchSupported(isSupported);
}

/**
 * @since 13
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_EnableAutoDeviceSwitch(Camera_CaptureSession* session, bool enabled)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_EnableAutoDeviceSwitch is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    return session->EnableAutoDeviceSwitch(enabled);
}

/**
 * @since 14
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_SetQualityPrioritization(
    Camera_CaptureSession* session, Camera_QualityPrioritization qualityPrioritization)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetQualityPrioritization is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");

    return session->SetQualityPrioritization(qualityPrioritization);
}

/**
 * @since 17
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_IsMacroSupported(Camera_CaptureSession* session, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsMacroSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->IsMacroSupported(isSupported);
}

/**
 * @since 17
 * @version 1.0
 */
Camera_ErrorCode OH_CaptureSession_EnableMacro(Camera_CaptureSession* session, bool enabled)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_EnableMacro is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->EnableMacro(enabled);
}

Camera_ErrorCode OH_CaptureSession_IsWhiteBalanceModeSupported(
    Camera_CaptureSession* session, Camera_WhiteBalanceMode whiteBalanceMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsWhiteBalanceModeSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");

    return session->IsWhiteBalanceModeSupported(whiteBalanceMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetWhiteBalanceMode(
    Camera_CaptureSession* session, Camera_WhiteBalanceMode* whiteBalanceMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetWhiteBalanceMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");

    return session->GetWhiteBalanceMode(whiteBalanceMode);
}

Camera_ErrorCode OH_CaptureSession_GetWhiteBalanceRange(Camera_CaptureSession* session, int32_t *minColorTemperature,
     int32_t *maxColorTemperature)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetWhiteBalanceRange is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->GetWhiteBalanceRange(minColorTemperature, maxColorTemperature);
}

Camera_ErrorCode OH_CaptureSession_GetWhiteBalance(Camera_CaptureSession* session, int32_t *colorTemperature)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetWhiteBalance is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->GetWhiteBalance(colorTemperature);
}

Camera_ErrorCode OH_CaptureSession_SetWhiteBalance(Camera_CaptureSession* session, int32_t colorTemperature)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetWhiteBalance is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->SetWhiteBalance(colorTemperature);
}

Camera_ErrorCode OH_CaptureSession_SetWhiteBalanceMode(Camera_CaptureSession* session,
    Camera_WhiteBalanceMode whiteBalanceMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetWhiteBalanceMode is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    return session->SetWhiteBalanceMode(whiteBalanceMode);
}

Camera_ErrorCode OH_CaptureSession_IsControlCenterSupported(Camera_CaptureSession* session, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsControlCenterSupported is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    return session->IsControlCenterSupported(isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetSupportedEffectTypes(
    Camera_CaptureSession* session, Camera_ControlCenterEffectType** types, uint32_t* size)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetSupportedEffectTypes is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(types == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, types is null!");
    CHECK_RETURN_RET_ELOG(size == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, size is null!");

    return session->GetSupportedEffectTypes(types, size);
}

Camera_ErrorCode OH_CaptureSession_DeleteSupportedEffectTypes(Camera_CaptureSession* session,
    Camera_ControlCenterEffectType* types, uint32_t size)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_DeleteSupportedEffectTypes is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(types == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, colorSpace is null!");

    return session->DeleteEffectTypes(types);
}

Camera_ErrorCode OH_CaptureSession_EnableControlCenter(Camera_CaptureSession* session, bool enabled)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_EnableControlCenter is called");
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, session is null!");
    return session->EnableControlCenter(enabled);
}

Camera_ErrorCode OH_CaptureSession_RegisterControlCenterEffectStatusChangeCallback(
    Camera_CaptureSession* session,
    OH_CaptureSession_OnControlCenterEffectStatusChange controlCenterEffectStatusChange)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(controlCenterEffectStatusChange == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->RegisterControlCenterEffectStatusChangeCallback(controlCenterEffectStatusChange);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_UnregisterControlCenterEffectStatusChangeCallback(
    Camera_CaptureSession* session,
    OH_CaptureSession_OnControlCenterEffectStatusChange controlCenterEffectStatusChange)
{
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, session is null!");
    CHECK_RETURN_RET_ELOG(controlCenterEffectStatusChange == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    session->UnregisterControlCenterEffectStatusChangeCallback(controlCenterEffectStatusChange);
    return CAMERA_OK;
}

#ifdef __cplusplus
}
#endif
