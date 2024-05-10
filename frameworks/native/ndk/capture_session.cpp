/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "impl/capture_session_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

Camera_ErrorCode OH_CaptureSession_RegisterCallback(Camera_CaptureSession* session, CaptureSession_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFocusStateChange!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFocusStateChange is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    session->RegisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_UnregisterCallback(Camera_CaptureSession* session,
    CaptureSession_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFocusStateChange!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFocusStateChange is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    session->UnregisterCallback(callback);
    return CAMERA_OK;
}
Camera_ErrorCode OH_CaptureSession_SetSessionMode(Camera_CaptureSession* session, Camera_SceneMode sceneMode)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    session->SetSessionMode(sceneMode);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_AddSecureOutput(Camera_CaptureSession* session, Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    session->AddSecureOutput(previewOutput);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CaptureSession_BeginConfig(Camera_CaptureSession* session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->BeginConfig();
}

Camera_ErrorCode OH_CaptureSession_CommitConfig(Camera_CaptureSession* session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->CommitConfig();
}

Camera_ErrorCode OH_CaptureSession_AddInput(Camera_CaptureSession* session, Camera_Input* cameraInput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");

    return session->AddInput(cameraInput);
}

Camera_ErrorCode OH_CaptureSession_RemoveInput(Camera_CaptureSession* session, Camera_Input* cameraInput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");

    return session->RemoveInput(cameraInput);
}

Camera_ErrorCode OH_CaptureSession_AddPreviewOutput(Camera_CaptureSession* session,
    Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");

    return session->AddPreviewOutput(previewOutput);
}

Camera_ErrorCode OH_CaptureSession_RemovePreviewOutput(Camera_CaptureSession* session,
    Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");

    return session->RemovePreviewOutput(previewOutput);
}

Camera_ErrorCode OH_CaptureSession_AddPhotoOutput(Camera_CaptureSession* session, Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_AddPhotoOutput is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");

    return session->AddPhotoOutput(photoOutput);
}

Camera_ErrorCode OH_CaptureSession_RemovePhotoOutput(Camera_CaptureSession* session, Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_RemovePhotoOutput is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");

    return session->RemovePhotoOutput(photoOutput);
}

Camera_ErrorCode OH_CaptureSession_AddMetadataOutput(Camera_CaptureSession* session,
    Camera_MetadataOutput* metadataOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_AddMetadataOutput is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, metadataOutput is null!");

    return session->AddMetaDataOutput(metadataOutput);
}

Camera_ErrorCode OH_CaptureSession_RemoveMetadataOutput(Camera_CaptureSession* session,
    Camera_MetadataOutput* metadataOutput)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_RemoveMetadataOutput is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, metadataOutput is null!");

    return session->RemoveMetaDataOutput(metadataOutput);
}

Camera_ErrorCode OH_CaptureSession_IsVideoStabilizationModeSupported(Camera_CaptureSession* session,
    Camera_VideoStabilizationMode mode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsVideoStabilizationModeSupported is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(isSupported != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, isSupported is null!");

    return session->IsVideoStabilizationModeSupported(mode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetVideoStabilizationMode(Camera_CaptureSession* session,
    Camera_VideoStabilizationMode* mode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetVideoStabilizationMode is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(mode != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, mode is null!");

    return session->GetVideoStabilizationMode(mode);
}

Camera_ErrorCode OH_CaptureSession_SetVideoStabilizationMode(Camera_CaptureSession* session,
    Camera_VideoStabilizationMode mode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetVideoStabilizationMode is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->SetVideoStabilizationMode(mode);
}

Camera_ErrorCode OH_CaptureSession_GetZoomRatioRange(Camera_CaptureSession* session, float* minZoom, float* maxZoom)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetZoomRatioRange is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(minZoom != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, minZoom is null!");
    CHECK_AND_RETURN_RET_LOG(maxZoom != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, maxZoom is null!");

    return session->GetZoomRatioRange(minZoom, maxZoom);
}

Camera_ErrorCode OH_CaptureSession_GetZoomRatio(Camera_CaptureSession* session, float* zoom)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetZoomRatio is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(zoom != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, zoom is null!");

    return session->GetZoomRatio(zoom);
}

Camera_ErrorCode OH_CaptureSession_SetZoomRatio(Camera_CaptureSession* session, float zoom)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetZoomRatio is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->SetZoomRatio(zoom);
}

Camera_ErrorCode OH_CaptureSession_IsFocusModeSupported(Camera_CaptureSession* session,
    Camera_FocusMode focusMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsFocusModeSupported is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(isSupported != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, isSupported is null!");

    return session->IsFocusModeSupported(focusMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetFocusMode(Camera_CaptureSession* session, Camera_FocusMode* focusMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetFocusMode is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(focusMode != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, focusMode is null!");

    return session->GetFocusMode(focusMode);
}

Camera_ErrorCode OH_CaptureSession_SetFocusMode(Camera_CaptureSession* session, Camera_FocusMode focusMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetFocusMode is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->SetFocusMode(focusMode);
}

Camera_ErrorCode OH_CaptureSession_SetFocusPoint(Camera_CaptureSession* session, Camera_Point focusPoint)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetFocusPoint is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->SetFocusPoint(focusPoint);
}

Camera_ErrorCode OH_CaptureSession_GetFocusPoint(Camera_CaptureSession* session, Camera_Point* focusPoint)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetFocusPoint is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(focusPoint != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, focusPoint is null!");

    return session->GetFocusPoint(focusPoint);
}

Camera_ErrorCode OH_CaptureSession_AddVideoOutput(Camera_CaptureSession* session, Camera_VideoOutput* videoOutput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");

    return session->AddVideoOutput(videoOutput);
}

Camera_ErrorCode OH_CaptureSession_RemoveVideoOutput(Camera_CaptureSession* session, Camera_VideoOutput* videoOutput)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");

    return session->RemoveVideoOutput(videoOutput);
}

Camera_ErrorCode OH_CaptureSession_Start(Camera_CaptureSession* session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->Start();
}

Camera_ErrorCode OH_CaptureSession_Stop(Camera_CaptureSession* session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->Stop();
}

Camera_ErrorCode OH_CaptureSession_Release(Camera_CaptureSession* session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    Camera_ErrorCode retCode = session->Release();
    if (session != nullptr) {
        delete session;
    }
    return retCode;
}

Camera_ErrorCode OH_CaptureSession_HasFlash(Camera_CaptureSession* session, bool* hasFlash)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(hasFlash != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, hasFlash is null!");

    return session->HasFlash(hasFlash);
}

Camera_ErrorCode OH_CaptureSession_IsFlashModeSupported(Camera_CaptureSession* session,
    Camera_FlashMode flashMode, bool* isSupported)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(isSupported != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, isSupported is null!");

    return session->IsFlashModeSupported(flashMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetFlashMode(Camera_CaptureSession* session, Camera_FlashMode* flashMode)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(flashMode != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, flashMode is null!");

    return session->GetFlashMode(flashMode);
}

Camera_ErrorCode OH_CaptureSession_SetFlashMode(Camera_CaptureSession* session, Camera_FlashMode flashMode)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");

    return session->SetFlashMode(flashMode);
}

Camera_ErrorCode OH_CaptureSession_IsExposureModeSupported(Camera_CaptureSession* session,
    Camera_ExposureMode exposureMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_IsExposureModeSupported is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(isSupported != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, isSupported is null!");
    return session->IsExposureModeSupported(exposureMode, isSupported);
}

Camera_ErrorCode OH_CaptureSession_GetExposureMode(Camera_CaptureSession* session, Camera_ExposureMode* exposureMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureMode is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(exposureMode != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, exposureMode is null!");
    return session->GetExposureMode(exposureMode);
}

Camera_ErrorCode OH_CaptureSession_SetExposureMode(Camera_CaptureSession* session, Camera_ExposureMode exposureMode)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetExposureMode is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    return session->SetExposureMode(exposureMode);
}

Camera_ErrorCode OH_CaptureSession_GetMeteringPoint(Camera_CaptureSession* session, Camera_Point* point)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetMeteringPoint is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(point != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, point is null!");
    return session->GetMeteringPoint(point);
}

Camera_ErrorCode OH_CaptureSession_SetMeteringPoint(Camera_CaptureSession* session, Camera_Point point)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetMeteringPoint is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    return session->SetMeteringPoint(point);
}

Camera_ErrorCode OH_CaptureSession_GetExposureBiasRange(Camera_CaptureSession* session,
    float* minExposureBias, float* maxExposureBias, float* step)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureBiasRange is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(minExposureBias != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, minExposureBias is null!");
    CHECK_AND_RETURN_RET_LOG(maxExposureBias != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, maxExposureBias is null!");
    CHECK_AND_RETURN_RET_LOG(step != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, step is null!");
    return session->GetExposureBiasRange(minExposureBias, maxExposureBias, step);
}

Camera_ErrorCode OH_CaptureSession_SetExposureBias(Camera_CaptureSession* session, float exposureBias)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_SetExposureBias is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    return session->SetExposureBias(exposureBias);
}
Camera_ErrorCode OH_CaptureSession_GetExposureBias(Camera_CaptureSession* session, float* exposureBias)
{
    MEDIA_DEBUG_LOG("OH_CaptureSession_GetExposureBias is called");
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_INVALID_ARGUMENT, "Invaild argument, session is null!");
    CHECK_AND_RETURN_RET_LOG(exposureBias != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, exposureBias is null!");
    return session->GetExposureBias(exposureBias);
}

#ifdef __cplusplus
}
#endif