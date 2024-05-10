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

#ifndef OHOS_CAPTURE_SESSION_IMPL_H
#define OHOS_CAPTURE_SESSION_IMPL_H

#include "kits/native/include/camera/camera.h"
#include "kits/native/include/camera/capture_session.h"
#include "session/capture_session.h"
#include "camera_input_impl.h"
#include "preview_output_impl.h"
#include "video_output_impl.h"
#include "photo_output_impl.h"
#include "metadata_output_impl.h"

struct Camera_CaptureSession {
public:
    explicit Camera_CaptureSession(OHOS::sptr<OHOS::CameraStandard::CaptureSession> &innerCaptureSession);
    ~Camera_CaptureSession();

    Camera_ErrorCode RegisterCallback(CaptureSession_Callbacks* callback);

    Camera_ErrorCode UnregisterCallback(CaptureSession_Callbacks* callback);

    Camera_ErrorCode SetSessionMode(Camera_SceneMode sceneMode);

    Camera_ErrorCode AddSecureOutput(Camera_PreviewOutput* previewOutput);

    Camera_ErrorCode BeginConfig();

    Camera_ErrorCode CommitConfig();

    Camera_ErrorCode AddInput(Camera_Input* cameraInput);

    Camera_ErrorCode RemoveInput(Camera_Input* cameraInput);

    Camera_ErrorCode AddPreviewOutput(Camera_PreviewOutput* previewOutput);

    Camera_ErrorCode RemovePreviewOutput(Camera_PreviewOutput* previewOutput);

    Camera_ErrorCode AddPhotoOutput(Camera_PhotoOutput* photoOutput);

    Camera_ErrorCode RemovePhotoOutput(Camera_PhotoOutput* photoOutput);

    Camera_ErrorCode AddVideoOutput(Camera_VideoOutput* videoOutput);

    Camera_ErrorCode RemoveVideoOutput(Camera_VideoOutput* videoOutput);

    Camera_ErrorCode AddMetaDataOutput(Camera_MetadataOutput* metadataOutput);

    Camera_ErrorCode RemoveMetaDataOutput(Camera_MetadataOutput* metadataOutput);

    Camera_ErrorCode IsVideoStabilizationModeSupported(Camera_VideoStabilizationMode mode, bool* isSupported);

    Camera_ErrorCode GetVideoStabilizationMode(Camera_VideoStabilizationMode* mode);

    Camera_ErrorCode SetVideoStabilizationMode(Camera_VideoStabilizationMode mode);

    Camera_ErrorCode GetZoomRatioRange(float* minZoom, float* maxZoom);

    Camera_ErrorCode GetZoomRatio(float* zoom);

    Camera_ErrorCode SetZoomRatio(float zoom);

    Camera_ErrorCode IsFocusModeSupported(Camera_FocusMode focusMode, bool* isSupported);

    Camera_ErrorCode GetFocusMode(Camera_FocusMode* focusMode);

    Camera_ErrorCode SetFocusMode(Camera_FocusMode focusMode);

    Camera_ErrorCode SetFocusPoint(Camera_Point focusPoint);

    Camera_ErrorCode GetFocusPoint(Camera_Point* focusPoint);

    Camera_ErrorCode HasFlash(bool* hasFlash);

    Camera_ErrorCode IsFlashModeSupported(Camera_FlashMode flashMode, bool* isSupported);

    Camera_ErrorCode GetFlashMode(Camera_FlashMode* flashMode);

    Camera_ErrorCode SetFlashMode(Camera_FlashMode flashMode);

    Camera_ErrorCode IsExposureModeSupported(Camera_ExposureMode exposureMode, bool* isSupported);

    Camera_ErrorCode GetExposureMode(Camera_ExposureMode* exposureMode);

    Camera_ErrorCode SetExposureMode(Camera_ExposureMode exposureMode);

    Camera_ErrorCode GetMeteringPoint(Camera_Point* point);

    Camera_ErrorCode SetMeteringPoint(Camera_Point point);

    Camera_ErrorCode GetExposureBiasRange(float* minExposureBias, float* maxExposureBias, float* step);

    Camera_ErrorCode SetExposureBias(float exposureBias);

    Camera_ErrorCode GetExposureBias(float* exposureBias);

    Camera_ErrorCode Start();

    Camera_ErrorCode Stop();

    Camera_ErrorCode Release();

private:
    OHOS::sptr<OHOS::CameraStandard::CaptureSession> innerCaptureSession_;
};
#endif // OHOS_CAPTURE_SESSION_IMPL_H