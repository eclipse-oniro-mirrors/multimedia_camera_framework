/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_COMMON_UNITTEST_H
#define CAMERA_COMMON_UNITTEST_H

#include "gtest/gtest.h"
#include "camera/camera_manager.h"
#include <refbase.h>
#include "camera/photo_output.h"

#include "image_receiver.h"
#include "image_receiver_manager.h"
namespace OHOS {
namespace CameraStandard {
class CameraNdkCommon {
public:
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    static const int32_t VIDEO_DEFAULT_WIDTH = 640;
    static const int32_t VIDEO_DEFAULT_HEIGHT = 480;

    static const int32_t WAIT_TIME_AFTER_CAPTURE = 3;
    static const int32_t WAIT_TIME_AFTER_START = 2;
    static const int32_t WAIT_TIME_BEFORE_STOP = 1;
    static const int32_t CAMERA_NUMBER = 2;

    static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
    static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
    static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
    static constexpr int32_t RECEIVER_TEST_FORMAT = 4;
    static constexpr int32_t CAMERA_DEVICE_INDEX = 0;

    Camera_Manager *cameraManager = nullptr;
    Camera_Device *cameraDevice = nullptr;
    uint32_t cameraDeviceSize = 0;
    std::shared_ptr<Media::ImageReceiver> imageReceiver;

    void InitCamera(void);
    void ReleaseCamera(void);
    void ReleaseImageReceiver(void);
    void ObtainAvailableFrameRate(Camera_FrameRateRange activeframeRateRange, Camera_FrameRateRange*& frameRateRange,
                                  uint32_t size, int32_t &minFps, int32_t &maxFps);
    void SessionCommit(Camera_CaptureSession *captureSession);
    void SessionControlParams(Camera_CaptureSession *captureSession);
    Camera_PhotoOutput* CreatePhotoOutput(int32_t width = PHOTO_DEFAULT_WIDTH, int32_t height = PHOTO_DEFAULT_HEIGHT);
    Camera_PreviewOutput* CreatePreviewOutput(int32_t width = PREVIEW_DEFAULT_WIDTH,
                                              int32_t height = PREVIEW_DEFAULT_HEIGHT);
    Camera_VideoOutput* CreateVideoOutput(int32_t width = VIDEO_DEFAULT_WIDTH, int32_t height = VIDEO_DEFAULT_HEIGHT);
    Camera_MetadataOutput* CreateMetadataOutput(Camera_MetadataObjectType type);
    static void OnCameraInputError(const Camera_Input* cameraInput, Camera_ErrorCode errorCode);
    static void CameraCaptureSessiononFocusStateChangeCb(Camera_CaptureSession* session, Camera_FocusState focusState);
    static void CameraCaptureSessionOnErrorCb(Camera_CaptureSession* session, Camera_ErrorCode errorCode);
    static void CameraCaptureSessionOnSmoothZoomInfoCb(Camera_CaptureSession* session,
        Camera_SmoothZoomInfo* smoothZoomInfo);
    static void CameraManagerOnCameraStatusCb(Camera_Manager* cameraManager, Camera_StatusInfo* status);
    static void CameraManagerOnCameraTorchStatusCb(Camera_Manager* cameraManager, Camera_TorchStatusInfo* status);
    static void CameraManagerOnCameraFoldStatusCb(Camera_Manager* cameraManager, Camera_FoldStatusInfo* status);
    static void CameraPreviewOutptOnFrameStartCb(Camera_PreviewOutput* previewOutput);
    static void CameraPreviewOutptOnFrameEndCb(Camera_PreviewOutput* previewOutput, int32_t frameCount);
    static void CameraPreviewOutptOnErrorCb(Camera_PreviewOutput* previewOutput, Camera_ErrorCode errorCode);
    static void CameraPhotoOutptOnFrameStartCb(Camera_PhotoOutput* photoOutput);
    static void CameraPhotoOutptOnFrameShutterCb(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* info);
    static void CameraPhotoOutptOnFrameEndCb(Camera_PhotoOutput* photoOutput, int32_t timestamp);
    static void CameraPhotoOutptOnErrorCb(Camera_PhotoOutput* photoOutput, Camera_ErrorCode errorCode);
    static void CameraPhotoOutptOnCaptureEndCb(Camera_PhotoOutput* photoOutput, int32_t frameCount);
    static void CameraPhotoOutptOnCaptureStartWithInfoCb(Camera_PhotoOutput* photoOutput,
        Camera_CaptureStartInfo* Info);
    static void CameraPhotoOutptOnFrameShutterEndCb(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* Info);
    static void CameraPhotoOutptOnCaptureReadyCb(Camera_PhotoOutput* photoOutput);
    static void CameraPhotoOutptEstimatedOnCaptureDurationCb(Camera_PhotoOutput* photoOutput, int64_t duration);
    static void CameraPhotoOutptOnPhotoAvailableCb(Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo);
    static void CameraPhotoOutptOnPhotoAssetAvailableCb(Camera_PhotoOutput* photoOutput, OH_MediaAsset* photoAsset);
    static void CameraVideoOutptOnFrameStartCb(Camera_VideoOutput* videoOutput);
    static void CameraVideoOutptOnFrameEndCb(Camera_VideoOutput* videoOutput, int32_t frameCount);
    static void CameraVideoOutptOnErrorCb(Camera_VideoOutput* videoOutput, Camera_ErrorCode errorCode);
    static void CameraMetadataOutputOnMetadataObjectAvailableCb(Camera_MetadataOutput* metadataOutput,
        Camera_MetadataObject* metadataObject, uint32_t size);
    static void CameraMetadataOutputOnErrorCb(Camera_MetadataOutput* metadataOutput, Camera_ErrorCode errorCode);
};
} // CameraStandard
} // OHOS
#endif // CAMERA_COMMON_UNITTEST_H