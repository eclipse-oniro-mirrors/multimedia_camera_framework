/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NDK_CAMERA_H
#define CAMERA_NDK_CAMERA_H

#include <unistd.h>
#include <string>
#include <thread>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <string>
#include <vector>
#include <native_buffer/native_buffer.h>
#include "iostream"
#include "mutex"

#include "hilog/log.h"
#include "multimedia/camera_framework/camera.h"
#include "multimedia/camera_framework/camera_input.h"
#include "multimedia/camera_framework/capture_session.h"
#include "multimedia/camera_framework/photo_output.h"
#include "multimedia/camera_framework/preview_output.h"
#include "multimedia/camera_framework/video_output.h"
#include "napi/native_api.h"
#include "multimedia/camera_framework/camera_manager.h"

class NDKCamera {
public:
    ~NDKCamera();
    static NDKCamera* GetInstance(char *str)
    {
        if (ndkCamera_ == nullptr) {
            std::lock_guard<std::mutex> lock(mtx_);
            if (ndkCamera_ == nullptr) {
                ndkCamera_ = new NDKCamera(str);
            }
        }
        return ndkCamera_;
    }
    
    static void Destroy()
    {
        if (ndkCamera_ != nullptr) {
            delete ndkCamera_;
            ndkCamera_ = nullptr;
        }
    }
    
    void EnumerateCamera(void);
    Camera_ErrorCode CreateCameraInput(void);
    Camera_ErrorCode CameraInputOpen(void);
    Camera_ErrorCode CameraInputClose(void);
    Camera_ErrorCode CameraInputRelease(void);
    Camera_ErrorCode GetSupportedCameras(void);
    Camera_ErrorCode GetSupportedOutputCapability(void);
    Camera_ErrorCode CreatePreviewOutput(void);
    Camera_ErrorCode CreatePhotoOutput(char* photoId);
    Camera_ErrorCode CreateVideoOutput(char* videoId);
    Camera_ErrorCode CreateMetadataOutput(void);
    Camera_ErrorCode IsCameraMuted(void);
    Camera_ErrorCode PreviewOutputStop(void);
    Camera_ErrorCode PreviewOutputRelease(void);
    Camera_ErrorCode PhotoOutputRelease(void);
    Camera_ErrorCode HasFlashFn(uint32_t mode);
    Camera_ErrorCode setZoomRatioFn(uint32_t zoomRatio);
    Camera_ErrorCode SessionFlowFn();
    Camera_ErrorCode SessionBegin();
    Camera_ErrorCode SessionCommitConfig();
    Camera_ErrorCode SessionStart();
    Camera_ErrorCode SessionStop();
    Camera_ErrorCode startVideo(char* videoId);
    Camera_ErrorCode AddVideoOutput();
    Camera_ErrorCode VideoOutputStart();
    Camera_ErrorCode startPhoto(char *mSurfaceId);

private:
    explicit NDKCamera(char *str);
    NDKCamera(const NDKCamera&) = delete;
    NDKCamera& operator = (const NDKCamera&) = delete;
    
    Camera_Manager* cameraManager_;
    Camera_CaptureSession* captureSession_;
    Camera_Device* cameras_;
    uint32_t size_;
    Camera_OutputCapability* cameraOutputCapability_;
    const Camera_Profile* profile_;
    const Camera_VideoProfile* videoProfile_;
    Camera_PreviewOutput* previewOutput_;
    Camera_PhotoOutput* photoOutput_;
    Camera_VideoOutput* videoOutput_;
    const Camera_MetadataObjectType* metaDataObjectType_;
    Camera_MetadataOutput* metadataOutput_;
    Camera_Input* cameraInput_;
    bool* isCameraMuted_;
    Camera_Position position_;
    Camera_Type type_;
    char* previewSurfaceId_;
    char* photoSurfaceId_;
    Camera_ErrorCode ret_;
    uint32_t takePictureTimes = 0;
    
    // callback
    CameraManager_Callbacks* callback_;
    
    static NDKCamera* ndkCamera_;
    static std::mutex mtx_;
    volatile bool valid_;
};

#endif  // CAMERA_NDK_CAMERA_H