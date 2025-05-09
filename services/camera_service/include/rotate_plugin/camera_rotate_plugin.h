/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef CAMERA_ROTATE_PLUGIN_H
#define CAMERA_ROTATE_PLUGIN_H

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <refbase.h>
#include "safe_map.h"
#include "camera_metadata_info.h"
#include "surface.h"

using ParameterMap = std::map<int32_t, std::string>;
using UpdateSettingsCallback = std::function<int32_t(ParameterMap& parameters)>;
namespace OHOS {
namespace CameraStandard {
enum PluginParameter {
    PLUGIN_BUNDLE_NAME = 0,
    PLUGIN_CAMERA_ID,
    PLUGIN_CAMERA_POSITION,
    PLUGIN_CAMERA_CONNECTION_TYPE,  // 0:buildin, 1:usb, 2:remote
    PLUGIN_SENSOR_ORIENTATION, // ability
    PLUGIN_PREVIEW_FORMAT, // preview
    PLUGIN_SURFACE_FRAME_GRAVITY, // preview
    PLUGIN_SURFACE_FIXED_ROTATION, // preview
    PLUGIN_CAMERA_HAL_ROTATE_ANGLE, // preview + video 不区分 统一下发给HAL的
    PLUGIN_JPEG_ORIENTATION, // jpeg
    PLUGIN_CAPTURE_MIRROR, // jpeg
    PLUGIN_SURFACE_APP_FWK_TYPE, //video
    PLUGIN_VIDEO_SURFACE_TRANSFORM, // video
    PLUGIN_VIDEO_MIRROR, // video
};
class HCaptureSession;

class CameraRotatePlugin : public RefBase {
    public:
    ~CameraRotatePlugin();
    static sptr<CameraRotatePlugin> &GetInstance();
    bool HookCameraAbility(const std::string& cameraId, std::shared_ptr<OHOS::Camera::CameraMetadata>& inability);
    bool HookOpenDeviceForRotate(const std::string& bundleName,
        std::shared_ptr<OHOS::Camera::CameraMetadata> inputCapability, const std::string& cameraId);
    bool HookCloseDeviceForRotate(const std::string& bundleName,
        std::shared_ptr<OHOS::Camera::CameraMetadata> inputCapability, const std::string& cameraId);
    bool HookCreatePreviewFormat(const std::string& bundleName, int32_t& format);
    bool HookPreviewStreamStart(ParameterMap basicInfoMap, const sptr<OHOS::IBufferProducer>& producer,
        int32_t& rotateAngle);
    bool HookPreviewTransform(ParameterMap basicInfoMap, const sptr<OHOS::IBufferProducer>& producer,
        int32_t& sensorOrientation, int32_t& cameraPosition);
    bool HookCreateVideoOutput(ParameterMap basicInfoMap, const sptr<OHOS::IBufferProducer>& producer);
    bool HookVideoStreamStart(ParameterMap basicInfoMap, const sptr<OHOS::IBufferProducer>& producer,
        bool& mirror);
    bool HookCaptureStreamStart(ParameterMap basicInfoMap, int32_t& jpegOrientation, bool& mirror);
    void SetCaptureSession(const std::string& bundleName, wptr<HCaptureSession> hcaptureSession);
private:
    CameraRotatePlugin();
    bool Init();
    void InitParam(const std::string& bundleName, std::shared_ptr<OHOS::Camera::CameraMetadata> inputCapability,
        const std::string& cameraId, ParameterMap& param);
    bool GetCameraAbility(ParameterMap basicInfoMap, uint8_t& cameraPosition, int32_t& sensorOrientation);
    bool SubscribeUpdateSettingCallback(ParameterMap basicInfoMap);
    bool UnSubscribeUpdateSettingCallback(ParameterMap basicInfoMap);
    bool CreatePreviewOutput(ParameterMap basicInfoMap, int32_t& format);
    bool PreviewStreamStart(ParameterMap basicInfoMap, int32_t& frameGravity, int32_t& fixedRotation,
        int32_t& rotateAngle);
    bool PreviewTransform(ParameterMap basicInfoMap, int32_t& frameGravity, int32_t& fixedRotation,
        int32_t& sensorOrientation, int32_t& cameraPosition);
    bool CaptureStreamStart(ParameterMap basicInfoMap, int32_t& jpegOrientation, bool& mirror);
    bool CreateVideoOutput(ParameterMap basicInfoMap, std::string& surfaceAppFwkType, uint32_t& transform);
    bool VideoStreamStart(ParameterMap basicInfoMap, std::string& surfaceAppFwkType, uint32_t& transform,
        bool& mirror);
    void* GetFunction(const std::string& functionName);
    bool GetParameterResult(ParameterMap basicInfoMap, const std::string& functionName, ParameterMap& parameterMap);
    int32_t OnParameterChange(ParameterMap ParameterMap);

    static std::mutex instanceMutex_;
    SafeMap<std::string, void*> functionMap_;
    static sptr<CameraRotatePlugin> cameraRotatePlugin_;
    static bool initResult;
    void *handle_ = nullptr;
    // wptr<HCaptureSession> hcaptureSession_;
    SafeMap<std::string, wptr<HCaptureSession>> captureSessionMap_;
};
}
}
#endif /* CAMERA_ROTATE_PLUGIN_H */