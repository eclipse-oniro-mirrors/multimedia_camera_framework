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

#ifndef OHOS_CAMERA_CAMERA_INPUT_H
#define OHOS_CAMERA_CAMERA_INPUT_H

#include <iostream>
#include <unordered_map>
#include <set>
#include <vector>
#include "camera_info.h"
#include "camera_device.h"
#include "capture_input.h"
#include "icamera_device_service.h"
#include "icamera_device_service_callback.h"
namespace OHOS {
namespace CameraStandard {
class ErrorCallback {
public:
    ErrorCallback() = default;
    virtual ~ErrorCallback() = default;
    virtual void OnError(const int32_t errorType, const int32_t errorMsg) const;
};

class CameraInput : public CaptureInput {
public:
    [[deprecated]] CameraInput(sptr<ICameraDeviceService> &deviceObj, sptr<CameraInfo> &camera);
    CameraInput(sptr<ICameraDeviceService> &deviceObj, sptr<CameraDevice> &camera);
    virtual ~CameraInput();

    /**
    * @brief open camera.
    */
    int Open() override;

    /**
    * @brief close camera.
    */
    int Close() override;

    /**
    * @brief create new device control setting.
    */
    [[deprecated]] void LockForControl();

    /**
    * @brief submit device control setting.
    *
    * @return Returns CAMERA_OK is success.
    */
    [[deprecated]] int32_t UnlockForControl();

    /**
    * @brief Get the supported format for photo.
    *
    * @return Returns vector of camera_format_t supported format for photo.
    */
    [[deprecated]] std::vector<camera_format_t> GetSupportedPhotoFormats();

    /**
    * @brief Get the supported format for video.
    *
    * @return Returns vector of camera_format_t supported format for video.
    */
    [[deprecated]] std::vector<camera_format_t> GetSupportedVideoFormats();

    /**
    * @brief Get the supported format for preview.
    *
    * @return Returns vector of camera_format_t supported format for preview.
    */
    [[deprecated]] std::vector<camera_format_t> GetSupportedPreviewFormats();

    /**
    * @brief Get the supported exposure modes.
    *
    * @return Returns vector of camera_exposure_mode_enum_t supported exposure modes.
    */
    [[deprecated]] std::vector<camera_exposure_mode_enum_t> GetSupportedExposureModes();

    /**
    * @brief Query whether given exposure mode supported.
    *
    * @param camera_exposure_mode_enum_t exposure mode to query.
    * @return True is supported false otherwise.
    */
    [[deprecated]] bool IsExposureModeSupported(camera_exposure_mode_enum_t exposureMode);

    /**
    * @brief Set exposure mode.
    *
    * @param camera_exposure_mode_enum_t exposure mode to be set.
    */
    [[deprecated]] void SetExposureMode(camera_exposure_mode_enum_t exposureMode);

    /**
    * @brief Get the current exposure mode.
    *
    * @return Returns current exposure mode.
    */
    [[deprecated]] camera_exposure_mode_enum_t GetExposureMode();

    /**
    * @brief Get the supported Focus modes.
    *
    * @return Returns vector of camera_focus_mode_enum_t supported exposure modes.
    */
    [[deprecated]] std::vector<camera_focus_mode_enum_t> GetSupportedFocusModes();

    /**
    * @brief Get exposure compensation range.
    *
    * @return Returns supported exposure compensation range.
    */
    [[deprecated]] std::vector<int32_t> GetExposureBiasRange();

    /**
    * @brief Set exposure compensation value.
    *
    * @param exposure compensation value to be set.
    */
    [[deprecated]] void SetExposureBias(int32_t exposureBias);

    /**
    * @brief Get exposure compensation value.
    *
    * @return Returns current exposure compensation value.
    */
    [[deprecated]] int32_t GetExposureValue();

    /**
    * @brief Query whether given focus mode supported.
    *
    * @param camera_focus_mode_enum_t focus mode to query.
    * @return True is supported false otherwise.
    */
    [[deprecated]] bool IsFocusModeSupported(camera_focus_mode_enum_t focusMode);

    /**
    * @brief Set Focus mode.
    *
    * @param camera_focus_mode_enum_t focus mode to be set.
    */
    [[deprecated]] void SetFocusMode(camera_focus_mode_enum_t focusMode);

    /**
    * @brief Get the current focus mode.
    *
    * @return Returns current focus mode.
    */
    [[deprecated]] camera_focus_mode_enum_t GetFocusMode();

    /**
    * @brief Get focal length.
    *
    * @return Returns focal length value.
    */
    [[deprecated]] float GetFocalLength();

    /**
    * @brief Get the supported Zoom Ratio range.
    *
    * @return Returns vector<float> of supported Zoom ratio range.
    */
    [[deprecated]] std::vector<float> GetSupportedZoomRatioRange();

    /**
    * @brief Get the current Zoom Ratio.
    *
    * @return Returns current Zoom Ratio.
    */
    [[deprecated]] float GetZoomRatio();

    /**
    * @brief Set Zoom ratio.
    *
    * @param Zoom ratio to be set.
    */
    [[deprecated]] void SetZoomRatio(float zoomRatio);

    /**
    * @brief Get the supported Focus modes.
    *
    * @return Returns vector of camera_focus_mode_enum_t supported exposure modes.
    */
    [[deprecated]] std::vector<camera_flash_mode_enum_t> GetSupportedFlashModes();

    /**
    * @brief Get the current flash mode.
    *
    * @return Returns current flash mode.
    */
    [[deprecated]] camera_flash_mode_enum_t GetFlashMode();

    /**
    * @brief Set flash mode.
    *
    * @param camera_flash_mode_enum_t flash mode to be set.
    */
    [[deprecated]] void SetFlashMode(camera_flash_mode_enum_t flashMode);

    /**
    * @brief Set the error callback.
    * which will be called when error occurs.
    *
    * @param The ErrorCallback pointer.
    */
    void SetErrorCallback(std::shared_ptr<ErrorCallback> errorCallback);

    /**
    * @brief Release camera input.
    */
    int Release() override;

    /**
    * @brief Get the camera Id.
    *
    * @return Returns the camera Id.
    */
    std::string GetCameraId();

    /**
    * @brief Get Camera Device.
    *
    * @return Returns Camera Device pointer.
    */
    sptr<ICameraDeviceService> GetCameraDevice();

    /**
    * @brief Get ErrorCallback pointer.
    *
    * @return Returns ErrorCallback pointer.
    */
    std::shared_ptr<ErrorCallback> GetErrorCallback();

    /**
    * @brief get the camera info associated with the device.
    *
    * @return Returns camera info.
    */
    sptr<CameraDevice> GetCameraDeviceInfo() override;

    /**
    * @brief This function is called when there is device setting state change
    * and process the state callback.
    *
    * @param result metadata got from callback from service layer.
    */
    void ProcessDeviceCallbackUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    /**
    * @brief This function is called when there is focus state change
    * and process the focus state callback.
    *
    * @param result metadata got from callback from service layer.
    */
    [[deprecated]] void ProcessAutoFocusUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    /**
    * @brief This function is called when there is exposure state change
    * and process the exposure state callback.
    *
    * @param result metadata got from callback from service layer.
    */
    [[deprecated]] void ProcessAutoExposureUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    /**
    * @brief Get current Camera Settings.
    *
    * @return Returns string encoded metadata setting.
    */
    std::string GetCameraSettings();

    /**
    * @brief set the camera metadata setting.
    *
    * @param string encoded camera metadata setting.
    * @return Returns 0 if success or appropriate error code if failed.
    */
    int32_t SetCameraSettings(std::string setting);

private:
    sptr<CameraDevice> cameraObj_;
    sptr<ICameraDeviceService> deviceObj_;
    std::shared_ptr<ErrorCallback> errorCallback_;
    sptr<ICameraDeviceServiceCallback> CameraDeviceSvcCallback_;
    std::mutex interfaceMutex_;

    int32_t UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_INPUT_H

