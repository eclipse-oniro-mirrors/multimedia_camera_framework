/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CAMERA_DEVICE_H
#define OHOS_CAMERA_CAMERA_DEVICE_H

#include <refbase.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include "camera_metadata_info.h"
#include "output/camera_output_capability.h"
#include "output/capture_output.h"

namespace OHOS {
namespace CameraStandard {
enum CameraPosition {
    CAMERA_POSITION_UNSPECIFIED = 0,
    CAMERA_POSITION_BACK,
    CAMERA_POSITION_FRONT,
    CAMERA_POSITION_FOLD_INNER
};

enum CameraType {
    CAMERA_TYPE_UNSUPPORTED = -1,
    CAMERA_TYPE_DEFAULT = 0,
    CAMERA_TYPE_WIDE_ANGLE,
    CAMERA_TYPE_ULTRA_WIDE,
    CAMERA_TYPE_TELEPHOTO,
    CAMERA_TYPE_TRUE_DEPTH
};

enum ConnectionType {
    CAMERA_CONNECTION_BUILT_IN = 0,
    CAMERA_CONNECTION_USB_PLUGIN,
    CAMERA_CONNECTION_REMOTE
};

enum CameraFoldScreenType {
    CAMERA_FOLDSCREEN_UNSPECIFIED = 0,
    CAMERA_FOLDSCREEN_INNER,
    CAMERA_FOLDSCREEN_OUTER
};

typedef struct dmDeviceInfo {
    /**
     * Device name of the device.
     */
    std::string deviceName;
    /**
     * Device type of the device.
     */
    uint16_t deviceTypeId;
    /**
     * NetworkId of the device.
     */
    std::string networkId;
} dmDeviceInfo;

class CameraDevice : public RefBase {
public:
    explicit CameraDevice(std::string cameraID, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    explicit CameraDevice(
        std::string cameraID, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, dmDeviceInfo deviceInfo);
    virtual ~CameraDevice() = default;
    /**
    * @brief Get the camera Id.
    *
    * @return Returns the camera Id.
    */
    std::string GetID();

    /**
    * @brief Get the metadata corresponding to current camera object.
    *
    * @return Returns the metadata corresponding to current object.
    */
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetMetadata();

    /**
    * @brief Reset cachedMetadata_ to default status
    */
    void ResetMetadata();

    /**
    * @brief Get the current camera static abilities.
    *
    * @return Returns the current camera static abilities.
    */
    const std::shared_ptr<OHOS::Camera::CameraMetadata> GetCameraAbility();

    /**
    * @brief Get the position of the camera.
    *
    * @return Returns the position of the camera.
    */
    CameraPosition GetPosition();

    /**
    * @brief Get the Camera type of the camera.
    *
    * @return Returns the Camera type of the camera.
    */
    CameraType GetCameraType();

    /**
    * @brief Get the Camera connection type.
    *
    * @return Returns the Camera type of the camera.
    */
    ConnectionType GetConnectionType();

    /**
    * @brief Get the facing for foldScreen device.
    *
    * @return Returns the Camera type of the camera.
    */
    CameraFoldScreenType GetCameraFoldScreenType();

    /**
    * @brief Get the Distributed Camera Host Name.
    *
    * @return Returns the  Host Name of the Distributed camera.
    */
    std::string GetHostName();

    /**
    * @brief Get the Distributed Camera deviceType.
    *
    * @return Returns the deviceType of the Distributed camera.
    */
    uint16_t GetDeviceType();

    /**
    * @brief Get the Distributed Camera networkId.
    *
    * @return Returns the networkId of the Distributed camera.
    */
    std::string GetNetWorkId();

    /**
    * @brief Get the camera orientation.
    *
    * @return Returns the camera orientation.
    */
    uint32_t GetCameraOrientation();

    /**
    * @brief Check if mirror mode supported.
    *
    * @return Returns True is supported.
    */
    bool IsMirrorSupported();

    // or can we move definition completely in session only?
    /**
    * @brief Get the supported Zoom Ratio range.
    *
    * @return Returns vector<float> of supported Zoom ratio range.
    */
    std::vector<float> GetZoomRatioRange();

    /**
    * @brief Get the supported exposure compensation range.
    *
    * @return Returns vector<int32_t> of supported exposure compensation range.
    */
    std::vector<float> GetExposureBiasRange();

    /**
    * @brief Get sensor module type
    *
    * @return moduleType sensor module type.
    */
    uint32_t GetModuleType();
    std::unordered_map<int32_t, std::vector<Profile>> modePreviewProfiles_ = {};
    std::unordered_map<int32_t, std::vector<Profile>> modePhotoProfiles_ = {};
    std::unordered_map<int32_t, std::vector<VideoProfile>> modeVideoProfiles_ = {};
    std::unordered_map<int32_t, DeferredDeliveryImageType> modeDeferredType_ = {};
private:
    std::string cameraID_;
    const std::shared_ptr<OHOS::Camera::CameraMetadata> baseAbility_;
    std::mutex cachedMetadataMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cachedMetadata_;
    CameraPosition cameraPosition_ = CAMERA_POSITION_UNSPECIFIED;
    CameraType cameraType_ = CAMERA_TYPE_DEFAULT;
    ConnectionType connectionType_ = CAMERA_CONNECTION_BUILT_IN;
    CameraFoldScreenType foldScreenType_ = CAMERA_FOLDSCREEN_UNSPECIFIED;
    uint32_t cameraOrientation_ = 0;
    bool isMirrorSupported_ = false;
    uint32_t moduleType_ = 0;
    dmDeviceInfo dmDeviceInfo_ = {};
    std::vector<float> zoomRatioRange_;
    std::vector<float> exposureBiasRange_;
    static const std::unordered_map<camera_type_enum_t, CameraType> metaToFwCameraType_;
    static const std::unordered_map<camera_position_enum_t, CameraPosition> metaToFwCameraPosition_;
    static const std::unordered_map<camera_connection_type_t, ConnectionType> metaToFwConnectionType_;
    static const std::unordered_map<camera_foldscreen_enum_t, CameraFoldScreenType> metaToFwCameraFoldScreenType_;
    void init(common_metadata_header_t* metadataHeader);
    bool isFindModuleTypeTag(uint32_t &tagId);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_DEVICE_H
