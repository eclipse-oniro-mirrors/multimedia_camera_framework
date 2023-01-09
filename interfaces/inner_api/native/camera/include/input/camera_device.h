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

#ifndef OHOS_CAMERA_CAMERA_DEVICE_H
#define OHOS_CAMERA_CAMERA_DEVICE_H

#include <iostream>
#include <unordered_map>
#include <vector>
#include <refbase.h>
#include "camera_metadata_info.h"

namespace OHOS {
namespace CameraStandard {
enum CameraPosition {
    CAMERA_POSITION_UNSPECIFIED = 0,
    CAMERA_POSITION_BACK,
    CAMERA_POSITION_FRONT
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

class CameraDevice : public RefBase {
public:
    CameraDevice() = default;
    CameraDevice(std::string cameraID, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    ~CameraDevice();
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
    std::vector<int32_t> GetExposureBiasRange();

private:
    std::string cameraID_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata_;
    CameraPosition cameraPosition_ = CAMERA_POSITION_UNSPECIFIED;
    CameraType cameraType_ = CAMERA_TYPE_DEFAULT;
    ConnectionType connectionType_ = CAMERA_CONNECTION_BUILT_IN;
    bool isMirrorSupported_ = false;
    std::vector<float> zoomRatioRange_;
    std::vector<int32_t> exposureBiasRange_;
    static const std::unordered_map<camera_type_enum_t, CameraType> metaToFwCameraType_;
    static const std::unordered_map<camera_position_enum_t, CameraPosition> metaToFwCameraPosition_;
    static const std::unordered_map<camera_connection_type_t, ConnectionType> metaToFwConnectionType_;

    void init(common_metadata_header_t* metadataHeader);
    std::vector<float> CalculateZoomRange();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_DEVICE_H
