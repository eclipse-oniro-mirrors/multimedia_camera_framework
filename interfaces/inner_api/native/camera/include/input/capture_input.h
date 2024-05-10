/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CAPTURE_INPUT_H
#define OHOS_CAMERA_CAPTURE_INPUT_H

#include <memory>
#include <refbase.h>

#include "camera_device.h"
#include "camera_info.h"

namespace OHOS {
namespace CameraStandard {
class MetadataResultProcessor {
public:
    MetadataResultProcessor() = default;
    virtual ~MetadataResultProcessor() = default;
    virtual void ProcessCallbacks(
        const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);
};

class CaptureInput : public RefBase {
public:
    CaptureInput() = default;
    virtual ~CaptureInput() = default;

    /**
     * @brief open camera.
     */
    virtual int Open() = 0;

    /**
     * @brief open camera.
     */
    virtual int Open(bool isEnableSecureCamera, uint64_t* secureSeqId) = 0;

    /**
     * @brief close camera.
     */
    virtual int Close() = 0;

    /**
     * @brief Release camera input.
     */
    virtual int Release() = 0;

    /**
     * @brief get the camera info associated with the device.
     *
     * @return Returns camera info.
     */
    virtual sptr<CameraDevice> GetCameraDeviceInfo() = 0;

    inline void SetMetadataResultProcessor(std::shared_ptr<MetadataResultProcessor> metadataResultProcessor)
    {
        std::lock_guard<std::mutex> lock(metadataResultProcessorMutex_);
        metadataResultProcessor_ = metadataResultProcessor;
    }

    inline std::shared_ptr<MetadataResultProcessor> GetMetadataResultProcessor()
    {
        std::lock_guard<std::mutex> lock(metadataResultProcessorMutex_);
        return metadataResultProcessor_.lock();
    }

private:
    std::mutex metadataResultProcessorMutex_;
    std::weak_ptr<MetadataResultProcessor> metadataResultProcessor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_INPUT_H
