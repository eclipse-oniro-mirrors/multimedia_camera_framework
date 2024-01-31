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

#ifndef OHOS_CAMERA_CAPTURE_OUTPUT_H
#define OHOS_CAMERA_CAPTURE_OUTPUT_H

#include <mutex>
#include <refbase.h>
#include <set>
#include <vector>

#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "icamera_util.h"
#include "input/camera_death_recipient.h"
#include "istream_common.h"

namespace OHOS {
namespace CameraStandard {
enum DeferredDeliveryImageType {
    DELIVERY_NONE = 0,
    DELIVERY_PHOTO,
    DELIVERY_VIDEO,
};
enum CaptureOutputType {
    CAPTURE_OUTPUT_TYPE_PREVIEW,
    CAPTURE_OUTPUT_TYPE_PHOTO,
    CAPTURE_OUTPUT_TYPE_VIDEO,
    CAPTURE_OUTPUT_TYPE_METADATA,
    CAPTURE_OUTPUT_TYPE_MAX
};

class MetadataObserver {
public:
    /**
     * @brief Get Observed matadata tags
     *        Register tags into capture session. If the tags data changes,{@link OnControlMetadataChanged} will be
     *        called.
     * @return Observed tags
     */
    virtual const std::set<camera_device_metadata_tag_t>& GetObserverControlTags()
    {
        // Empty impl
        const static std::set<camera_device_metadata_tag_t> tags = {};
        return tags;
    };

    /**
     * @brief Get Observed matadata tags
     *        Register tags into capture session. If the tags data changes,{@link OnResultMetadataChanged} will be
     *        called.
     * @return Observed tags
     */
    virtual const std::set<camera_device_metadata_tag_t>& GetObserverResultTags()
    {
        // Empty impl
        const static std::set<camera_device_metadata_tag_t> tags = {};
        return tags;
    };

    /**
     * @brief Callback of request metadata change.
     * @return Operate result
     */
    virtual int32_t OnControlMetadataChanged(
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
    {
        // Empty impl
        return CAM_META_SUCCESS;
    };

    /**
     * @brief Callback of result metadata change.
     * @return Operate result
     */
    virtual int32_t OnResultMetadataChanged(
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
    {
        // Empty impl
        return CAM_META_SUCCESS;
    };
};

class CaptureSession;
class CaptureOutput : public RefBase, public MetadataObserver {
public:
    explicit CaptureOutput(CaptureOutputType OutputType, StreamType streamType, sptr<IStreamCommon> stream);
    virtual ~CaptureOutput();

    /**
     * @brief Releases the instance of CaptureOutput.
     */
    virtual int32_t Release() = 0;

    CaptureOutputType GetOutputType();
    const char* GetOutputTypeString();
    StreamType GetStreamType();
    sptr<IStreamCommon> GetStream();
    sptr<CaptureSession> GetSession();
    void SetSession(wptr<CaptureSession> captureSession);
    std::mutex asyncOpMutex_;
    std::mutex outputCallbackMutex_;
    int32_t SetPhotoProfile(Profile& profile);
    Profile GetPhotoProfile();
    int32_t SetPreviewProfile(Profile& profile);
    Profile GetPreviewProfile();
    int32_t SetVideoProfile(VideoProfile& videoProfile);
    VideoProfile GetVideoProfile();
    virtual void CameraServerDied(pid_t pid) = 0;

protected:
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;

private:
    CaptureOutputType outputType_;
    StreamType streamType_;
    sptr<IStreamCommon> stream_;
    wptr<CaptureSession> session_;
    std::mutex sessionMutex_;
    std::mutex streamMutex_;
    Profile photoProfile_;
    Profile previewProfile_;
    VideoProfile videoProfile_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_OUTPUT_H
