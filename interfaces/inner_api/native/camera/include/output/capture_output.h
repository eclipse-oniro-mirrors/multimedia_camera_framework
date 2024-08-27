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

#include <cstdint>
#include <mutex>
#include <refbase.h>
#include <set>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "icamera_util.h"
#include "input/camera_death_recipient.h"
#include "istream_common.h"

namespace OHOS {
class IBufferProducer;
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
    CAPTURE_OUTPUT_TYPE_DEPTH_DATA,
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
class CaptureOutput : virtual public RefBase, public MetadataObserver {
public:
    enum Tag { DYNAMIC_PROFILE };
    enum ImageRotation {
        ROTATION_0 = 0,
        ROTATION_90 = 90,
        ROTATION_180 = 180,
        ROTATION_270 = 270
    };
    explicit CaptureOutput(CaptureOutputType outputType, StreamType streamType, sptr<IBufferProducer> bufferProducer,
        sptr<IStreamCommon> stream);
    virtual ~CaptureOutput();

    /**
     * @brief Releases the instance of CaptureOutput.
     */
    virtual int32_t Release() = 0;

    CaptureOutputType GetOutputType();
    const char* GetOutputTypeString();
    StreamType GetStreamType();
    sptr<IStreamCommon> GetStream();
    void SetStream(sptr<IStreamCommon> stream);
    bool IsStreamCreated();
    sptr<CaptureSession> GetSession();
    void SetSession(wptr<CaptureSession> captureSession);
    std::mutex asyncOpMutex_;
    std::mutex outputCallbackMutex_;
    void SetPhotoProfile(Profile& profile);
    std::shared_ptr<Profile> GetPhotoProfile();
    void SetPreviewProfile(Profile& profile);
    std::shared_ptr<Profile> GetPreviewProfile();
    void SetVideoProfile(VideoProfile& videoProfile);
    std::shared_ptr<VideoProfile> GetVideoProfile();
    void SetDepthProfile(DepthProfile& depthProfile);
    std::shared_ptr<DepthProfile> GetDepthProfile();
    void ClearProfiles();
    virtual void CameraServerDied(pid_t pid) = 0;

    virtual int32_t CreateStream() = 0;

    virtual void AddTag(Tag tag) final;
    virtual void RemoveTag(Tag tag) final;
    virtual bool IsTagSetted(Tag tag) final;

protected:
    virtual sptr<IBufferProducer> GetBufferProducer() final;

private:
    void OnCameraServerDied(pid_t pid);
    void RegisterStreamBinderDied();
    void UnregisterStreamBinderDied();

    std::mutex deathRecipientMutex_;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;

    CaptureOutputType outputType_;
    StreamType streamType_;
    sptr<IStreamCommon> stream_;
    wptr<CaptureSession> session_;
    std::mutex sessionMutex_;
    std::mutex streamMutex_;

    // Multithread add same output,set profile may cause problems, let's add mutex guard.
    std::mutex photoProfileMutex_;
    std::shared_ptr<Profile> photoProfile_;
    std::mutex previewProfileMutex_;
    std::shared_ptr<Profile> previewProfile_;
    std::mutex videoProfileMutex_;
    std::shared_ptr<VideoProfile> videoProfile_;
    std::mutex depthProfileMutex_;
    std::shared_ptr<DepthProfile> depthProfile_;

    std::mutex bufferProducerMutex_;
    sptr<IBufferProducer> bufferProducer_;

    std::mutex tagsMutex_;
    std::unordered_set<Tag> tags_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_OUTPUT_H
