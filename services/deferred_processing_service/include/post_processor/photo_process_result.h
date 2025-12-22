/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_PHOTO_PROCESS_RESULT_H
#define OHOS_CAMERA_DPS_PHOTO_PROCESS_RESULT_H

#include <sys/mman.h>

#include "basic_definitions.h"
#include "dp_log.h"
#include "image_info.h"
#include "picture_interface.h"
#include "v1_4/types.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
struct MetadataKeys {
    static constexpr auto DATA_SIZE = "dataSize";
    static constexpr auto DEGRADED_IMAGE = "isDegradedImage";
    static constexpr auto CLOUD_FLAG = "cloudImageEnhanceFlag";
    static constexpr auto DEFERRED_FORMAT = "deferredImageFormat";
    static constexpr auto EXIF_SIZE = "exifDataSize";
    static constexpr auto ROTATION_IN_IPS = "rotationInIps";
};
static const std::string SYSTEM_CAMERA = "com.huawei.hmos.camera";

enum class PhotoFormat : int32_t {
    RGBA = 0,
    JPG,
    HEIF,
    YUV,
};

class MappedMemory {
public:
    MappedMemory(int fd, size_t size)
    {
        addr_ = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        valid_ = (addr_ != MAP_FAILED);
    }

    ~MappedMemory()
    {
        DP_INFO_LOG("entered.");
        if (valid_) {
            munmap(addr_, size_);
        }
    }

    operator bool() const
    {
        return valid_;
    }

    uint8_t* data() const
    {
        return static_cast<uint8_t*>(addr_);
    }

private:
    void* addr_ = MAP_FAILED;
    size_t size_ = 0;
    bool valid_ = false;
};

class BufferHandleGuard {
public:
    explicit BufferHandleGuard(BufferHandle* h) : handle_(h)
    {}

    ~BufferHandleGuard()
    {
        DP_DEBUG_LOG("entered.");
        if (handle_) {
            FreeBufferHandle(handle_);
        }
    }

    BufferHandle* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }

    BufferHandle* handle_;
};

class PhotoProcessResult {
public:
    explicit PhotoProcessResult(const int32_t userId);
    ~PhotoProcessResult();

    void OnProcessDone(const std::string& imageId, std::unique_ptr<ImageInfo> imageInfo);
    void OnError(const std::string& imageId,  DpsError errorCode);
    void OnStateChanged(HdiStatus hdiStatus);
    void OnPhotoSessionDied();
    int32_t ProcessPictureInfoV1_3(const std::string& imageId, const HDI::Camera::V1_3::ImageBufferInfoExt& buffer);
    void SetBundleName(const std::string& bundleName);

    template <typename BufferType>
    int32_t ProcessBufferInfo(const std::string& imageId, const BufferType& buffer)
    {
        auto bufferHandle = buffer.imageHandle->GetBufferHandle();
        DP_CHECK_ERROR_RETURN_RET_LOG(bufferHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED,
            "Invalid buffer handle for imageId: %{public}s", imageId.c_str());

        auto imageInfo = CreateFromMeta(bufferHandle->size, buffer.metadata);
        auto dataSize = imageInfo->GetDataSize();
        MappedMemory mapped(bufferHandle->fd, dataSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(!mapped, DPS_ERROR_IMAGE_PROC_FAILED,
            "Memory mapping failed for imageId: %{public}s", imageId.c_str());

        auto bufferPtr = std::make_unique<SharedBuffer>(dataSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(bufferPtr->Initialize() != DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
            "Failed to initialize shared buffer for imageId: %{public}s", imageId.c_str());

        auto ret = bufferPtr->CopyFrom(mapped.data(), dataSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
            "Failed to copy buffer for imageId: %{public}s", imageId.c_str());

        DP_INFO_LOG("DPS_PHOTO: bufferHandle fd: %{public}d, bufferPtr fd: %{public}d",
            bufferHandle->fd, bufferPtr->GetFd());
        imageInfo->SetBuffer(std::move(bufferPtr));
        OnProcessDone(imageId, std::move(imageInfo));
        return DP_OK;
    }

private:
    std::unique_ptr<ImageInfo> CreateFromMeta(int32_t defaultSize,
        const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metadata);
    std::shared_ptr<PictureIntf> AssemblePicture(const HDI::Camera::V1_3::ImageBufferInfoExt& buffer);
    sptr<SurfaceBuffer> TransBufferHandleToSurfaceBuffer(const BufferHandle* bufferHandle);
    BufferHandle* CloneBufferHandle(const BufferHandle* handle);
    sptr<SurfaceBuffer> DpCopyBuffer(const sptr<SurfaceBuffer>& surfaceBuffer);
    void DpCopyMetaData(const sptr<SurfaceBuffer>& inBuffer, sptr<SurfaceBuffer>& outBuffer);
    void SetAuxiliaryPicture(const std::shared_ptr<PictureIntf>& picture, BufferHandle *bufferHandle,
        CameraAuxiliaryPictureType type);
    void AssemleAuxilaryPicture(const HDI::Camera::V1_3::ImageBufferInfoExt& buffer,
        const std::shared_ptr<PictureIntf>& picture);
    void ReportEvent(const std::string& imageId);

    template <typename T>
    void GetMetadataValue(const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metadata,
        const std::string& key, T& value)
    {
        if (metadata) {
            auto ret = metadata->Get(key, value);
            DP_INFO_LOG("Get metaTag: %{public}s ret: %{public}d", key.c_str(), ret);
        }
    }

    const int32_t userId_;
    std::string bundleName_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_PROCESS_RESULT_H