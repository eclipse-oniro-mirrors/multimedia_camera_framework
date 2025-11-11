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
 * See the License for the specific language governing permissions andPhotoProcessResult
 * limitations under the License.
 */

#include "photo_process_result.h"

#include "buffer_extra_data_impl.h"
#include "dp_log.h"
#include "dps.h"
#include "dps_event_report.h"
#include "events_monitor.h"
#include "photo_process_command.h"
#include "picture_proxy.h"
#include "securec.h"
#include "service_died_command.h"
#include <optional>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
PhotoProcessResult::PhotoProcessResult(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered.");
}

PhotoProcessResult::~PhotoProcessResult()
{
    DP_INFO_LOG("entered.");
}

void PhotoProcessResult::OnProcessDone(const std::string& imageId, std::unique_ptr<ImageInfo> imageInfo)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnProcessDone imageId: %{public}s", imageId.c_str());
    ReportEvent(imageId);
    auto ret = DPS_SendCommand<PhotoProcessSuccessCommand>(userId_, imageId, std::move(imageInfo));
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "process success imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
}

void PhotoProcessResult::OnError(const std::string& imageId, DpsError errorCode)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnError imageId: %{public}s, error: %{public}d", imageId.c_str(), errorCode);
    auto ret = DPS_SendCommand<PhotoProcessFailedCommand>(userId_, imageId, errorCode);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "processExt success imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
}

void PhotoProcessResult::OnStateChanged(HdiStatus hdiStatus)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnStateChanged hdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void PhotoProcessResult::OnPhotoSessionDied()
{
    DP_ERR_LOG("DPS_PHOTO: OnPhotoSessionDied");
    auto ret = DPS_SendCommand<PhotoDiedCommand>(userId_);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK, "process photoSessionDied. ret: %{public}d", ret);
}


int32_t PhotoProcessResult::ProcessPictureInfoV1_3(const std::string& imageId,
    const HDI::Camera::V1_3::ImageBufferInfoExt& buffer)
{
    DP_CHECK_RETURN_RET(buffer.imageHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED);
    auto bufferHandle = buffer.imageHandle->GetBufferHandle();
    DP_CHECK_ERROR_RETURN_RET_LOG(bufferHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "bufferHandle is nullptr.");

    int32_t deferredFormat = 0;
    GetMetadataValue(buffer.metadata, MetadataKeys::DEFERRED_FORMAT, deferredFormat);
    if (deferredFormat != static_cast<int32_t>(PhotoFormat::YUV)) {
        return ProcessBufferInfo(imageId, buffer);
    }

    auto imageInfo = CreateFromMeta(bufferHandle->size, buffer.metadata);
    std::shared_ptr<PictureIntf> picture = AssemblePicture(buffer);
    DP_CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "failed to AssemblePicture.");

    imageInfo->SetPicture(picture);
    OnProcessDone(imageId, std::move(imageInfo));
    return DP_OK;
}

std::unique_ptr<ImageInfo> PhotoProcessResult::CreateFromMeta(int32_t defaultSize,
    const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metadata)
{
    int32_t dataSize = defaultSize;
    int32_t isDegradedImage = 0;
    uint32_t cloudFlag = 0;
    GetMetadataValue(metadata, MetadataKeys::DATA_SIZE, dataSize);
    GetMetadataValue(metadata, MetadataKeys::DEGRADED_IMAGE, isDegradedImage);
    GetMetadataValue(metadata, MetadataKeys::CLOUD_FLAG, cloudFlag);
    bool isHighQuality = isDegradedImage == 0;
    DP_INFO_LOG("DPS_PHOTO: bufferHandle param size: %{public}d, dataSize: %{public}d, "
        "isDegradedImage: %{public}d, cloudFlag: %{public}u", defaultSize, dataSize, isDegradedImage, cloudFlag);
    return std::make_unique<ImageInfo>(dataSize, isHighQuality, cloudFlag);
}

std::shared_ptr<PictureIntf> PhotoProcessResult::AssemblePicture(const HDI::Camera::V1_3::ImageBufferInfoExt& buffer)
{
    int32_t exifDataSize = 0;
    int32_t rotationInIps = false;
    GetMetadataValue(buffer.metadata, MetadataKeys::EXIF_SIZE, exifDataSize);
    GetMetadataValue(buffer.metadata, MetadataKeys::ROTATION_IN_IPS, rotationInIps);
    DP_CHECK_RETURN_RET(buffer.imageHandle == nullptr, nullptr);
    auto imageBuffer = TransBufferHandleToSurfaceBuffer(buffer.imageHandle->GetBufferHandle());
    DP_CHECK_ERROR_RETURN_RET_LOG(imageBuffer == nullptr, nullptr, "bufferHandle is nullptr.");

    DP_INFO_LOG("DPS_PHOTO: AssemblePicture: gainMap(%{public}d), depthMap(%{public}d), unrefocusMap(%{public}d), "
        "linearMap(%{public}d), exif(%{public}d), makeInfo(%{public}d), exifDataSize(%{public}d)",
        buffer.isGainMapValid, buffer.isDepthMapValid, buffer.isUnrefocusImageValid,
        buffer.isHighBitDepthLinearImageValid, buffer.isExifValid, buffer.isMakerInfoValid, exifDataSize);
    std::shared_ptr<PictureIntf> picture = PictureProxy::CreatePictureProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, nullptr, "picture is nullptr.");
    picture->CreateWithDeepCopySurfaceBuffer(imageBuffer);

    if (buffer.isExifValid) {
        auto exifBuffer = TransBufferHandleToSurfaceBuffer(buffer.exifHandle->GetBufferHandle());
        sptr<BufferExtraData> extraData = sptr<BufferExtraDataImpl>::MakeSptr();
        extraData->ExtraSet(MetadataKeys::EXIF_SIZE, exifDataSize);
        if (exifBuffer) {
            exifBuffer->SetExtraData(extraData);
        }
        picture->SetExifMetadata(exifBuffer);
    }

    AssemleAuxilaryPicture(buffer, picture);
    DP_CHECK_ERROR_RETURN_RET_LOG(rotationInIps, picture, "HAL rotationInIps");
    picture->RotatePicture();
    return picture;
}

sptr<SurfaceBuffer> PhotoProcessResult::TransBufferHandleToSurfaceBuffer(const BufferHandle *bufferHandle)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(bufferHandle == nullptr, nullptr, "bufferHandle is nullptr.");
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    DP_CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, nullptr, "surfaceBuffer is nullptr.");
    auto surfaceBufferHandle = CloneBufferHandle(bufferHandle);
    DP_CHECK_ERROR_RETURN_RET_LOG(surfaceBufferHandle == nullptr, nullptr, "surfaceBufferHandle is nullptr.");
    surfaceBuffer->SetBufferHandle(surfaceBufferHandle);
    DP_INFO_LOG("TransBufferHandleToSurfaceBuffer w=%{public}d, h=%{public}d, f=%{public}d",
        surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), surfaceBuffer->GetFormat());
    return DpCopyBuffer(surfaceBuffer);
}

BufferHandle* PhotoProcessResult::CloneBufferHandle(const BufferHandle* handle)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(handle == nullptr, nullptr, "bufferHandle is nullptr.");

    BufferHandleGuard newHandleGuard(AllocateBufferHandle(handle->reserveFds, handle->reserveInts));
    DP_CHECK_ERROR_RETURN_RET_LOG(newHandleGuard.handle_ == nullptr, nullptr,
        "AllocateBufferHandle failed, newHandle is nullptr.");

    BufferHandle* newHandle = newHandleGuard.handle_;
    // 基础字段拷贝
    static constexpr size_t BASE_FIELDS_SIZE = offsetof(BufferHandle, reserve);
    auto ret = memcpy_s(newHandle, BASE_FIELDS_SIZE, handle, BASE_FIELDS_SIZE);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != EOK, nullptr, "CloneBufferHandle: Base fields copy failed");

    if (handle->fd != -1) {
        newHandle->fd = dup(handle->fd);
        DP_CHECK_ERROR_RETURN_RET_LOG(newHandle->fd == -1, nullptr,
            "CloneBufferHandle: FD dup failed (errno:%{public}d)", errno);
    }

    for (uint32_t i = 0; i < newHandle->reserveFds; i++) {
        newHandle->reserve[i] = dup(handle->reserve[i]);
        DP_CHECK_ERROR_RETURN_RET_LOG(newHandle->reserve[i] == -1, nullptr, "CloneBufferHandle dup reserveFds failed");
    }

    if (handle->reserveInts > 0) {
        const size_t intsSize = sizeof(int32_t) * handle->reserveInts;
        const void* src = &handle->reserve[handle->reserveFds];
        void* dest = &newHandle->reserve[newHandle->reserveFds];
        ret = memcpy_s(dest, intsSize, src, intsSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != EOK, nullptr, "CloneBufferHandle: Reserve ints copy failed");
    }

    return newHandleGuard.release();
}

sptr<SurfaceBuffer> PhotoProcessResult::DpCopyBuffer(const sptr<SurfaceBuffer>& surfaceBuffer)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, nullptr, "surfaceBuffer is nullptr");
    DP_DEBUG_LOG("DpCopyBuffer w=%{public}d, h=%{public}d, f=%{public}d",
        surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), surfaceBuffer->GetFormat());
    BufferRequestConfig requestConfig = {
        .width = surfaceBuffer->GetWidth(),
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .timeout = 0,
        .colorGamut = surfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = surfaceBuffer->GetSurfaceBufferTransform(),
    };
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DP_CHECK_ERROR_RETURN_RET_LOG(newSurfaceBuffer == nullptr, nullptr, "newSurfaceBuffer is nullptr.");
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    DP_DEBUG_LOG("DpCopyBuffer SurfaceBuffer alloc ret: %{public}d", allocErrorCode);
    DP_CHECK_ERROR_RETURN_RET_LOG(allocErrorCode != GSError::GSERROR_OK, nullptr,
        "DpCopyBuffer Alloc faled!, errCode:%{public}d", static_cast<int32_t>(allocErrorCode));

    errno_t errNo = memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize());
    DP_CHECK_ERROR_RETURN_RET_LOG(errNo != EOK, nullptr, "DpCopyBuffer memcpy_s failed");
    DpCopyMetaData(surfaceBuffer, newSurfaceBuffer);
    DP_DEBUG_LOG("DpCopyBuffer memcpy end");
    return newSurfaceBuffer;
}

void PhotoProcessResult::DpCopyMetaData(const sptr<SurfaceBuffer>& inBuffer, sptr<SurfaceBuffer>& outBuffer)
{
    std::vector<uint32_t> keys = {};
    DP_CHECK_ERROR_RETURN_LOG(inBuffer == nullptr || outBuffer == nullptr,
        "DpCopyMetaData: inBuffer or outBuffer is nullptr.");
    auto ret = inBuffer->ListMetadataKeys(keys);
    DP_CHECK_ERROR_RETURN_LOG(ret != GSError::GSERROR_OK, "DpCopyMetaData: ListMetadataKeys fail!");
    for (uint32_t key : keys) {
        std::vector<uint8_t> values;
        ret = inBuffer->GetMetadata(key, values);
        DP_LOOP_CONTINUE_LOG(ret != GSError::GSERROR_OK,
            "GetMetadata fail! key = %{public}d res = %{public}d", key, ret);

        ret = outBuffer->SetMetadata(key, values);
        DP_LOOP_CONTINUE_LOG(ret != GSError::GSERROR_OK,
            "SetMetadata fail! key = %{public}d res = %{public}d", key, ret);
    }
}

void PhotoProcessResult::SetAuxiliaryPicture(const std::shared_ptr<PictureIntf>& picture, BufferHandle *bufferHandle,
    CameraAuxiliaryPictureType type)
{
    DP_INFO_LOG("entered, AuxiliaryPictureType type = %{public}d", static_cast<int32_t>(type));
    DP_CHECK_ERROR_RETURN_LOG(picture == nullptr || bufferHandle == nullptr, "bufferHandle is nullptr.");

    auto buffer = TransBufferHandleToSurfaceBuffer(bufferHandle);
    picture->SetAuxiliaryPicture(buffer, type);
}

void PhotoProcessResult::AssemleAuxilaryPicture(const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer,
    const std::shared_ptr<PictureIntf>& picture)
{
    if (buffer.isGainMapValid) {
        SetAuxiliaryPicture(picture, buffer.gainMapHandle->GetBufferHandle(),
            CameraAuxiliaryPictureType::GAINMAP);
    }
    if (buffer.isDepthMapValid) {
        SetAuxiliaryPicture(picture, buffer.depthMapHandle->GetBufferHandle(),
            CameraAuxiliaryPictureType::DEPTH_MAP);
    }
    if (buffer.isUnrefocusImageValid) {
        SetAuxiliaryPicture(picture, buffer.unrefocusImageHandle->GetBufferHandle(),
            CameraAuxiliaryPictureType::UNREFOCUS_MAP);
    }
    if (buffer.isHighBitDepthLinearImageValid) {
        SetAuxiliaryPicture(picture, buffer.highBitDepthLinearImageHandle->GetBufferHandle(),
            CameraAuxiliaryPictureType::LINEAR_MAP);
    }
    if (buffer.isMakerInfoValid) {
        auto makerInfoBuffer = TransBufferHandleToSurfaceBuffer(buffer.makerInfoHandle->GetBufferHandle());
        picture->SetMaintenanceData(makerInfoBuffer);
    }
}

void PhotoProcessResult::ReportEvent(const std::string& imageId)
{
    DPSEventReport::GetInstance().UpdateProcessDoneTime(imageId, userId_);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS