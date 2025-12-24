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
#include "dps_metadata_info.h"
#include "events_monitor.h"
#include "photo_process_command.h"
#include "picture_proxy.h"
#include "securec.h"
#include "service_died_command.h"
#include "camera_util.h"

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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

int32_t PhotoProcessResult::ProcessPictureInfoV1_4(
    const std::string& imageId, const HDI::Camera::V1_5::ImageBufferInfo_V1_4& buffer)
{
    const auto& bufferV_3 = buffer.v1_3;
    DP_CHECK_RETURN_RET(bufferV_3.imageHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED);
    auto bufferHandle = bufferV_3.imageHandle->GetBufferHandle();
    DP_CHECK_ERROR_RETURN_RET_LOG(bufferHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "bufferHandle is nullptr.");

    int32_t deferredFormat = 0;
    GetMetadataValue(bufferV_3.metadata, MetadataKeys::DEFERRED_FORMAT, deferredFormat);
    if (deferredFormat != static_cast<int32_t>(PhotoFormat::YUV)) {
        return ProcessBufferInfo(imageId, bufferV_3);
    }

    auto imageInfo = CreateFromMeta(bufferHandle->size, bufferV_3.metadata);
    std::vector<std::shared_ptr<PictureIntf>> pictures = AssemblePictureList(buffer);
    DP_CHECK_ERROR_RETURN_RET_LOG(pictures.empty(), DPS_ERROR_IMAGE_PROC_FAILED, "failed to AssemblePictureList.");

    imageInfo->SetPicture(pictures[0]);
    OnProcessDone(imageId, std::move(imageInfo));
    return DP_OK;
}

std::vector<std::shared_ptr<PictureIntf>> PhotoProcessResult::AssemblePictureList(
    const HDI::Camera::V1_5::ImageBufferInfo_V1_4& bufferV4)
{
    std::vector<std::shared_ptr<PictureIntf>> pictures;
    if (bufferV4.isOriginalImageValid) {
        auto picXTstyle = AssemblePictureV4(bufferV4, !bufferV4.isAuxiliaryInfoValid);
        DP_CHECK_ERROR_RETURN_RET_LOG(picXTstyle == nullptr, pictures, "picXTstyle is nullptr.");

        pictures.emplace_back(picXTstyle);
    }
    auto picture = AssemblePictureV4(bufferV4, true);
    DP_CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, pictures, "picture is nullptr.");

    pictures.emplace_back(picture);
    return pictures;
}

void PhotoProcessResult::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

std::unique_ptr<ImageInfo> PhotoProcessResult::CreateFromMeta(int32_t defaultSize,
    const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metadata)
{
    int32_t dataSize = defaultSize;
    int32_t isDegradedImage = 0;
    uint32_t cloudFlag = 0;
    uint32_t captureFlag = 0;
    GetMetadataValue(metadata, MetadataKeys::DATA_SIZE, dataSize);
    GetMetadataValue(metadata, MetadataKeys::DEGRADED_IMAGE, isDegradedImage);
    GetMetadataValue(metadata, MetadataKeys::CLOUD_FLAG, cloudFlag);
    GetMetadataValue(metadata, MetadataKeys::CPATURE_FLAG, captureFlag);
    DpsMetadata dpsMetadata;
    dpsMetadata.Set(MetadataKeys::CLOUD_FLAG, cloudFlag);
    dpsMetadata.Set(MetadataKeys::CPATURE_FLAG, captureFlag);
    bool isHighQuality = isDegradedImage == 0;
    DP_INFO_LOG("DPS_PHOTO: bufferHandle param size: %{public}d, dataSize: %{public}d, "
        "isDegradedImage: %{public}d, cloudFlag: %{public}u, captureFlag : %{public}u", defaultSize,
        dataSize, isDegradedImage, cloudFlag, captureFlag);
    return std::make_unique<ImageInfo>(dataSize, isHighQuality, cloudFlag, captureFlag, dpsMetadata);
}

std::shared_ptr<PictureIntf> PhotoProcessResult::AssemblePicture(const HDI::Camera::V1_3::ImageBufferInfoExt& buffer)
{
    int32_t exifDataSize = 0;
    int32_t rotationInIps = false;
    GetMetadataValue(buffer.metadata, MetadataKeys::EXIF_SIZE, exifDataSize);
    GetMetadataValue(buffer.metadata, MetadataKeys::ROTATION_IN_IPS, rotationInIps);
    DP_CHECK_ERROR_RETURN_RET_LOG(buffer.imageHandle == nullptr, nullptr, "imageHandle is nullptr.");
    auto imageBuffer = TransBufferHandleToSurfaceBuffer(buffer.imageHandle->GetBufferHandle());
    DP_CHECK_ERROR_RETURN_RET_LOG(imageBuffer == nullptr, nullptr, "imageBuffer is nullptr.");

    DP_INFO_LOG("DPS_PHOTO: AssemblePicture: gainMap(%{public}d), depthMap(%{public}d), unrefocusMap(%{public}d), "
        "linearMap(%{public}d), exif(%{public}d), makeInfo(%{public}d), exifDataSize(%{public}d)",
        buffer.isGainMapValid, buffer.isDepthMapValid, buffer.isUnrefocusImageValid,
        buffer.isHighBitDepthLinearImageValid, buffer.isExifValid, buffer.isMakerInfoValid, exifDataSize);
    std::shared_ptr<PictureIntf> picture = PictureProxy::CreatePictureProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, nullptr, "picture is nullptr.");
    picture->Create(imageBuffer);

    if (buffer.isExifValid) {
        DP_CHECK_ERROR_RETURN_RET_LOG(buffer.exifHandle == nullptr, nullptr, "exifHandle is nullptr.");
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
    DP_INFO_LOG("DPS_PHOTO rotate picture user id: %{public}d, bundle name: %{public}s",
        userId_, bundleName_.c_str());
    if (bundleName_ == SYSTEM_CAMERA) {
        picture->RotatePicture();
    }
    return picture;
}

std::shared_ptr<PictureIntf> PhotoProcessResult::AssemblePictureV4(
    const HDI::Camera::V1_5::ImageBufferInfo_V1_4& buffer, bool isUseImageHandle)
{
    DP_INFO_LOG("PhotoProcessListener::AssemblePictureV4 isUseImageHandle: %{public}d", isUseImageHandle);
    const auto& bufferV_3 = buffer.v1_3;
    int32_t exifDataSize = 0;
    int32_t rotationInIps = false;
    GetMetadataValue(bufferV_3.metadata, MetadataKeys::EXIF_SIZE, exifDataSize);
    GetMetadataValue(bufferV_3.metadata, MetadataKeys::ROTATION_IN_IPS, rotationInIps);
    DP_CHECK_ERROR_RETURN_RET_LOG((isUseImageHandle && bufferV_3.imageHandle == nullptr)
        || (!isUseImageHandle && buffer.originalImageHandle == nullptr), nullptr,
        "imageHandle or originalImageHandle is nullptr.");
    BufferHandle* handle = isUseImageHandle ?
        bufferV_3.imageHandle->GetBufferHandle() : buffer.originalImageHandle->GetBufferHandle();
    auto imageBuffer = TransBufferHandleToSurfaceBuffer(handle);
    DP_CHECK_ERROR_RETURN_RET_LOG(imageBuffer == nullptr, nullptr, "imageBuffer is nullptr.");

    DP_INFO_LOG("DPS_PHOTO: AssemblePicture ImageBufferInfo_V1_4 valid: gainMap(%{public}d),"
        "depthMap(%{public}d), unrefocusMap(%{public}d), linearMap(%{public}d), exif(%{public}d),"
        "makeInfo(%{public}d), OriginalImage(%{public}d), auxiliaryInfo(%{public}d), exifDataSize(%{public}d)",
        bufferV_3.isGainMapValid, bufferV_3.isDepthMapValid, bufferV_3.isUnrefocusImageValid,
        bufferV_3.isHighBitDepthLinearImageValid, bufferV_3.isExifValid, bufferV_3.isMakerInfoValid,
        buffer.isOriginalImageValid, buffer.isAuxiliaryInfoValid, exifDataSize);
    std::shared_ptr<PictureIntf> picture = PictureProxy::CreatePictureProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, nullptr, "picture is nullptr.");

    picture->Create(imageBuffer);
    if (bufferV_3.isExifValid) {
        DP_CHECK_ERROR_RETURN_RET_LOG(bufferV_3.exifHandle == nullptr, nullptr, "exifHandle is nullptr.");
        auto exifBuffer = TransBufferHandleToSurfaceBuffer(bufferV_3.exifHandle->GetBufferHandle());
        sptr<BufferExtraData> extraData = sptr<BufferExtraDataImpl>::MakeSptr();
        extraData->ExtraSet(MetadataKeys::EXIF_SIZE, exifDataSize);
        if (exifBuffer) {
            exifBuffer->SetExtraData(extraData);
        }
        picture->SetExifMetadata(exifBuffer);
    }
    AssemleAuxilaryPictureV4(buffer, picture);
    DP_CHECK_ERROR_RETURN_RET_LOG(rotationInIps, picture, "HAL rotationInIps");
    DP_INFO_LOG("DPS_PHOTO rotate picture user id: %{public}d, bundle name: %{public}s",
        userId_, bundleName_.c_str());
    if (bundleName_ == SYSTEM_CAMERA) {
        picture->RotatePicture();
    }
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
    return surfaceBuffer;
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
    DP_DEBUG_LOG("width(%{public}d) -> (%{public}d)", handle->width, newHandle->width);
    DP_DEBUG_LOG("stride(%{public}d) -> (%{public}d)", handle->stride, newHandle->stride);
    DP_DEBUG_LOG("height(%{public}d) -> (%{public}d)", handle->height, newHandle->height);
    DP_DEBUG_LOG("size(%{public}d) -> (%{public}d)", handle->size, newHandle->size);
    DP_DEBUG_LOG("format(%{public}d) -> (%{public}d)", handle->format, newHandle->format);
    DP_DEBUG_LOG("usage(%{public}" PRIu64 ") -> usage(%{public}" PRIu64 ")", handle->usage, newHandle->usage);

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

void PhotoProcessResult::SetAuxiliaryPicture(const std::shared_ptr<PictureIntf>& picture, BufferHandle *bufferHandle,
    CameraAuxiliaryPictureType type)
{
    DP_DEBUG_LOG("entered, AuxiliaryPictureType type = %{public}d", static_cast<int32_t>(type));
    DP_CHECK_ERROR_RETURN_LOG(picture == nullptr || bufferHandle == nullptr, "bufferHandle is nullptr.");

    auto buffer = TransBufferHandleToSurfaceBuffer(bufferHandle);
    picture->SetAuxiliaryPicture(buffer, type);
}

void PhotoProcessResult::AssemleAuxilaryPicture(const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer,
    const std::shared_ptr<PictureIntf>& picture)
{
    DP_CHECK_EXECUTE(buffer.isGainMapValid, SetAuxiliaryPicture(picture, buffer.gainMapHandle->GetBufferHandle(),
        CameraAuxiliaryPictureType::GAINMAP));
    DP_CHECK_EXECUTE(buffer.isDepthMapValid, SetAuxiliaryPicture(picture, buffer.depthMapHandle->GetBufferHandle(),
        CameraAuxiliaryPictureType::DEPTH_MAP));
    DP_CHECK_EXECUTE(buffer.isUnrefocusImageValid, SetAuxiliaryPicture(picture,
        buffer.unrefocusImageHandle->GetBufferHandle(), CameraAuxiliaryPictureType::UNREFOCUS_MAP));
    DP_CHECK_EXECUTE(buffer.isHighBitDepthLinearImageValid, SetAuxiliaryPicture(picture,
        buffer.highBitDepthLinearImageHandle->GetBufferHandle(), CameraAuxiliaryPictureType::LINEAR_MAP));
    DP_CHECK_EXECUTE(buffer.isMakerInfoValid, {
        auto makerInfoBuffer = TransBufferHandleToSurfaceBuffer(buffer.makerInfoHandle->GetBufferHandle());
        picture->SetMaintenanceData(makerInfoBuffer);
    });
}

void PhotoProcessResult::AssemleAuxilaryPictureV4(
    const HDI::Camera::V1_5::ImageBufferInfo_V1_4& bufferV4, const std::shared_ptr<PictureIntf>& picture)
{
    if (bufferV4.isAuxiliaryInfoValid) {
        auto imageBuffer = TransBufferHandleToSurfaceBuffer(bufferV4.auxiliaryInfoHandle->GetBufferHandle());
        uint32_t retCode = picture->SetXtStyleMetadataBlob(
            reinterpret_cast<uint8_t*>(imageBuffer->GetVirAddr()), imageBuffer->GetSize());
        DP_INFO_LOG("retCode=%{public}u, imageBuffer->GetSize()%{public}d", retCode, imageBuffer->GetSize());
    }
    AssemleAuxilaryPicture(bufferV4.v1_3, picture);
}

void PhotoProcessResult::ReportEvent(const std::string& imageId)
{
    DPSEventReport::GetInstance().UpdateProcessDoneTime(imageId, userId_);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS