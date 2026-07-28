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

#include "image_effect_proxy.h"

#include "picture.h"
#include "picture_proxy.h"
#include "picture_adapter.h"
#include "image_packer.h"
#include "photo_asset_proxy.h"

#include <sys/stat.h>
#include <fstream>
#include "json_parse.h"
#include "parameters.h"

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

int32_t PhotoProcessResult::ProcessPictureInfoV1_6(
    const std::string& imageId, const std::vector<HDI::Camera::V1_5::ImageBufferInfo_V1_4>& buffers)
{
    DP_INFO_LOG("ProcessPictureInfoV1_6 enter");
    auto imageInfo = std::make_unique<ImageInfo>();
    DP_CHECK_ERROR_RETURN_RET_LOG(buffers.empty(), DPS_ERROR_IMAGE_PROC_FAILED, "buffers is empty");

#ifdef CAMERA_CAPTURE_YUV
    bool isDump = system::GetParameter("const.camera_service.dump100_enable", "0") == "1";
    DP_INFO_LOG("ProcessPictureInfoV1_6 isDump %{public}d", isDump);
    auto mediaLibraryManagerProxy = MediaLibraryManagerProxy::GetMediaLibraryManagerProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaLibraryManagerProxy == nullptr, DPS_ERROR_IMAGE_PROC_FAILED,
        "ProcessPictureInfoV1_6 get MediaLibraryManagerProxy fail");

    DeferredPictureInfo deferInfo = mediaLibraryManagerProxy->GetDeferredPictureInfo(imageId);
    std::string editData = deferInfo.editData;
    std::string encodeFormat = deferInfo.mimeType;
    DP_INFO_LOG("ProcessPictureInfoV1_6 encodeFormat:%{public}s", encodeFormat.c_str());
    const int32_t ONLY_EFFECT_IMAGE = 1;
    bool isOneEffectNoOriginal = editData.empty() && buffers.size() == ONLY_EFFECT_IMAGE;
    if (isOneEffectNoOriginal) {
        DP_INFO_LOG("ProcessPictureInfoV1_6 only effectImage, enter V1_4");
        return ProcessPictureInfoV1_4(imageId, buffers.front());
    }
    bool isRequireOriginImg = !editData.empty() && buffers.size() == ONLY_EFFECT_IMAGE;
    auto [filterName, filterParam] = ParseWatermarkFilter(editData);
    bool isIncludeWatermark = !filterName.empty() && !filterParam.empty();
    DP_INFO_LOG("ProcessPictureInfoV1_6 isOneEffectNoOriginal:%{public}d, isRequireOriginImg: %{public}d, "
                "isIncludeWatermark:%{public}d",
        isOneEffectNoOriginal, isRequireOriginImg, isIncludeWatermark);
#else
    std::string editData;
    std::string encodeFormat;
#endif
    DP_INFO_LOG("ProcessPictureInfoV1_6 editData:%{public}s", editData.c_str());
    for (auto& buffer : buffers) {
        DP_INFO_LOG("ProcessPictureInfoV1_6 buffer loop enter");
        const auto& bufferV_3 = buffer.v1_3;
        DP_CHECK_RETURN_RET(bufferV_3.imageHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED);
        auto bufferHandle = bufferV_3.imageHandle->GetBufferHandle();
        DP_CHECK_ERROR_RETURN_RET_LOG(bufferHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "bufferHandle is nullptr.");
        int32_t deferredFormat = 0;
        GetMetadataValue(bufferV_3.metadata, MetadataKeys::DEFERRED_FORMAT, deferredFormat);
        auto [dataSize, isHighQuality, cloudFlag, captureFlag, dpsMetadata] =
            ParseMeta(bufferHandle->size, bufferV_3.metadata);
        auto imageInfoSingle =
            std::make_unique<ImageInfoSingle>(dataSize, isHighQuality, cloudFlag, captureFlag, dpsMetadata);
        if (deferredFormat != static_cast<int32_t>(PhotoFormat::YUV)) {
            // JPG
            DP_INFO_LOG("ProcessPictureInfoV1_6 JPG process");
            auto dataSize = imageInfoSingle->GetDataSize();
            MappedMemory mapped(bufferHandle->fd, dataSize);
            DP_CHECK_ERROR_RETURN_RET_LOG(
                !mapped, DPS_ERROR_IMAGE_PROC_FAILED, "Memory mapping failed for imageId: %{public}s", imageId.c_str());

            auto bufferPtr = std::make_unique<SharedBuffer>(dataSize);
            DP_CHECK_ERROR_RETURN_RET_LOG(bufferPtr->Initialize() != DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
                "Failed to initialize shared buffer for imageId: %{public}s", imageId.c_str());

            auto ret = bufferPtr->CopyFrom(mapped.data(), dataSize);
            DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
                "Failed to copy buffer for imageId: %{public}s", imageId.c_str());

            DP_INFO_LOG("DPS_PHOTO: bufferHandle fd: %{public}d, bufferPtr fd: %{public}d", bufferHandle->fd,
                bufferPtr->GetFd());
            imageInfoSingle->SetBuffer(std::move(bufferPtr));
            // jpg no need to post process
            OnProcessDone(imageId, std::move(imageInfo));
            return EOK;
        }
#ifdef CAMERA_CAPTURE_YUV
        else {
            // YUV
            DP_INFO_LOG("ProcessPictureInfoV1_6 YUV process");
            std::vector<std::shared_ptr<PictureIntf>> pictures = AssemblePictureList(buffer);
            DP_CHECK_ERROR_RETURN_RET_LOG(
                pictures.empty(), DPS_ERROR_IMAGE_PROC_FAILED, "failed to AssemblePictureList.");

            imageInfoSingle->SetPicture(pictures[0]);
        }
        // process
        DP_INFO_LOG("ProcessPictureInfoV1_6 continue processing");
        auto Encode = [&](const std::unique_ptr<ImageInfoSingle>& imageSingle,
            const std::string& encodeFormat, const std::string&title) -> std::unique_ptr<ImageInfoSingle> {
            // encode to jpeg
            DP_CHECK_ERROR_RETURN_RET_LOG(!imageSingle, nullptr, "Encode imageSingle is nullptr");
            auto pictureIntf = imageSingle->GetPicture();
            auto [buffer, bfSize] = pictureIntf->Encode(encodeFormat);
            DP_CHECK_ERROR_RETURN_RET_LOG(!buffer, nullptr, "Encode fail buffer nullptr ");
            DP_CHECK_ERROR_RETURN_RET_LOG(bfSize == 0, nullptr, "Encode fail size 0");
            DP_INFO_LOG("Encode pack pixelMap success, packedSize: %{public}" PRId64, bfSize);

            if (isDump) {
                PictureAdapter::DumpEncoded(buffer.get(), bfSize, title + "100encode");
            }
            auto bufferPtr = std::make_unique<SharedBuffer>(bfSize);
            DP_CHECK_ERROR_RETURN_RET_LOG(bufferPtr->Initialize() != DP_OK, nullptr,
                "Encode Failed to initialize shared buffer for imageId: %{public}s", imageId.c_str());

            auto ret = bufferPtr->CopyFrom(buffer.get(), bfSize);
            DP_CHECK_ERROR_RETURN_RET_LOG(
                ret != DP_OK, nullptr, "Encode Failed to copy buffer for imageId: %{public}s", imageId.c_str());

            DP_INFO_LOG("Encode DPS_PHOTO: bufferHandle fd: %{public}d, bufferPtr fd: %{public}d", bufferHandle->fd,
                bufferPtr->GetFd());
            auto encodedImg = std::make_unique<ImageInfoSingle>();
            encodedImg->SetBuffer(std::move(bufferPtr));
            encodedImg->SetDataSize(bfSize);
            return encodedImg;
        };

        auto SuppressWatermark = [&](std::unique_ptr<ImageInfoSingle>& imageSingle,
                                     const std::string& editData) -> int32_t {
            // add watermark
            DP_INFO_LOG("SuppressWatermark start");
            DP_CHECK_ERROR_RETURN_RET_LOG(!imageSingle, DPS_ERROR_IMAGE_PROC_FAILED, "imageSingle is nullptr");
            auto imageEffectProxy = ImageEffectProxy::CreateImageEffectProxy();
            DP_CHECK_ERROR_RETURN_RET_LOG(
                !imageEffectProxy, DPS_ERROR_IMAGE_PROC_FAILED, "imageEffectProxy is nullptr");
            auto pictureIntf = imageSingle->GetPicture();
            DP_CHECK_ERROR_RETURN_RET_LOG(!pictureIntf, DPS_ERROR_IMAGE_PROC_FAILED, "pictureIntf is nullptr");
            auto picture = pictureIntf->GetPicture();
            DP_CHECK_ERROR_RETURN_RET_LOG(!picture, DPS_ERROR_IMAGE_PROC_FAILED, "picture is nullptr");
            int32_t ret = imageEffectProxy->SuppressWatermarkForPicture(picture, editData);
            DP_CHECK_ERROR_RETURN_RET_LOG(ret != 0, DPS_ERROR_IMAGE_PROC_FAILED,
                "ProcessPictureInfoV1_6 SuppressWatermarkForPicture fail, editData:%{public}s", editData.c_str());
            return DPS_NO_ERROR;
        };

        auto DownSampling = [&](std::unique_ptr<ImageInfoSingle>& imageSingle) -> std::shared_ptr<PictureIntf> {
            // downSampling
            using namespace Media;
            auto pictureIntf = imageSingle->GetPicture();
            DP_CHECK_ERROR_RETURN_RET_LOG(!pictureIntf, nullptr, "pictureIntf is nullptr");
            auto picture = pictureIntf->GetPicture();
            DP_CHECK_ERROR_RETURN_RET_LOG(!picture, nullptr, "picture is nullptr");
            std::shared_ptr<PictureIntf> lcdPicAdapter = std::make_shared<PictureAdapter>(std::move(picture));
            DP_CHECK_ERROR_RETURN_RET_LOG(lcdPicAdapter == nullptr, nullptr, "lcdPicAdapter is nullptr");
            bool isSucc = lcdPicAdapter->ResizeLcdPicture();
            if (!isSucc) {
                DP_ERR_LOG("ResizeLcdPicture fail");
            }
            return lcdPicAdapter;
        };

        int32_t imageType = ImageBufferType::NONE;
        auto& metadata = bufferV_3.metadata;
        DP_CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "metadata is nullptr");
        metadata->Get("ImageBufferType", imageType);

        switch (imageType) {
            case ImageBufferType::ORIGINAL: {
                DP_INFO_LOG("ProcessPictureInfoV1_6 process origin image");
                auto encodedImg = Encode(imageInfoSingle, encodeFormat, "100org");
                if (isDump) {
                    if (auto pictureIntf = imageInfoSingle->GetPicture()) {
                        pictureIntf->DumpMainPixel(imageId + "_100Org");
                    }
                }
                DP_CHECK_ERROR_RETURN_RET_LOG(encodedImg == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "Encode fail");
                encodedImg->SetType(CallbackType::IMAGE_ORIGIN);
                imageInfo->imageInfoSingles_.emplace_back(std::move(encodedImg));
                break;
            }
            case ImageBufferType::RENDER: {
                DP_INFO_LOG("ProcessPictureInfoV1_6 process render image");
                if (isDump) {
                    if (auto pictureIntf = imageInfoSingle->GetPicture()) {
                        pictureIntf->DumpMainPixel(imageId + "_100Effect");
                    }
                }

                std::unique_ptr<ImageInfoSingle> imageInfoSingleOrg = nullptr;
                if (isRequireOriginImg) {
                    // encode org
                    imageInfoSingleOrg =
                        std::make_unique<ImageInfoSingle>(dataSize, isHighQuality, cloudFlag, captureFlag, dpsMetadata);
                    DP_CHECK_ERROR_RETURN_RET_LOG(
                        imageInfoSingleOrg == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "imageInfoSingleOrg nullptr");
                    if (isIncludeWatermark) {
                        // deep copy
                        auto pictureIntf = imageInfoSingle->GetPicture();
                        DP_CHECK_ERROR_RETURN_RET_LOG(
                            pictureIntf == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "GetPicture fail");
                        auto picture = pictureIntf->GetPicture();
                        DP_CHECK_ERROR_RETURN_RET_LOG(
                            picture == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "picture is nullptr");
                        auto cpPicture = PictureAdapter::CopyPictureSource(picture);
                        std::shared_ptr<PictureAdapter> picAdp = std::make_shared<PictureAdapter>(cpPicture);
                        imageInfoSingleOrg->SetPicture(picAdp);
                    } else {
                        imageInfoSingleOrg->SetPicture(imageInfoSingle->GetPicture());
                    }
                }
                if (isIncludeWatermark) {
                    // only effect
                    int32_t ret = SuppressWatermark(imageInfoSingle, editData);
                    if (ret != DPS_NO_ERROR) {
                        DP_ERR_LOG("SuppressWatermark fail,editData:%{public}s", editData.c_str());
                    }
                }
                DP_CHECK_ERROR_RETURN_RET_LOG(
                    !imageInfoSingle, DPS_ERROR_IMAGE_PROC_FAILED, "imageInfoSingleWater is nullptr");
                if (imageInfoSingle->GetType() == CallbackType::IMAGE_PROCESS_DONE) {
                    DP_ERR_LOG("only yuv support, return");
                    return DPS_ERROR_IMAGE_PROC_FAILED;
                } else if (imageInfoSingle->GetType() == CallbackType::IMAGE_PROCESS_YUV_DONE) {
                    // encode
                    auto encodedImg = Encode(imageInfoSingle, encodeFormat, "100eff");
                    DP_CHECK_ERROR_RETURN_RET_LOG(encodedImg == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "Encode fail");
                    if (isRequireOriginImg) {
                        if (isIncludeWatermark) {
                            auto encodedImgOrg = Encode(imageInfoSingleOrg, encodeFormat, "100orgOne");
                            encodedImgOrg->SetType(CallbackType::IMAGE_ORIGIN);
                            imageInfo->imageInfoSingles_.emplace_back(std::move(encodedImgOrg));
                            encodedImg->SetType(CallbackType::IMAGE_EFFECT);
                            imageInfo->imageInfoSingles_.emplace_back(std::move(encodedImg));
                        } else {
                            encodedImg->SetType(CallbackType::IMAGE_BOTH);
                            imageInfo->imageInfoSingles_.emplace_back(std::move(encodedImg));
                        }
                    } else {
                        encodedImg->SetType(CallbackType::IMAGE_EFFECT);
                        imageInfo->imageInfoSingles_.emplace_back(std::move(encodedImg));
                    }

                    // lcd
                    auto lcdImage = DownSampling(imageInfoSingle);
                    if (isDump) {
                        if (auto pictureIntf = imageInfoSingle->GetPicture()) {
                            pictureIntf->DumpMainPixel(imageId + "_100Lcd");
                        }
                    }
                    DP_CHECK_ERROR_RETURN_RET_LOG(!lcdImage, DPS_ERROR_IMAGE_PROC_FAILED, "lcdImage is nullptr");
                    imageInfo->SetLcdImage(lcdImage);
                } else {
                    DP_ERR_LOG("error buffer type: %{public}d", (int32_t)imageInfoSingle->GetType());
                    return DPS_ERROR_IMAGE_PROC_FAILED;
                }
                break;
            }
            default:
                DP_ERR_LOG("error buffer type: %{public}d", imageType);
                return DPS_ERROR_IMAGE_PROC_FAILED;
        }
#endif
    }
#ifdef CAMERA_CAPTURE_YUV
    OnProcessDone(imageId, std::move(imageInfo));
#endif
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
std::tuple<int32_t, bool, uint32_t, uint32_t, DpsMetadata> PhotoProcessResult::ParseMeta(
    int32_t defaultSize, const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metadata)
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
    return { dataSize, isHighQuality, cloudFlag, captureFlag, dpsMetadata };
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
#ifndef CAMERA_CAPTURE_YUV
    DP_INFO_LOG("DPS_PHOTO rotate picture user id: %{public}d", userId_);
    picture->RotatePicture();
#endif
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
#ifndef CAMERA_CAPTURE_YUV
    DP_INFO_LOG("DPS_PHOTO rotate picture user id: %{public}d", userId_);
    picture->RotatePicture();
#endif
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

void PhotoProcessResult::AssemleAuxilaryPicture(
    const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer, const std::shared_ptr<PictureIntf>& picture)
{
    DP_CHECK_EXECUTE(buffer.isGainMapValid,
        SetAuxiliaryPicture(picture, buffer.gainMapHandle->GetBufferHandle(), CameraAuxiliaryPictureType::GAINMAP));
    DP_CHECK_EXECUTE(buffer.isDepthMapValid,
        SetAuxiliaryPicture(picture, buffer.depthMapHandle->GetBufferHandle(), CameraAuxiliaryPictureType::DEPTH_MAP));
    DP_CHECK_EXECUTE(buffer.isUnrefocusImageValid,
        SetAuxiliaryPicture(
            picture, buffer.unrefocusImageHandle->GetBufferHandle(), CameraAuxiliaryPictureType::UNREFOCUS_MAP));
    DP_CHECK_EXECUTE(buffer.isHighBitDepthLinearImageValid,
        SetAuxiliaryPicture(
            picture, buffer.highBitDepthLinearImageHandle->GetBufferHandle(), CameraAuxiliaryPictureType::LINEAR_MAP));
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