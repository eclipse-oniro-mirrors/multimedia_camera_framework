/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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
#include "photo_post_processor.h"

#include <cstdint>
#include <string>
#include <sys/mman.h>
#include "foundation/multimedia/camera_framework/services/camera_service/include/camera_util.h"
#include "foundation/multimedia/media_library/interfaces/inner_api/media_library_helper/include/photo_proxy.h"
#include "image_format.h"
#include "image_mime_type.h"
#include "image_type.h"
#include "v1_3/iimage_process_service.h"
#include "iproxy_broker.h"
#include "v1_3/types.h"
#include "securec.h"
#include "shared_buffer.h"
#include "dp_utils.h"
#include "events_monitor.h"
#include "dps_event_report.h"
#include "picture.h"
#include "steady_clock.h"
#include "buffer_extra_data_impl.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr uint32_t MAX_CONSECUTIVE_TIMEOUT_COUNT = 3;
constexpr uint32_t MAX_CONSECUTIVE_CRASH_COUNT = 3;

DpsError MapHdiError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DpsError code = DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL;
    switch (errorCode) {
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID:
            code = DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS:
            code = DpsError::DPS_ERROR_IMAGE_PROC_FAILED;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT:
            code = DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_HIGH_TEMPERATURE:
            code = DpsError::DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABNORMAL:
            code = DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT:
            code = DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", errorCode);
            break;
    }
    return code;
}

HdiStatus MapHdiStatus(OHOS::HDI::Camera::V1_2::SessionStatus statusCode)
{
    HdiStatus code = HdiStatus::HDI_DISCONNECTED;
    switch (statusCode) {
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY:
            code = HdiStatus::HDI_READY;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED:
            code = HdiStatus::HDI_READY_SPACE_LIMIT_REACHED;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY:
            code = HdiStatus::HDI_NOT_READY_TEMPORARILY;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT:
            code = HdiStatus::HDI_NOT_READY_OVERHEAT;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED:
            code = HdiStatus::HDI_NOT_READY_PREEMPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", statusCode);
            break;
    }
    return code;
}

OHOS::HDI::Camera::V1_2::ExecutionMode MapToHdiExecutionMode(ExecutionMode executionMode)
{
    auto mode = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
    switch (executionMode) {
        case ExecutionMode::HIGH_PERFORMANCE:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::HIGH_PREFORMANCE;
            break;
        case ExecutionMode::LOAD_BALANCE:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED;
            break;
        case ExecutionMode::LOW_POWER:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", executionMode);
            break;
    }
    return mode;
}

class PhotoPostProcessor::PhotoProcessListener : public OHOS::HDI::Camera::V1_3::IImageProcessCallback {
public:
    explicit PhotoProcessListener(PhotoPostProcessor* photoPostProcessor) : photoPostProcessor_(photoPostProcessor)
    {
    }

    ~PhotoProcessListener()
    {
        photoPostProcessor_ = nullptr;
    }

    int32_t OnProcessDone(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer) override;

    int32_t OnProcessDoneExt(const std::string& imageId,
        const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer) override;

    int32_t OnError(const std::string& imageId,  OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override;
    int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override;

private:
    void ReportEvent(const std::string& imageId);
    int32_t processBufferInfo(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer);

    std::shared_ptr<Media::Picture> AssemblePicture(const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer);
    PhotoPostProcessor* photoPostProcessor_;
};

int32_t PhotoPostProcessor::PhotoProcessListener::OnProcessDone(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    DP_DEBUG_LOG("imageId: %{public}s", imageId.c_str());
    auto ret = processBufferInfo(imageId, buffer);
    if (ret != DP_OK) {
        DP_ERR_LOG("process done failed imageId: %{public}s.", imageId.c_str());
        photoPostProcessor_->OnError(imageId, DPS_ERROR_IMAGE_PROC_FAILED);
    }
    return DP_OK;
}

int32_t PhotoPostProcessor::PhotoProcessListener::processBufferInfo(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    auto bufferHandle = buffer.imageHandle->GetBufferHandle();
    DP_CHECK_ERROR_RETURN_RET_LOG(bufferHandle == nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "bufferHandle is nullptr.");

    int32_t size = bufferHandle->size;
    int32_t isDegradedImage = 0;
    int32_t dataSize = size;
    int32_t isCloudImageEnhanceSupported = 0;
    if (buffer.metadata) {
        int32_t retImageQuality = buffer.metadata->Get("isDegradedImage", isDegradedImage);
        int32_t retDataSize = buffer.metadata->Get("dataSize", dataSize);
        int32_t retCloudImageEnhanceSupported = buffer.metadata->Get("isCloudImageEnhanceSupported",
            isCloudImageEnhanceSupported);
        DP_INFO_LOG("retImageQuality: %{public}d, retDataSize: %{public}d, retCloudImageEnhanceSupported: %{public}d",
            static_cast<int>(retImageQuality), static_cast<int>(retDataSize),
            static_cast<int>(retCloudImageEnhanceSupported));
    }
    DP_INFO_LOG("bufferHandle param, size: %{public}d, dataSize: %{public}d, isDegradedImage: %{public}d",
        size, static_cast<int>(dataSize), isDegradedImage);
    auto bufferPtr = std::make_shared<SharedBuffer>(dataSize);
    DP_CHECK_ERROR_RETURN_RET_LOG(bufferPtr->Initialize() != DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
        "failed to initialize shared buffer.");

    auto addr = mmap(nullptr, dataSize, PROT_READ | PROT_WRITE, MAP_SHARED, bufferHandle->fd, 0);
    DP_CHECK_ERROR_RETURN_RET_LOG(addr == MAP_FAILED, DPS_ERROR_IMAGE_PROC_FAILED, "failed to mmap shared buffer.");

    if (bufferPtr->CopyFrom(static_cast<uint8_t*>(addr), dataSize) == DP_OK) {
        DP_INFO_LOG("bufferPtr fd: %{public}d, fd: %{public}d", bufferHandle->fd, bufferPtr->GetFd());
        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>(bufferPtr, dataSize,
            isDegradedImage == 0, isCloudImageEnhanceSupported);
        ReportEvent(imageId);
        photoPostProcessor_->OnProcessDone(imageId, bufferInfo);
    }
    munmap(addr, dataSize);
    return DP_OK;
}

BufferHandle *CloneBufferHandle(const BufferHandle *handle)
{
    if (handle == nullptr) {
        DP_ERR_LOG("%{public}s handle is nullptr", __func__);
        return nullptr;
    }

    BufferHandle *newHandle = AllocateBufferHandle(handle->reserveFds, handle->reserveInts);
    if (newHandle == nullptr) {
        DP_ERR_LOG("%{public}s AllocateBufferHandle failed, newHandle is nullptr", __func__);
        return nullptr;
    }

    if (handle->fd == -1) {
        newHandle->fd = handle->fd;
    } else {
        newHandle->fd = dup(handle->fd);
        if (newHandle->fd == -1) {
            DP_ERR_LOG("CloneBufferHandle dup failed");
            FreeBufferHandle(newHandle);
            return nullptr;
        }
    }
    newHandle->width = handle->width;
    newHandle->stride = handle->stride;
    newHandle->height = handle->height;
    newHandle->size = handle->size;
    newHandle->format = handle->format;
    newHandle->usage = handle->usage;
    newHandle->phyAddr = handle->phyAddr;

    for (uint32_t i = 0; i < newHandle->reserveFds; i++) {
        newHandle->reserve[i] = dup(handle->reserve[i]);
        if (newHandle->reserve[i] == -1) {
            DP_ERR_LOG("CloneBufferHandle dup reserveFds failed");
            FreeBufferHandle(newHandle);
            return nullptr;
        }
    }

    if (handle->reserveInts == 0) {
        DP_ERR_LOG("There is no reserved integer value in old handle, no need to copy");
        return newHandle;
    }

    if (memcpy_s(&newHandle->reserve[newHandle->reserveFds], sizeof(int32_t) * newHandle->reserveInts,
        &handle->reserve[handle->reserveFds], sizeof(int32_t) * handle->reserveInts) != EOK) {
        DP_ERR_LOG("CloneBufferHandle memcpy_s failed");
        FreeBufferHandle(newHandle);
        return nullptr;
    }
    return newHandle;
}

sptr<SurfaceBuffer> TransBufferHandleToSurfaceBuffer(BufferHandle *bufferHandle)
{
    DP_INFO_LOG("entered");
    if (bufferHandle == nullptr) {
        DP_ERR_LOG("bufferHandle is null");
        return nullptr;
    }
    BufferHandle *newBufferHandle = CloneBufferHandle(bufferHandle);
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    surfaceBuffer->SetBufferHandle(newBufferHandle);
    DP_INFO_LOG("TransBufferHandleToSurfaceBuffer w=%{public}d, h=%{public}d, f=%{public}d",
        surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), surfaceBuffer->GetFormat());
    return surfaceBuffer;
}

std::shared_ptr<Media::AuxiliaryPicture> CreateAuxiliaryPicture(BufferHandle *bufferHandle,
    Media::AuxiliaryPictureType type)
{
    DP_INFO_LOG("entered, AuxiliaryPictureType type = %{public}d", static_cast<int32_t>(type));
    if (bufferHandle == nullptr) {
        DP_ERR_LOG("bufferHandle is null");
        return nullptr;
    }
    auto buffer = TransBufferHandleToSurfaceBuffer(bufferHandle);
    auto uniquePtr = Media::AuxiliaryPicture::Create(buffer, type, {buffer->GetWidth(), buffer->GetHeight()});
    auto auxiliaryPicture = std::shared_ptr<Media::AuxiliaryPicture>(uniquePtr.release());
    return auxiliaryPicture;
}

inline void RotatePixelMap(std::shared_ptr<Media::PixelMap> pixelMap, const std::string& exifOrientation)
{
    float degree = DeferredProcessing::TransExifOrientationToDegree(exifOrientation);
    if (pixelMap) {
        DP_INFO_LOG("RotatePicture degree is %{public}f", degree);
        pixelMap->rotate(degree);
    } else {
        DP_ERR_LOG("RotatePicture Failed pixelMap is nullptr");
    }
}

std::string GetAndSetExifOrientation(OHOS::Media::ImageMetadata* exifData)
{
    std::string orientation = "";
    if (exifData != nullptr) {
        exifData->GetValue("Orientation", orientation);
        std::string defalutExifOrientation = "1";
        exifData->SetValue("Orientation", defalutExifOrientation);
        DP_INFO_LOG("GetExifOrientation orientation:%{public}s", orientation.c_str());
    } else {
        DP_ERR_LOG("GetExifOrientation exifData is nullptr");
    }
    return orientation;
}

void RotatePicture(std::shared_ptr<Media::Picture> picture)
{
    std::string orientation = GetAndSetExifOrientation(
        reinterpret_cast<OHOS::Media::ImageMetadata*>(picture->GetExifMetadata().get()));
    RotatePixelMap(picture->GetMainPixel(), orientation);
    auto gainMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::GAINMAP);
    if (gainMap) {
        RotatePixelMap(gainMap->GetContentPixel(), orientation);
    }
    auto depthMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::DEPTH_MAP);
    if (depthMap) {
        RotatePixelMap(depthMap->GetContentPixel(), orientation);
    }
    auto unrefocusMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::UNREFOCUS_MAP);
    if (unrefocusMap) {
        RotatePixelMap(unrefocusMap->GetContentPixel(), orientation);
    }
    auto linearMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::LINEAR_MAP);
    if (linearMap) {
        RotatePixelMap(linearMap->GetContentPixel(), orientation);
    }
}

void AssemleAuxilaryPicture(const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer,
    std::shared_ptr<Media::Picture>& picture)
{
    if (buffer.isGainMapValid) {
        auto auxiliaryPicture = CreateAuxiliaryPicture(buffer.gainMapHandle->GetBufferHandle(),
            Media::AuxiliaryPictureType::GAINMAP);
        if (auxiliaryPicture) {
            picture->SetAuxiliaryPicture(auxiliaryPicture);
        }
    }
    if (buffer.isDepthMapValid) {
        auto auxiliaryPicture = CreateAuxiliaryPicture(buffer.depthMapHandle->GetBufferHandle(),
            Media::AuxiliaryPictureType::DEPTH_MAP);
        if (auxiliaryPicture) {
            picture->SetAuxiliaryPicture(auxiliaryPicture);
        }
    }
    if (buffer.isUnrefocusImageValid) {
        auto auxiliaryPicture = CreateAuxiliaryPicture(buffer.unrefocusImageHandle->GetBufferHandle(),
            Media::AuxiliaryPictureType::UNREFOCUS_MAP);
        if (auxiliaryPicture) {
            picture->SetAuxiliaryPicture(auxiliaryPicture);
        }
    }
    if (buffer.isHighBitDepthLinearImageValid) {
        auto auxiliaryPicture = CreateAuxiliaryPicture(buffer.highBitDepthLinearImageHandle->GetBufferHandle(),
            Media::AuxiliaryPictureType::LINEAR_MAP);
        if (auxiliaryPicture) {
            picture->SetAuxiliaryPicture(auxiliaryPicture);
        }
    }
    if (buffer.isMakerInfoValid) {
        auto makerInfoBuffer = TransBufferHandleToSurfaceBuffer(buffer.makerInfoHandle->GetBufferHandle());
        picture->SetMaintenanceData(makerInfoBuffer);
    }
}

std::shared_ptr<Media::Picture> PhotoPostProcessor::PhotoProcessListener::AssemblePicture(
    const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer)
{
    DP_INFO_LOG("entered");
    int32_t exifDataSize = 0;
    if (buffer.metadata) {
        int32_t retExifDataSize = buffer.metadata->Get("exifDataSize", exifDataSize);
        DP_INFO_LOG("AssemblePicture retExifDataSize: %{public}d, exifDataSize: %{public}d",
            static_cast<int>(retExifDataSize), static_cast<int>(exifDataSize));
    }
    auto imageBuffer = TransBufferHandleToSurfaceBuffer(buffer.imageHandle->GetBufferHandle());
    DP_CHECK_ERROR_RETURN_RET_LOG(imageBuffer == nullptr, nullptr, "bufferHandle is nullptr.");
    DP_INFO_LOG("AssemblePicture ImageBufferInfoExt valid: gainMap(%{public}d), depthMap(%{public}d), "
        "unrefocusMap(%{public}d), linearMap(%{public}d), exif(%{public}d), makeInfo(%{public}d)",
        buffer.isGainMapValid, buffer.isDepthMapValid, buffer.isUnrefocusImageValid,
        buffer.isHighBitDepthLinearImageValid, buffer.isExifValid, buffer.isMakerInfoValid);
    std::shared_ptr<Media::Picture> picture = Media::Picture::Create(imageBuffer);
    DP_CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, nullptr, "picture is nullptr.");
    if (buffer.isExifValid) {
        auto exifBuffer = TransBufferHandleToSurfaceBuffer(buffer.exifHandle->GetBufferHandle());
        sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
        extraData->ExtraSet("exifDataSize", exifDataSize);
        if (exifBuffer) {
            exifBuffer->SetExtraData(extraData);
        }
        picture->SetExifMetadata(exifBuffer);
    }
    if (picture) {
        AssemleAuxilaryPicture(buffer, picture);
        RotatePicture(picture);
    }
    return picture;
}

int32_t PhotoPostProcessor::PhotoProcessListener::OnProcessDoneExt(
    const std::string& imageId, const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer)
{
    DP_INFO_LOG("entered");
    auto imageBufferHandle = buffer.imageHandle->GetBufferHandle();
    if (imageBufferHandle == nullptr) {
        DP_ERR_LOG("bufferHandle is null");
        return 0;
    }
    int size = imageBufferHandle->size;
    int32_t isDegradedImage = 0;
    int32_t dataSize = size;
    int32_t deferredImageFormat = 0;
    int32_t isCloudImageEnhanceSupported = 0;
    if (buffer.metadata) {
        int32_t retImageQuality = buffer.metadata->Get("isDegradedImage", isDegradedImage);
        int32_t retDataSize = buffer.metadata->Get("dataSize", dataSize);
        int32_t retFormat = buffer.metadata->Get("deferredImageFormat", deferredImageFormat);
        int32_t retCloudImageEnhanceSupported = buffer.metadata->Get("isCloudImageEnhanceSupported",
            isCloudImageEnhanceSupported);
        DP_INFO_LOG("retImageQuality: %{public}d, retDataSize: %{public}d, retFormat: %{public}d,"
            "retCloudImageEnhanceSupported %{public}d", retImageQuality, retDataSize, retFormat,
            retCloudImageEnhanceSupported);
    }
    DP_INFO_LOG("bufferHandle param, bufferHandleSize: %{public}d, dataSize: %{public}d, isDegradedImage: %{public}d, "
        "deferredImageFormat: %{public}d, isCloudImageEnhanceSupported: %{public}d",
        size, dataSize, isDegradedImage, deferredImageFormat, isCloudImageEnhanceSupported);
    if (deferredImageFormat == static_cast<int32_t>(Media::PhotoFormat::YUV)) {
        std::shared_ptr<Media::Picture> picture = AssemblePicture(buffer);
        std::shared_ptr<BufferInfoExt> bufferInfo = std::make_shared<BufferInfoExt>(picture, dataSize,
            isDegradedImage == 0, isCloudImageEnhanceSupported);
        photoPostProcessor_->OnProcessDoneExt(imageId, bufferInfo);
    } else {
        auto bufferPtr = std::make_shared<SharedBuffer>(dataSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(bufferPtr->Initialize() != DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
            "failed to initialize shared buffer.");

        auto addr = mmap(nullptr, dataSize, PROT_READ | PROT_WRITE, MAP_SHARED, imageBufferHandle->fd, 0);
        DP_CHECK_ERROR_RETURN_RET_LOG(
            addr == MAP_FAILED, DPS_ERROR_IMAGE_PROC_FAILED, "failed to mmap shared buffer.");

        if (bufferPtr->CopyFrom(static_cast<uint8_t*>(addr), dataSize) == DP_OK) {
            DP_INFO_LOG("bufferPtr fd: %{public}d, fd: %{public}d", imageBufferHandle->fd, bufferPtr->GetFd());
            std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>(bufferPtr, dataSize,
                isDegradedImage == 0, isCloudImageEnhanceSupported);
            photoPostProcessor_->OnProcessDone(imageId, bufferInfo);
        }
        munmap(addr, dataSize);
    }
    ReportEvent(imageId);
    return 0;
}

void PhotoPostProcessor::PhotoProcessListener::ReportEvent(const std::string& imageId)
{
    DPSEventReport::GetInstance()
        .UpdateProcessDoneTime(imageId, photoPostProcessor_->GetUserId());
}


int32_t PhotoPostProcessor::PhotoProcessListener::OnError(const std::string& imageId,
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    DpsError dpsErrorCode = MapHdiError(errorCode);
    photoPostProcessor_->OnError(imageId, dpsErrorCode);
    return DP_OK;
}

int32_t PhotoPostProcessor::PhotoProcessListener::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    DP_INFO_LOG("entered");
    HdiStatus hdiStatus = MapHdiStatus(status);
    photoPostProcessor_->OnStateChanged(hdiStatus);
    return DP_OK;
}

class PhotoPostProcessor::SessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SessionDeathRecipient(PhotoPostProcessor* processor)
        : photoPostProcessor_(processor)
    {
    }
    ~SessionDeathRecipient()
    {
        photoPostProcessor_ = nullptr;
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        DP_ERR_LOG("Remote died.");
        if (photoPostProcessor_ == nullptr) {
            return;
        }
        photoPostProcessor_->OnSessionDied();
    }

private:
    PhotoPostProcessor* photoPostProcessor_;
};


PhotoPostProcessor::PhotoPostProcessor(const int32_t userId,
    TaskManager* taskManager, IImageProcessCallbacks* callbacks)
    : userId_(userId),
      taskManager_(taskManager),
      processCallacks_(callbacks),
      listener_(nullptr),
      session_(nullptr),
      sessionDeathRecipient_(nullptr),
      imageId2Handle_(),
      imageId2CrashCount_(),
      removeNeededList_(),
      consecutiveTimeoutCount_(0)
{
    DP_DEBUG_LOG("entered");
}

PhotoPostProcessor::~PhotoPostProcessor()
{
    DP_DEBUG_LOG("entered");
    DisconnectServiceIfNecessary();
    taskManager_ = nullptr;
    processCallacks_ = nullptr;
    session_ = nullptr;
    sessionDeathRecipient_ = nullptr;
    listener_ = nullptr;
    imageId2Handle_.Clear();
    consecutiveTimeoutCount_ = 0;
}

void PhotoPostProcessor::Initialize()
{
    DP_DEBUG_LOG("entered");
    sessionDeathRecipient_ = new SessionDeathRecipient(this); // sptr<SessionDeathRecipient>::MakeSptr(this);
    listener_ = new PhotoProcessListener(this); // sptr<PhotoProcessListener>::MakeSptr(this);
    ConnectServiceIfNecessary();
}

int32_t PhotoPostProcessor::GetUserId()
{
    return userId_;
}

int PhotoPostProcessor::GetConcurrency(ExecutionMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int count = 1;
    if (session_) {
        int32_t ret = session_->GetCoucurrency(OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED, count);
        DP_INFO_LOG("getConcurrency, ret: %{public}d", ret);
    }
    DP_INFO_LOG("entered, count: %{public}d", count);
    return count;
}

bool PhotoPostProcessor::GetPendingImages(std::vector<std::string>& pendingImages)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (session_) {
        int32_t ret = session_->GetPendingImages(pendingImages);
        DP_INFO_LOG("getPendingImages, ret: %{public}d", ret);
        if (ret == 0) {
        return true;
        }
    }
    return false;
}

void PhotoPostProcessor::SetExecutionMode(ExecutionMode executionMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, executionMode: %{public}d", executionMode);
    if (session_) {
        int32_t ret = session_->SetExecutionMode(MapToHdiExecutionMode(executionMode));
        DP_INFO_LOG("setExecutionMode, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::SetDefaultExecutionMode()
{
    // 采用直接新增方法，不适配1_2 和 1_3 模式的差异点
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered.");
    if (session_) {
        int32_t ret = session_->SetExecutionMode(
            static_cast<OHOS::HDI::Camera::V1_2::ExecutionMode>(OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT));
        DP_INFO_LOG("setExecutionMode, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::ProcessImage(std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    if (!ConnectServiceIfNecessary()) {
        DP_INFO_LOG("failed to process image (%{public}s) due to connect service failed", imageId.c_str());
        OnError(imageId, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    DP_CHECK_ERROR_RETURN_LOG(session_ == nullptr, "PhotoPostProcessor::ProcessImage imageProcessSession is nullptr");
    int32_t ret = session_->ProcessImage(imageId);
    DP_INFO_LOG("processImage, ret: %{public}d", ret);
    uint32_t callbackHandle;
    constexpr uint32_t maxProcessingTimeMs = 11 * 1000;
    GetGlobalWatchdog().StartMonitor(callbackHandle, maxProcessingTimeMs, [this, imageId](uint32_t handle) {
        DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog executed, userId: %{public}d, handle: %{public}d",
            userId_, static_cast<int>(handle));
        OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    });
    DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog registered, userId: %{public}d, handle: %{public}d",
        userId_, static_cast<int>(callbackHandle));
    imageId2Handle_.Insert(imageId, callbackHandle);
}

void PhotoPostProcessor::RemoveImage(std::string imageId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    if (session_) {
        int32_t ret = session_->RemoveImage(imageId);
        DP_INFO_LOG("removeImage, imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
        imageId2CrashCount_.erase(imageId);
        DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId_);
    } else {
        removeNeededList_.emplace_back(imageId);
    }
}

void PhotoPostProcessor::Interrupt()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (session_) {
        int32_t ret = session_->Interrupt();
        DP_INFO_LOG("interrupt, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (session_) {
        int32_t ret = session_->Reset();
        DP_INFO_LOG("reset, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::OnProcessDone(const std::string& imageId, std::shared_ptr<BufferInfo> bufferInfo)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    consecutiveTimeoutCount_ = 0;
    StopTimer(imageId);
    if (processCallacks_) {
        taskManager_->SubmitTask([this, imageId, bufferInfo = std::move(bufferInfo)]() {
            processCallacks_->OnProcessDone(userId_, imageId, std::move(bufferInfo));
        });
    }
}

void PhotoPostProcessor::OnProcessDoneExt(const std::string& imageId, std::shared_ptr<BufferInfoExt> bufferInfo)
{
    DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    consecutiveTimeoutCount_ = 0;
    StopTimer(imageId);
    if (processCallacks_) {
        taskManager_->SubmitTask([this, imageId, bufferInfo = std::move(bufferInfo)]() {
            processCallacks_->OnProcessDoneExt(userId_, imageId, std::move(bufferInfo));
        });
    }
}

void PhotoPostProcessor::OnError(const std::string& imageId, DpsError errorCode)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    StopTimer(imageId);
    if (errorCode == DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT) {
        consecutiveTimeoutCount_++;
        if (consecutiveTimeoutCount_ >= static_cast<int>(MAX_CONSECUTIVE_TIMEOUT_COUNT)) {
            Reset();
            consecutiveTimeoutCount_ = 0;
        }
    } else {
        consecutiveTimeoutCount_ = 0;
    }
    if (processCallacks_) {
        taskManager_->SubmitTask([this, imageId, errorCode]() {
            processCallacks_->OnError(userId_, imageId, errorCode);
        });
    }
}

void PhotoPostProcessor::OnStateChanged(HdiStatus hdiStatus)
{
    DP_INFO_LOG("entered, HdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void PhotoPostProcessor::OnSessionDied()
{
    DP_INFO_LOG("entered, session died!");
    std::lock_guard<std::mutex> lock(mutex_);

    session_ = nullptr;
    consecutiveTimeoutCount_ = 0;
    OnStateChanged(HdiStatus::HDI_DISCONNECTED);
    std::vector<std::string> crashJobs;
    imageId2Handle_.Iterate([&](const std::string& imageId, const uint32_t value) {
        crashJobs.emplace_back(imageId);
    });
    for (const auto& id : crashJobs) {
        DP_INFO_LOG("failed to process imageId(%{public}s) due to connect service failed", id.c_str());
        if (imageId2CrashCount_.count(id) == 0) {
            imageId2CrashCount_.emplace(id, 1);
        } else {
            imageId2CrashCount_[id] += 1;
        }
        if (imageId2CrashCount_[id] >= MAX_CONSECUTIVE_CRASH_COUNT) {
            OnError(id, DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
        } else {
            OnError(id, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        }
    }
    ScheduleConnectService();
}

bool PhotoPostProcessor::ConnectServiceIfNecessary()
{
    DP_INFO_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ != nullptr) {
        DP_INFO_LOG("connected");
        return true;
    }
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> imageProcessSession;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessService> imageProcessServiceProxyV1_2;
    sptr<OHOS::HDI::Camera::V1_3::IImageProcessService> imageProcessServiceProxyV1_3;
    imageProcessServiceProxyV1_2 = OHOS::HDI::Camera::V1_2::IImageProcessService::Get(
        std::string("camera_image_process_service"));
    if (imageProcessServiceProxyV1_2 == nullptr) {
        DP_INFO_LOG("Failed to CreateImageProcessSession");
        ScheduleConnectService();
        return false;
    }
    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    imageProcessServiceProxyV1_2->GetVersion(majorVer, minorVer);
    int32_t versionId = GetVersionId(majorVer, minorVer);
    DP_INFO_LOG("CreateImageProcessSession version=%{public}d_%{public}d", majorVer, minorVer);
    if (imageProcessServiceProxyV1_2 != nullptr && versionId >= GetVersionId(HDI_VERSION_1, HDI_VERSION_3)) {
        imageProcessServiceProxyV1_3 =
            OHOS::HDI::Camera::V1_3::IImageProcessService::CastFrom(imageProcessServiceProxyV1_2);
        DP_INFO_LOG("CreateImageProcessSession CastFrom imageProcessServiceProxyV1_3 == nullptr %{public}d",
            imageProcessServiceProxyV1_3 == nullptr);
    }
    if (imageProcessServiceProxyV1_3 != nullptr && versionId >= GetVersionId(HDI_VERSION_1, HDI_VERSION_3)) {
        sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> imageProcessSessionV1_3;
        imageProcessServiceProxyV1_3->CreateImageProcessSessionExt(userId_, listener_, imageProcessSessionV1_3);
        DP_INFO_LOG("CreateImageProcessSessionExt");
        imageProcessSession = imageProcessSessionV1_3;
    } else if (imageProcessServiceProxyV1_2 != nullptr && versionId >= GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        imageProcessServiceProxyV1_2->CreateImageProcessSession(userId_, listener_, imageProcessSession);
    }
    session_ = imageProcessSession;
    for (const auto& imageId : removeNeededList_) {
        int32_t ret = session_->RemoveImage(imageId);
        DP_INFO_LOG("removeImage, imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
    }
    removeNeededList_.clear();
    const sptr<IRemoteObject>& remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_2::IImageProcessSession>(session_);
    DP_CHECK_ERROR_RETURN_RET_LOG(!remote->AddDeathRecipient(sessionDeathRecipient_),
        false, "AddDeathRecipient for ImageProcessSession failed.");
    OnStateChanged(HdiStatus::HDI_READY);
    return true;
}

void PhotoPostProcessor::DisconnectServiceIfNecessary()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_CHECK_ERROR_RETURN_LOG(session_ == nullptr, "imageProcessSession is nullptr");
    const sptr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_2::IImageProcessSession>(session_);
    DP_CHECK_ERROR_PRINT_LOG(!remote->RemoveDeathRecipient(sessionDeathRecipient_),
        "RemoveDeathRecipient for ImageProcessSession failed.");
    session_ = nullptr;
}

void PhotoPostProcessor::ScheduleConnectService()
{
    DP_INFO_LOG("entered.");

    if (session_ == nullptr) {
        constexpr uint32_t delayMilli = 10 * 1000;
        uint32_t callbackHandle;
        GetGlobalWatchdog().StartMonitor(callbackHandle, delayMilli, [this](uint32_t handle) {
            DP_INFO_LOG("PhotoPostProcessor Watchdog executed, handle: %{public}d", static_cast<int>(handle));
            ConnectServiceIfNecessary();
        });
        DP_INFO_LOG("PhotoPostProcessor Watchdog registered, handle: %{public}d", static_cast<int>(callbackHandle));
    } else {
        DP_INFO_LOG("already connected.");
    }
}

void PhotoPostProcessor::StopTimer(const std::string& imageId)
{
    uint32_t callbackHandle;
    DP_CHECK_ERROR_RETURN_LOG(!imageId2Handle_.Find(imageId, callbackHandle),
        "stoptimer failed not find imageId: %{public}s", imageId.c_str());
    imageId2Handle_.Erase(imageId);
    GetGlobalWatchdog().StopMonitor(callbackHandle);
    DP_INFO_LOG("stoptimer success, imageId: %{public}s", imageId.c_str());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS