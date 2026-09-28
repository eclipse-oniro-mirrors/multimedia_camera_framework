/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "photo_buffer_consumer.h"

#include "camera_log.h"
#include "task_manager.h"
#include "camera_surface_buffer_util.h"
#include "hstream_capture.h"
#include "task_manager.h"
#include "picture_assembler.h"
#include "camera_server_photo_proxy.h"
#include "picture_proxy.h"
#include "camera_report_dfx_uitls.h"
#include "watch_dog.h"

namespace OHOS {
namespace CameraStandard {

PhotoBufferConsumer::PhotoBufferConsumer(wptr<HStreamCapture> streamCapture, bool isRaw)
    : streamCapture_(streamCapture), isRaw_(isRaw)
{
    MEDIA_INFO_LOG("PhotoBufferConsumer new E, isRaw:%{public}d", isRaw);
}

PhotoBufferConsumer::~PhotoBufferConsumer()
{
    MEDIA_INFO_LOG("PhotoBufferConsumer ~ E");
}

void PhotoBufferConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("PhotoBufferConsumer OnBufferAvailable E");
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    auto photoTask = streamCapture->photoTask_.Get();
    CHECK_RETURN_ELOG(photoTask == nullptr, "photoTask is null");
    wptr<PhotoBufferConsumer> thisPtr(this);
    photoTask->SubmitTask([thisPtr]() {
        auto listener = thisPtr.promote();
        CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
    });
    MEDIA_INFO_LOG("PhotoBufferConsumer OnBufferAvailable X");
}

void PhotoBufferConsumer::ExecuteOnBufferAvailable()
{

    MEDIA_INFO_LOG("P_ExecuteOnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    sptr<Surface> surface;
    if (isRaw_) {
        surface = streamCapture->rawSurface_.Get();
    } else {
        surface = streamCapture->surface_;
    }
    CHECK_RETURN_ELOG(surface == nullptr, "surface is null");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = surface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "PhotoBufferConsumer Failed to acquire surface buffer");
    int32_t isDegradedImage = CameraSurfaceBufferUtil::GetIsDegradedImage(surfaceBuffer);
    MEDIA_INFO_LOG("PhotoBufferConsumer ts isDegradedImage:%{public}d", isDegradedImage);
    MEDIA_INFO_LOG("PhotoBufferConsumer ts is:%{public}" PRId64, timestamp);
    // deep copy surfaceBuffer
    sptr<SurfaceBuffer> newSurfaceBuffer = CameraSurfaceBufferUtil::DeepCopyBuffer(surfaceBuffer);
    // release surfaceBuffer to bufferQueue
    surface->ReleaseBuffer(surfaceBuffer, -1);
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "newSurfaceBuffer is null");
    int32_t captureId = CameraSurfaceBufferUtil::GetCaptureId(newSurfaceBuffer);
    CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::PHOTO_AVAILABLE, captureId);
    CameraReportDfxUtils::GetInstance()->SetFirstBufferEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyStartInfo(captureId);
    int32_t auxiliaryCount = CameraSurfaceBufferUtil::GetImageCount(newSurfaceBuffer);
#ifdef CAMERA_CAPTURE_YUV
    bool isSystemApp = PhotoLevelManager::GetInstance().GetPhotoLevelInfo(captureId);
    if (!isSystemApp && streamCapture_->isYuvCapture_) {
        MEDIA_INFO_LOG("OnBufferAvailable captureId:%{public}d auxiliaryCount:%{public}d",
            captureId, auxiliaryCount);
        StartWaitAuxiliaryTask(captureId, auxiliaryCount, timestamp, newSurfaceBuffer);
    } else
#endif
    if (!isRaw_ && !streamCapture_->isYuvCapture_ && streamCapture_->IsAuxPhotoEnabled() &&
        auxiliaryCount > 1 && !streamCapture_->IsAuxPhotoDegraded(captureId)) {
        StartWaitAuxPhotoTask(captureId, timestamp, newSurfaceBuffer);
    } else {
        streamCapture->OnPhotoAvailable(newSurfaceBuffer, timestamp, isRaw_);
        // Direct delivery (aux not enabled / degraded capture / imageCount declared none):
        // clean the per-capture auxiliary state so no orphan entries stay in the maps.
        if (streamCapture_->IsAuxPhotoEnabled()) {
            streamCapture_->CleanAuxPhotoState(captureId);
        }
    }
    MEDIA_INFO_LOG("P_ExecuteOnBufferAvailable X");
}

uint32_t PhotoBufferConsumer::GetArrivedAuxPhotoCount(const sptr<HStreamCapture>& streamCapture,
    int32_t captureId)
{
    std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};
    uint32_t arrivedCount = 0;
    if (streamCapture->captureIdOxygenMap_.count(captureId) > 0) {
        arrivedCount++;
    }
    if (streamCapture->captureIdPigmentationMap_.count(captureId) > 0) {
        arrivedCount++;
    }
    return arrivedCount;
}

uint32_t PhotoBufferConsumer::StartAuxPhotoWatchdog(int32_t captureId, int64_t timestamp)
{
    uint32_t pictureHandle = 0;
    constexpr uint32_t delayMilli = 1 * 1000;
    wptr<PhotoBufferConsumer> thisPtr(this);
    DeferredProcessing::Watchdog::GetGlobalWatchdog().StartMonitor(
        pictureHandle, delayMilli, [thisPtr, captureId, timestamp](uint32_t handle) {
            MEDIA_INFO_LOG("StartWaitAuxPhotoTask Watchdog executed, handle: %{public}d, captureId:%{public}d",
                static_cast<int>(handle), captureId);
            auto ptr = thisPtr.promote();
            CHECK_RETURN(ptr == nullptr);
            ptr->AssembleCompressedPhotoWithAux(timestamp, captureId);
        });
    return pictureHandle;
}

// Caller must hold HStreamCapture::g_photoImageMutex.
bool PhotoBufferConsumer::ArmAuxPhotoConsumerTrigger(const sptr<HStreamCapture>& streamCapture,
    int32_t captureId, uint32_t pictureHandle, uint32_t expectedCount)
{
    streamCapture->captureIdHandleMap_[captureId] = pictureHandle;
    streamCapture->captureIdCountMap_[captureId] = static_cast<int32_t>(expectedCount);
    int32_t arrivedCount = streamCapture->captureIdAuxiliaryCountMap_.count(captureId) > 0 ?
        streamCapture->captureIdAuxiliaryCountMap_[captureId] : 0;
    // True when all auxiliary buffers arrived while the monitor was being registered.
    return arrivedCount != -1 && arrivedCount >= static_cast<int32_t>(expectedCount);
}

void PhotoBufferConsumer::StartWaitAuxPhotoTask(int32_t captureId, int64_t timestamp,
    sptr<SurfaceBuffer>& mainBuffer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("StartWaitAuxPhotoTask E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    uint32_t expectedCount = 0;
    bool isComplete = false;
    {
        std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};
        if (streamCapture->captureIdMainPhotoMap_.count(captureId) > 0) {
            MEDIA_WARNING_LOG("StartWaitAuxPhotoTask captureId:%{public}d already waiting", captureId);
            return;
        }
        streamCapture->captureIdMainPhotoMap_[captureId] = mainBuffer;
        int32_t imageCount = CameraSurfaceBufferUtil::GetImageCount(mainBuffer);
        int32_t imageAuxCount = imageCount - 1;
        expectedCount = imageAuxCount > 0 ? static_cast<uint32_t>(imageAuxCount) : 0;
        // Auxiliary buffers may have arrived before the main photo, check by map presence.
        uint32_t arrivedCount = GetArrivedAuxPhotoCount(streamCapture, captureId);
        isComplete = arrivedCount >= expectedCount;
        MEDIA_INFO_LOG("StartWaitAuxPhotoTask expect auxiliary photos, captureId:%{public}d, "
            "imageCount:%{public}d, expectedCount:%{public}u, arrivedCount:%{public}u",
            captureId, imageCount, expectedCount, arrivedCount);
    }
    // Assemble outside the lock: the delivery callback sends an IPC, keep the photo mutex hold
    // time minimal. The main photo map guard in the assemble makes re-entry a no-op.
    if (isComplete) {
        MEDIA_INFO_LOG("StartWaitAuxPhotoTask auxiliary photos complete, captureId:%{public}d", captureId);
        AssembleCompressedPhotoWithAux(timestamp, captureId);
        return;
    }
    uint32_t pictureHandle = StartAuxPhotoWatchdog(captureId, timestamp);
    {
        // Arm the consumer trigger only after the handle is stored, so the consumer equality
        // path never fires DoTimeout with an unset (zero) handle.
        std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};
        isComplete = ArmAuxPhotoConsumerTrigger(streamCapture, captureId, pictureHandle, expectedCount);
    }
    if (isComplete) {
        DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(pictureHandle);
        AssembleCompressedPhotoWithAux(timestamp, captureId);
        return;
    }
    MEDIA_INFO_LOG("StartWaitAuxPhotoTask monitor started, pictureHandle:%{public}u, captureId:%{public}d",
        pictureHandle, captureId);
}

void PhotoBufferConsumer::AssembleCompressedPhotoWithAux(int64_t timestamp, int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AssembleCompressedPhotoWithAux E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    sptr<SurfaceBuffer> mainBuffer = nullptr;
    sptr<SurfaceBuffer> oxygenBuffer = nullptr;
    sptr<SurfaceBuffer> pigmentationBuffer = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};
        auto itMain = streamCapture->captureIdMainPhotoMap_.find(captureId);
        if (itMain == streamCapture->captureIdMainPhotoMap_.end()) {
            MEDIA_WARNING_LOG("AssembleCompressedPhotoWithAux captureId:%{public}d already assembled", captureId);
            return;
        }
        mainBuffer = itMain->second;
        streamCapture->captureIdMainPhotoMap_.erase(itMain);
        auto itOxygen = streamCapture->captureIdOxygenMap_.find(captureId);
        if (itOxygen != streamCapture->captureIdOxygenMap_.end() && itOxygen->second != nullptr) {
            oxygenBuffer = itOxygen->second;
        }
        auto itPigmentation = streamCapture->captureIdPigmentationMap_.find(captureId);
        if (itPigmentation != streamCapture->captureIdPigmentationMap_.end() && itPigmentation->second != nullptr) {
            pigmentationBuffer = itPigmentation->second;
        }
        streamCapture->CleanAuxPhotoState(captureId);
        streamCapture->captureIdHandleMap_.erase(captureId);
        streamCapture->captureIdAuxiliaryCountMap_.erase(captureId);
        streamCapture->captureIdCountMap_.erase(captureId);
    }
    CHECK_RETURN_ELOG(mainBuffer == nullptr, "AssembleCompressedPhotoWithAux mainBuffer is nullptr");
    streamCapture->OnPhotoAvailable(mainBuffer, oxygenBuffer, pigmentationBuffer, timestamp, false);
    MEDIA_INFO_LOG("AssembleCompressedPhotoWithAux X, captureId:%{public}d", captureId);
}

#ifdef CAMERA_CAPTURE_YUV
void PhotoBufferConsumer::StartWaitAuxiliaryTask(
    const int32_t captureId, const int32_t auxiliaryCount, int64_t timestamp, sptr<SurfaceBuffer> &newSurfaceBuffer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("StartWaitAuxiliaryTask E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    {
        std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};
        streamCapture->captureIdCountMap_[captureId] = auxiliaryCount;
        streamCapture->captureIdAuxiliaryCountMap_[captureId]++;
        MEDIA_INFO_LOG("PhotoBufferConsumer StartWaitAuxiliaryTask captureId = %{public}d", captureId);

        // create and save pictureProxy
        std::shared_ptr<PictureIntf> pictureProxy = PictureProxy::CreatePictureProxy();
        if (pictureProxy == nullptr) {
            CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::MEDIALIBRARY_ERROR, captureId);
            MEDIA_ERR_LOG("pictureProxy is nullptr");
            return;
        }
        pictureProxy->Create(newSurfaceBuffer);
        MEDIA_INFO_LOG(
            "PhotoBufferConsumer StartWaitAuxiliaryTask MainSurface w=%{public}d, h=%{public}d, f=%{public}d",
            newSurfaceBuffer->GetWidth(), newSurfaceBuffer->GetHeight(), newSurfaceBuffer->GetFormat());
        streamCapture->captureIdPictureMap_[captureId] = pictureProxy;

        // all AuxiliaryBuffer ready, do assamble
        if (streamCapture->captureIdCountMap_[captureId] != 0 &&
            streamCapture->captureIdAuxiliaryCountMap_[captureId] == streamCapture->captureIdCountMap_[captureId]) {
            MEDIA_INFO_LOG(
                "PhotoBufferConsumer StartWaitAuxiliaryTask auxiliaryCount is complete, StopMonitor DoTimeout "
                "captureId = %{public}d",  captureId);
            AssembleDeferredPicture(timestamp, captureId);
        } else {
            // start timeer to do assamble
            uint32_t pictureHandle;
            constexpr uint32_t delayMilli = 1 * 1000;
            MEDIA_INFO_LOG(
                "PhotoBufferConsumer StartWaitAuxiliaryTask GetGlobalWatchdog StartMonitor, captureId=%{public}d",
                captureId);
            auto thisPtr = wptr<PhotoBufferConsumer>(this);
            DeferredProcessing::Watchdog::GetGlobalWatchdog().StartMonitor(
                pictureHandle, delayMilli, [thisPtr, captureId, timestamp](uint32_t handle) {
                    MEDIA_INFO_LOG(
                        "PhotoBufferConsumer PhotoBufferConsumer-Watchdog executed, handle: %{public}d, "
                        "captureId=%{public}d", static_cast<int>(handle), captureId);
                    auto ptr = thisPtr.promote();
                    CHECK_RETURN(ptr == nullptr);
                    ptr->AssembleDeferredPicture(timestamp, captureId);
                    auto streamCapture = ptr->streamCapture_.promote();
                    if (streamCapture && streamCapture->captureIdAuxiliaryCountMap_.count(captureId)) {
                        streamCapture->captureIdAuxiliaryCountMap_[captureId] = -1;
                        MEDIA_INFO_LOG(
                            "PhotoBufferConsumer StartWaitAuxiliaryTask captureIdAuxiliaryCountMap_ = -1, "
                            "captureId=%{public}d", captureId);
                    }
                });
            streamCapture->captureIdHandleMap_[captureId] = pictureHandle;
            MEDIA_INFO_LOG(
                "PhotoBufferConsumer StartWaitAuxiliaryTask, pictureHandle: %{public}d, captureId=%{public}d "
                "captureIdCountMap = %{public}d, captureIdAuxiliaryCountMap = %{public}d",
                pictureHandle, captureId, streamCapture->captureIdCountMap_[captureId],
                streamCapture->captureIdAuxiliaryCountMap_[captureId]);
        }
    }
    MEDIA_INFO_LOG("StartWaitAuxiliaryTask X");
}

inline void LoggingSurfaceBufferInfo(sptr<SurfaceBuffer> buffer, std::string bufName)
{
    if (buffer) {
        MEDIA_INFO_LOG("LoggingSurfaceBufferInfo %{public}s w=%{public}d, h=%{public}d, f=%{public}d",
            bufName.c_str(), buffer->GetWidth(), buffer->GetHeight(), buffer->GetFormat());
    }
};

void PhotoBufferConsumer::CleanAfterTransPicture(int32_t captureId)
{
    MEDIA_INFO_LOG("CleanAfterTransPicture E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};

    streamCapture->captureIdPictureMap_.erase(captureId);
    streamCapture->captureIdGainmapMap_.erase(captureId);
    streamCapture->captureIdDepthMap_.Erase(captureId);
    streamCapture->captureIdExifMap_.erase(captureId);
    streamCapture->captureIdDebugMap_.erase(captureId);
    streamCapture->captureIdAuxiliaryCountMap_.erase(captureId);
    streamCapture->captureIdCountMap_.erase(captureId);
    streamCapture->captureIdHandleMap_.erase(captureId);
    streamCapture->captureIdLhdrGainmapMap_.erase(captureId);
    streamCapture->CleanAuxPhotoState(captureId);
}

namespace {
// Embeds the oxygen/pigmentation auxiliary photo buffers (if delivered) into the main picture
// as OXY_MAP/MEL_MAP auxiliary pictures, and clears the cached buffers on embed.
void AppendAuxiliaryPicturesToMain(const sptr<HStreamCapture>& streamCapture,
    const std::shared_ptr<PictureIntf>& picture, int32_t captureId)
{
    CHECK_RETURN_ELOG(picture == nullptr, "AppendAuxiliaryPicturesToMain picture is nullptr");
    if (streamCapture->captureIdOxygenMap_[captureId]) {
        MEDIA_INFO_LOG("AssembleDeferredPicture oxygenSurfaceBuffer");
        LoggingSurfaceBufferInfo(streamCapture->captureIdOxygenMap_[captureId], "oxygenSurfaceBuffer");
        picture->SetAuxiliaryPicture(
            streamCapture->captureIdOxygenMap_[captureId], CameraAuxiliaryPictureType::OXY_MAP);
        streamCapture->captureIdOxygenMap_[captureId] = nullptr;
    }
    if (streamCapture->captureIdPigmentationMap_[captureId]) {
        MEDIA_INFO_LOG("AssembleDeferredPicture pigmentationSurfaceBuffer");
        LoggingSurfaceBufferInfo(streamCapture->captureIdPigmentationMap_[captureId], "pigmentationSurfaceBuffer");
        picture->SetAuxiliaryPicture(
            streamCapture->captureIdPigmentationMap_[captureId], CameraAuxiliaryPictureType::MEL_MAP);
        streamCapture->captureIdPigmentationMap_[captureId] = nullptr;
    }
}
}

void PhotoBufferConsumer::AssembleDeferredPicture(int64_t timestamp, int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AssembleDeferredPicture E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    std::lock_guard<std::mutex> lock(streamCapture->g_assembleImageMutex);

    std::shared_ptr<PictureIntf> picture = streamCapture->captureIdPictureMap_[captureId];
    if (streamCapture->captureIdExifMap_[captureId] && picture) {
        MEDIA_INFO_LOG("AssembleDeferredPicture exifSurfaceBuffer");
        auto buffer = streamCapture->captureIdExifMap_[captureId];
        LoggingSurfaceBufferInfo(buffer, "exifSurfaceBuffer");
        picture->SetExifMetadata(buffer);
        streamCapture->captureIdExifMap_[captureId] = nullptr;
    }
    if (streamCapture->captureIdGainmapMap_[captureId] && picture) {
        MEDIA_INFO_LOG("AssembleDeferredPicture gainmapSurfaceBuffer");
        LoggingSurfaceBufferInfo(streamCapture->captureIdGainmapMap_[captureId], "gainmapSurfaceBuffer");
        picture->SetAuxiliaryPicture(
            streamCapture->captureIdGainmapMap_[captureId], CameraAuxiliaryPictureType::GAINMAP);
        streamCapture->captureIdGainmapMap_[captureId] = nullptr;
    }
    sptr<SurfaceBuffer> depthBuffer = nullptr;
    streamCapture->captureIdDepthMap_.FindOldAndSetNew(captureId, depthBuffer, nullptr);
    if (depthBuffer && picture) {
        MEDIA_INFO_LOG("AssembleDeferredPicture deepSurfaceBuffer");
        LoggingSurfaceBufferInfo(depthBuffer, "deepSurfaceBuffer");
        picture->SetAuxiliaryPicture(depthBuffer, CameraAuxiliaryPictureType::DEPTH_MAP);
    }
    if (streamCapture->captureIdDebugMap_[captureId] && picture) {
        MEDIA_INFO_LOG("AssembleDeferredPicture debugSurfaceBuffer");
        auto buffer = streamCapture->captureIdDebugMap_[captureId];
        LoggingSurfaceBufferInfo(buffer, "debugSurfaceBuffer");
        picture->SetMaintenanceData(buffer);
        streamCapture->captureIdDebugMap_[captureId] = nullptr;
    }
    if (streamCapture->captureIdLhdrGainmapMap_[captureId] && picture) {
        MEDIA_INFO_LOG("AssembleDeferredPicture lhdrGainmapSurfaceBuffer");
        LoggingSurfaceBufferInfo(streamCapture->captureIdLhdrGainmapMap_[captureId], "lhdrGainmapSurfaceBuffer");
        picture->SetAuxiliaryPicture(
            streamCapture->captureIdLhdrGainmapMap_[captureId], CameraAuxiliaryPictureType::LHDR_GAINMAP);
        streamCapture->captureIdLhdrGainmapMap_[captureId] = nullptr;
    }
    AppendAuxiliaryPicturesToMain(streamCapture, picture, captureId);
    CHECK_RETURN_ELOG(!picture, "CreateMediaLibrary picture is nullptr");
    streamCapture->OnPhotoAvailable(picture);

    CleanAfterTransPicture(captureId);
    MEDIA_INFO_LOG("AssembleDeferredPicture X, captureId:%{public}d", captureId);
}
#endif
}  // namespace CameraStandard
}  // namespace OHOS