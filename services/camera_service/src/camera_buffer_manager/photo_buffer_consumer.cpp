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
#include "camera_report_dfx_uitls.h"
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
    CameraReportDfxUtils::GetInstance()->SetFirstBufferEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyStartInfo(captureId);
    bool isSystemApp = PhotoLevelManager::GetInstance().GetPhotoLevelInfo(captureId);
    if (!isSystemApp && streamCapture_->isYuvCapture_) {
        int32_t auxiliaryCount = CameraSurfaceBufferUtil::GetImageCount(newSurfaceBuffer);
        MEDIA_INFO_LOG("OnBufferAvailable captureId:%{public}d auxiliaryCount:%{public}d", captureId, auxiliaryCount);
        StartWaitAuxiliaryTask(captureId, auxiliaryCount, timestamp, newSurfaceBuffer);
    } else {
        streamCapture->OnPhotoAvailable(newSurfaceBuffer, timestamp, isRaw_);
    }
    MEDIA_INFO_LOG("P_ExecuteOnBufferAvailable X");
}

void PhotoBufferConsumer::StartWaitAuxiliaryTask(
    const int32_t captureId, const int32_t auxiliaryCount, int64_t timestamp, sptr<SurfaceBuffer> &newSurfaceBuffer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("StartWaitAuxiliaryTask E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    {
        std::lock_guard<std::mutex> lock(streamCapture->g_photoImageMutex);
        streamCapture->captureIdCountMap_[captureId] = auxiliaryCount;
        streamCapture->captureIdAuxiliaryCountMap_[captureId]++;
        MEDIA_INFO_LOG("PhotoBufferConsumer StartWaitAuxiliaryTask captureId = %{public}d", captureId);

        // create and save pictureProxy
        std::shared_ptr<PictureIntf> pictureProxy = PictureProxy::CreatePictureProxy();
        CHECK_RETURN_ELOG(pictureProxy == nullptr, "pictureProxy is nullptr");
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

    streamCapture->captureIdPictureMap_.erase(captureId);
    streamCapture->captureIdGainmapMap_.erase(captureId);
    streamCapture->captureIdDepthMap_.Erase(captureId);
    streamCapture->captureIdExifMap_.erase(captureId);
    streamCapture->captureIdDebugMap_.erase(captureId);
    streamCapture->captureIdAuxiliaryCountMap_.erase(captureId);
    streamCapture->captureIdCountMap_.erase(captureId);
    streamCapture->captureIdHandleMap_.erase(captureId);
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
    CHECK_RETURN_ELOG(!picture, "CreateMediaLibrary picture is nullptr");
    streamCapture->OnPhotoAvailable(picture);

    CleanAfterTransPicture(captureId);
    MEDIA_INFO_LOG("AssembleDeferredPicture X, captureId:%{public}d", captureId);
}
}  // namespace CameraStandard
}  // namespace OHOS