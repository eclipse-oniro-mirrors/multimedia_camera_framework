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

#include "photo_asset_buffer_consumer.h"

#include "camera_log.h"
#include "video_key_info.h"
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

PhotoAssetBufferConsumer::PhotoAssetBufferConsumer(wptr<HStreamCapture> streamCapture) : streamCapture_(streamCapture)
{
    MEDIA_INFO_LOG("PhotoAssetBufferConsumer new E");
}

PhotoAssetBufferConsumer::~PhotoAssetBufferConsumer()
{
    MEDIA_INFO_LOG("PhotoAssetBufferConsumer ~ E");
}

void PhotoAssetBufferConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("OnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    auto photoTask = streamCapture->photoTask_.Get();
    CHECK_RETURN_ELOG(photoTask == nullptr, "photoTask is null");
    wptr<PhotoAssetBufferConsumer> thisPtr(this);
    photoTask->SubmitTask([thisPtr]() {
        auto listener = thisPtr.promote();
        CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
    });

    MEDIA_INFO_LOG("OnBufferAvailable X");
}

void PhotoAssetBufferConsumer::ExecuteOnBufferAvailable()
{
    MEDIA_INFO_LOG("PA_ExecuteOnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    CHECK_RETURN_ELOG(streamCapture->surface_ == nullptr, "surface is null");
    streamCapture->ElevateThreadPriority();
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = streamCapture->surface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire surface buffer");
    CameraSurfaceBufferUtil::DumpSurfaceBuffer(surfaceBuffer);
    // deep copy surfaceBuffer
    sptr<SurfaceBuffer> newSurfaceBuffer = CameraSurfaceBufferUtil::DeepCopyBuffer(surfaceBuffer);
    // release surfaceBuffer to bufferQueue
    streamCapture->surface_->ReleaseBuffer(surfaceBuffer, -1);
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "DeepCopyBuffer faild");
    int32_t originCaptureId = CameraSurfaceBufferUtil::GetCaptureId(newSurfaceBuffer);
    int32_t captureId = CameraSurfaceBufferUtil::GetMaskCaptureId(newSurfaceBuffer);
    int32_t unMaskedCaptureId = CameraSurfaceBufferUtil::GetCaptureId(newSurfaceBuffer);
    CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::PHOTO_AVAILABLE, unMaskedCaptureId);
    MEDIA_DEBUG_LOG("OnBufferAvailable unMaskedCaptureId:%{public}d", unMaskedCaptureId);
    CameraReportDfxUtils::GetInstance()->SetFirstBufferEndInfo(unMaskedCaptureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyStartInfo(unMaskedCaptureId);
    int32_t auxiliaryCount = CameraSurfaceBufferUtil::GetImageCount(newSurfaceBuffer);
    MEDIA_INFO_LOG("OnBufferAvailable captureId:%{public}d auxiliaryCount:%{public}d", captureId, auxiliaryCount);
    // create photoProxy
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->GetServerPhotoProxyInfo(newSurfaceBuffer);

    std::string uri;
    int32_t cameraShotType = 0;
    std::string burstKey;
    bool isYuv = streamCapture->isYuvCapture_;
    MEDIA_INFO_LOG("CreateMediaLibrary captureId:%{public}d isYuv::%{public}d", captureId, isYuv);
#ifdef CAMERA_CAPTURE_YUV
    if (isYuv) {
        StartWaitAuxiliaryTask(originCaptureId, captureId, auxiliaryCount, timestamp, newSurfaceBuffer);
    } else {
#endif
        streamCapture->CreateMediaLibrary(cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp);
        MEDIA_INFO_LOG("CreateMediaLibrary uri:%{public}s", uri.c_str());
        streamCapture->OnPhotoAssetAvailable(originCaptureId, uri, cameraShotType, burstKey);
#ifdef CAMERA_CAPTURE_YUV
    }
#endif

    MEDIA_INFO_LOG("PA_ExecuteOnBufferAvailable X");
}

inline void LoggingSurfaceBufferInfo(sptr<SurfaceBuffer> buffer, std::string bufName)
{
    if (buffer) {
        MEDIA_INFO_LOG("LoggingSurfaceBufferInfo %{public}s w=%{public}d, h=%{public}d, f=%{public}d",
            bufName.c_str(), buffer->GetWidth(), buffer->GetHeight(), buffer->GetFormat());
    }
};

#ifdef CAMERA_CAPTURE_YUV
// LCOV_EXCL_START
void PhotoAssetBufferConsumer::StartWaitAuxiliaryTask(const int32_t originCaptureId, const int32_t captureId,
    const int32_t auxiliaryCount, int64_t timestamp, sptr<SurfaceBuffer> &newSurfaceBuffer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("StartWaitAuxiliaryTask E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    {
        std::lock_guard<std::mutex> lock(streamCapture->g_photoImageMutex);
        // create and save photoProxy
        streamCapture->captureIdCountMap_[captureId] = auxiliaryCount;
        streamCapture->captureIdAuxiliaryCountMap_[captureId]++;
        MEDIA_INFO_LOG("PhotoAssetBufferConsumer StartWaitAuxiliaryTask 4 captureId = %{public}d", captureId);
        sptr<CameraServerPhotoProxy> photoProxy = new CameraServerPhotoProxy();
        photoProxy->GetServerPhotoProxyInfo(newSurfaceBuffer);
        photoProxy->SetDisplayName(CreateDisplayName(suffixJpeg));
        streamCapture->photoProxyMap_[captureId] = photoProxy;
        MEDIA_INFO_LOG("PhotoAssetBufferConsumer StartWaitAuxiliaryTask 5");

        // create and save pictureProxy
        std::shared_ptr<PictureIntf> pictureProxy = PictureProxy::CreatePictureProxy();
        if (pictureProxy == nullptr) {
            int32_t unMaskedCaptureId = CameraSurfaceBufferUtil::GetCaptureId(newSurfaceBuffer);
            CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::MEDIALIBRARY_ERROR, unMaskedCaptureId);
            MEDIA_ERR_LOG("pictureProxy is nullptr");
            return;
        }
        pictureProxy->Create(newSurfaceBuffer);
        MEDIA_INFO_LOG(
            "PhotoAssetBufferConsumer StartWaitAuxiliaryTask MainSurface w=%{public}d, h=%{public}d, f=%{public}d",
            newSurfaceBuffer->GetWidth(), newSurfaceBuffer->GetHeight(), newSurfaceBuffer->GetFormat());
        streamCapture->captureIdPictureMap_[captureId] = pictureProxy;

        // all AuxiliaryBuffer ready, do assamble
        if (streamCapture->captureIdCountMap_[captureId] != 0 &&
            streamCapture->captureIdAuxiliaryCountMap_[captureId] == streamCapture->captureIdCountMap_[captureId]) {
            MEDIA_INFO_LOG(
                "PhotoAssetBufferConsumer StartWaitAuxiliaryTask auxiliaryCount is complete, StopMonitor DoTimeout "
                "captureId = %{public}d",  captureId);
            AssembleDeferredPicture(timestamp, captureId, originCaptureId);
        } else {
            // start timeer to do assamble
            uint32_t pictureHandle = 0;
            constexpr uint32_t delayMilli = 1 * 1000;
            MEDIA_INFO_LOG(
                "PhotoAssetBufferConsumer StartWaitAuxiliaryTask GetGlobalWatchdog StartMonitor, captureId=%{public}d",
                captureId);
            auto thisPtr = wptr<PhotoAssetBufferConsumer>(this);
            DeferredProcessing::Watchdog::GetGlobalWatchdog().StartMonitor(
                pictureHandle, delayMilli, [thisPtr, captureId, originCaptureId, timestamp](uint32_t handle) {
                    MEDIA_INFO_LOG(
                        "PhotoAssetBufferConsumer PhotoAssetBufferConsumer-Watchdog executed, handle: %{public}d, "
                        "captureId=%{public}d", static_cast<int>(handle), captureId);
                    auto ptr = thisPtr.promote();
                    CHECK_RETURN(ptr == nullptr);
                    ptr->AssembleDeferredPicture(timestamp, captureId, originCaptureId);
                    auto streamCapture = ptr->streamCapture_.promote();
                    if (streamCapture && streamCapture->captureIdAuxiliaryCountMap_.count(captureId)) {
                        streamCapture->captureIdAuxiliaryCountMap_[captureId] = -1;
                        MEDIA_INFO_LOG(
                            "PhotoAssetBufferConsumer StartWaitAuxiliaryTask captureIdAuxiliaryCountMap_ = -1, "
                            "captureId=%{public}d", captureId);
                    }
                });
            streamCapture->captureIdHandleMap_[captureId] = pictureHandle;
            MEDIA_INFO_LOG(
                "PhotoAssetBufferConsumer StartWaitAuxiliaryTask, pictureHandle: %{public}d, captureId=%{public}d "
                "captureIdCountMap = %{public}d, captureIdAuxiliaryCountMap = %{public}d",
                pictureHandle, captureId, streamCapture->captureIdCountMap_[captureId],
                streamCapture->captureIdAuxiliaryCountMap_[captureId]);
        }
    }
    MEDIA_INFO_LOG("StartWaitAuxiliaryTask X");
}

void PhotoAssetBufferConsumer::CleanAfterTransPicture(int32_t captureId)
{
    MEDIA_INFO_LOG("CleanAfterTransPicture E, captureId:%{public}d", captureId);
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");

    streamCapture->photoProxyMap_.erase(captureId);
    streamCapture->captureIdPictureMap_.erase(captureId);
    streamCapture->captureIdGainmapMap_.erase(captureId);
    streamCapture->captureIdDepthMap_.Erase(captureId);
    streamCapture->captureIdExifMap_.erase(captureId);
    streamCapture->captureIdDebugMap_.erase(captureId);
    streamCapture->captureIdAuxiliaryCountMap_.erase(captureId);
    streamCapture->captureIdCountMap_.erase(captureId);
    streamCapture->captureIdHandleMap_.erase(captureId);
}

void PhotoAssetBufferConsumer::AssembleDeferredPicture(int64_t timestamp, int32_t captureId, int32_t originCaptureId)
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
    std::string uri;
    int32_t cameraShotType;
    std::string burstKey = "";
    MEDIA_DEBUG_LOG("AssembleDeferredPicture CreateMediaLibrary E");
    streamCapture->CreateMediaLibrary(
        picture, streamCapture->photoProxyMap_[captureId], uri, cameraShotType, burstKey, timestamp);
    MEDIA_DEBUG_LOG("AssembleDeferredPicture CreateMediaLibrary X");
    MEDIA_INFO_LOG("CreateMediaLibrary result %{public}s, type %{public}d", uri.c_str(), cameraShotType);
    streamCapture->OnPhotoAssetAvailable(originCaptureId, uri, cameraShotType, burstKey);
    CleanAfterTransPicture(captureId);
    MEDIA_INFO_LOG("AssembleDeferredPicture X, captureId:%{public}d", captureId);
}
#endif
}  // namespace CameraStandard
}  // namespace OHOS
// LCOV_EXCL_STOP