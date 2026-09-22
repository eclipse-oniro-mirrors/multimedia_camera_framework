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
// LCOV_EXCL_START
#include "photo_asset_auxiliary_consumer.h"

#include "camera_log.h"
#include "hstream_capture.h"
#include "task_manager.h"
#include "camera_surface_buffer_util.h"
#include "buffer_extra_data_impl.h"
#include "watch_dog.h"

namespace OHOS {
namespace CameraStandard {
namespace {
sptr<Surface> GetAuxConsumerSurface(const sptr<HStreamCapture>& streamCapture, const std::string& surfaceName)
{
    if (surfaceName == S_GAINMAP) {
        return streamCapture->gainmapSurface_.Get();
    } else if (surfaceName == S_DEEP) {
        return streamCapture->deepSurface_.Get();
    } else if (surfaceName == S_EXIF) {
        return streamCapture->exifSurface_.Get();
    } else if (surfaceName == S_DEBUG) {
        return streamCapture->debugSurface_.Get();
    } else if (surfaceName == S_LHDR_GAINMAP) {
        return streamCapture->lhdrGainmapSurface_.Get();
    } else if (surfaceName == S_OXYGEN_PHOTO) {
        return streamCapture->oxygenSurface_.Get();
    } else if (surfaceName == S_PIGMENTATION_PHOTO) {
        return streamCapture->pigmentationSurface_.Get();
    }
    return nullptr;
}

// Caller must hold HStreamCapture::g_photoImageMutex.
void CacheAuxConsumerBuffer(const sptr<HStreamCapture>& streamCapture, const std::string& surfaceName,
    int32_t captureId, const sptr<SurfaceBuffer>& surfaceBuffer)
{
    if (surfaceName == S_GAINMAP) {
        streamCapture->captureIdGainmapMap_[captureId] = surfaceBuffer;
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer gainmapSurfaceBuffer_, captureId=%{public}d", captureId);
    } else if (surfaceName == S_DEEP) {
        streamCapture->captureIdDepthMap_.EnsureInsert(captureId, surfaceBuffer);
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer deepSurfaceBuffer_, captureId=%{public}d", captureId);
    } else if (surfaceName == S_EXIF) {
        streamCapture->captureIdExifMap_[captureId] = surfaceBuffer;
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer exifSurfaceBuffer_, captureId=%{public}d", captureId);
    } else if (surfaceName == S_DEBUG) {
        streamCapture->captureIdDebugMap_[captureId] = surfaceBuffer;
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer debugSurfaceBuffer_, captureId=%{public}d", captureId);
    } else if (surfaceName == S_LHDR_GAINMAP) {
        streamCapture->captureIdLhdrGainmapMap_[captureId] = surfaceBuffer;
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer lhdrGainmapSurfaceBuffer_, captureId=%{public}d", captureId);
    } else if (surfaceName == S_OXYGEN_PHOTO) {
        streamCapture->captureIdOxygenMap_[captureId] = surfaceBuffer;
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer oxygenSurfaceBuffer_, captureId=%{public}d", captureId);
    } else if (surfaceName == S_PIGMENTATION_PHOTO) {
        streamCapture->captureIdPigmentationMap_[captureId] = surfaceBuffer;
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer pigmentationSurfaceBuffer_, captureId=%{public}d", captureId);
    }
}
} // namespace

AuxiliaryBufferConsumer::AuxiliaryBufferConsumer(const std::string surfaceName, wptr<HStreamCapture> streamCapture)
    : surfaceName_(surfaceName), streamCapture_(streamCapture)
{
    MEDIA_INFO_LOG("AuxiliaryBufferConsumer new E, surfaceName:%{public}s", surfaceName_.c_str());
}

AuxiliaryBufferConsumer::~AuxiliaryBufferConsumer()
{
    MEDIA_INFO_LOG("AuxiliaryBufferConsumer ~ E, surfaceName:%{public}s", surfaceName_.c_str());
}

void AuxiliaryBufferConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("OnBufferAvailable E, surfaceName:%{public}s", surfaceName_.c_str());
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    wptr<AuxiliaryBufferConsumer> thisPtr(this);
    if (surfaceName_ == S_OXYGEN_PHOTO || surfaceName_ == S_PIGMENTATION_PHOTO) {
        CHECK_RETURN_ELOG(streamCapture->photoSubAuxPhotoTask_ == nullptr, "photoSubAuxPhotoTask is null");
        streamCapture->photoSubAuxPhotoTask_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
        });
        MEDIA_INFO_LOG("OnBufferAvailable X");
        return;
    }
    CHECK_RETURN_ELOG(streamCapture->photoSubExifTask_ == nullptr, "photoSubTask is null");
    CHECK_RETURN_ELOG(streamCapture->photoSubGainMapTask_ == nullptr, "photoSubTask is null");
    CHECK_RETURN_ELOG(streamCapture->photoSubDebugTask_ == nullptr, "photoSubTask is null");
    CHECK_RETURN_ELOG(streamCapture->photoSubDeepTask_ == nullptr, "photoSubTask is null");
    if (surfaceName_ == S_EXIF) {
        streamCapture->photoSubExifTask_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
        });
    } else if (surfaceName_ == S_GAINMAP) {
        streamCapture->photoSubGainMapTask_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
        });
    } else if (surfaceName_ == S_DEEP) {
        streamCapture->photoSubDebugTask_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
        });
    } else if (surfaceName_ == S_DEBUG) {
        streamCapture->photoSubDeepTask_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
        });
    }
    MEDIA_INFO_LOG("OnBufferAvailable X");
}

void AuxiliaryBufferConsumer::ExecuteOnBufferAvailable()
{
    MEDIA_INFO_LOG("A_ExecuteOnBufferAvailable E, surfaceName:%{public}s", surfaceName_.c_str());
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    sptr<Surface> surface = GetAuxConsumerSurface(streamCapture, surfaceName_);
    // acquire copy release buffer
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    CHECK_RETURN_ELOG(surface == nullptr, "surface is null");
    SurfaceError surfaceRet = surface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_INFO_LOG("AuxiliaryBufferConsumer surfaceName = %{public}s AcquireBuffer end", surfaceName_.c_str());
    CHECK_PRINT_ELOG(surfaceRet != SURFACE_ERROR_OK, "AuxiliaryBufferConsumer Failed to acquire surface buffer");
    sptr<SurfaceBuffer> newSurfaceBuffer = CameraSurfaceBufferUtil::DeepCopyBuffer(surfaceBuffer);
    surface->ReleaseBuffer(surfaceBuffer, -1);
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "newSurfaceBuffer is null");
    if (surfaceName_ == S_EXIF) {
        int32_t dataSize = CameraSurfaceBufferUtil::GetDataSize(newSurfaceBuffer);
        sptr<BufferExtraData> extraData = newSurfaceBuffer->GetExtraData();
        extraData->ExtraSet("exifDataSize", dataSize);
        newSurfaceBuffer->SetExtraData(extraData);
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer exifDataSize = %{public}d", dataSize);
    }

    int32_t captureId = CameraSurfaceBufferUtil::GetMaskCaptureId(newSurfaceBuffer);
    MEDIA_INFO_LOG("AuxiliaryBufferConsumer captureId:%{public}d", captureId);
    {
        std::lock_guard<std::recursive_mutex> lock{streamCapture->g_photoImageMutex};
        if (surfaceName_ == S_OXYGEN_PHOTO || surfaceName_ == S_PIGMENTATION_PHOTO) {
            CHECK_RETURN_ILOG(streamCapture->captureIdAuxDegradeMap_.count(captureId) != 0 &&
                streamCapture->captureIdAuxDegradeMap_[captureId] != 0,
                "AuxiliaryBufferConsumer degraded capture, buffer dropped, captureId=%{public}d", captureId);
        }
        if (streamCapture->captureIdAuxiliaryCountMap_.count(captureId)) {
            int32_t auxiliaryCount = streamCapture->captureIdAuxiliaryCountMap_[captureId];
            int32_t expectCount = streamCapture->captureIdCountMap_[captureId];
            // AuxiliaryBuffer unexpected
            CHECK_RETURN_ILOG(auxiliaryCount == -1 || (expectCount != 0 && auxiliaryCount == expectCount),
                "AuxiliaryBufferConsumer ReleaseBuffer, captureId=%{public}d", captureId);
        }
        // cache buffer and check assemble
        streamCapture->captureIdAuxiliaryCountMap_[captureId]++;
        CacheAuxConsumerBuffer(streamCapture, surfaceName_, captureId, newSurfaceBuffer);
        MEDIA_INFO_LOG("AuxiliaryBufferConsumer auxiliaryPhotoCount = %{public}d, captureCount = %{public}d, "
                       "surfaceName=%{public}s, captureId=%{public}d",
            streamCapture->captureIdAuxiliaryCountMap_[captureId], streamCapture->captureIdCountMap_[captureId],
            surfaceName_.c_str(), captureId);
        if (streamCapture->captureIdCountMap_[captureId] != 0 &&
            streamCapture->captureIdAuxiliaryCountMap_[captureId] == streamCapture->captureIdCountMap_[captureId]) {
            uint32_t pictureHandle = streamCapture->captureIdHandleMap_[captureId];
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer StopMonitor, surfaceName=%{public}s, pictureHandle = %{public}d, "
                           "captureId = %{public}d",
                surfaceName_.c_str(), pictureHandle, captureId);
            streamCapture->captureIdAuxiliaryCountMap_[captureId] = -1;
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer captureIdAuxiliaryCountMap_ = -1");
            DeferredProcessing::Watchdog::GetGlobalWatchdog().DoTimeout(pictureHandle);
            DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(pictureHandle);
        }
    }
    MEDIA_INFO_LOG("A_ExecuteOnBufferAvailable X");
}
}  // namespace CameraStandard
}  // namespace OHOS
// LCOV_EXCL_STOP