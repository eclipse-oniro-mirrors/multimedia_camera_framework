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
#include "photo_asset_auxiliary_consumer.h"

#include "camera_log.h"
#include "hstream_capture.h"
#include "task_manager.h"
#include "camera_surface_buffer_util.h"
#include "buffer_extra_data_impl.h"
#include "watch_dog.h"

namespace OHOS {
namespace CameraStandard {

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
    CHECK_RETURN_ELOG(streamCapture->photoSubTask_ == nullptr, "photoSubTask is null");
    wptr<AuxiliaryBufferConsumer> thisPtr(this);
    streamCapture->photoSubTask_->SubmitTask([thisPtr]() {
        auto listener = thisPtr.promote();
        CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
    });

    MEDIA_INFO_LOG("OnBufferAvailable X");
}

void AuxiliaryBufferConsumer::ExecuteOnBufferAvailable()
{
    MEDIA_INFO_LOG("A_ExecuteOnBufferAvailable E, surfaceName:%{public}s", surfaceName_.c_str());
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    sptr<Surface> surface;
    if (surfaceName_ == S_GAINMAP) {
        surface = streamCapture->gainmapSurface_;
    } else if (surfaceName_ == S_DEEP) {
        surface = streamCapture->deepSurface_;
    } else if (surfaceName_ == S_EXIF) {
        surface = streamCapture->exifSurface_;
    } else if (surfaceName_ == S_DEBUG) {
        surface = streamCapture->debugSurface_;
    }
    // acquire copy release buffer
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = surface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_INFO_LOG("AuxiliaryBufferConsumer surfaceName = %{public}s AcquireBuffer end", surfaceName_.c_str());
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("AuxiliaryBufferConsumer Failed to acquire surface buffer");
    }
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
        std::lock_guard<std::mutex> lock(streamCapture->g_photoImageMutex);
        if (streamCapture->captureIdAuxiliaryCountMap_.count(captureId)) {
            int32_t auxiliaryCount = streamCapture->captureIdAuxiliaryCountMap_[captureId];
            int32_t expectCount = streamCapture->captureIdCountMap_[captureId];
            // AuxiliaryBuffer unexpected
            if (auxiliaryCount == -1 || (expectCount != 0 && auxiliaryCount == expectCount)) {
                MEDIA_INFO_LOG("AuxiliaryBufferConsumer ReleaseBuffer, captureId=%{public}d", captureId);
                return;
            }
        }
        // cache buffer and check assemble
        streamCapture->captureIdAuxiliaryCountMap_[captureId]++;
        if (surfaceName_ == S_GAINMAP) {
            streamCapture->captureIdGainmapMap_[captureId] = newSurfaceBuffer;
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer gainmapSurfaceBuffer_, captureId=%{public}d", captureId);
        } else if (surfaceName_ == S_DEEP) {
            streamCapture->captureIdDepthMap_.EnsureInsert(captureId, newSurfaceBuffer);
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer deepSurfaceBuffer_, captureId=%{public}d", captureId);
        } else if (surfaceName_ == S_EXIF) {
            streamCapture->captureIdExifMap_[captureId] = newSurfaceBuffer;
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer exifSurfaceBuffer_, captureId=%{public}d", captureId);
        } else if (surfaceName_ == S_DEBUG) {
            streamCapture->captureIdDebugMap_[captureId] = newSurfaceBuffer;
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer debugSurfaceBuffer_, captureId=%{public}d", captureId);
        }
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
            DeferredProcessing::Watchdog::GetGlobalWatchdog().DoTimeout(pictureHandle);
            DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(pictureHandle);
            streamCapture->captureIdAuxiliaryCountMap_[captureId] = -1;
            MEDIA_INFO_LOG("AuxiliaryBufferConsumer captureIdAuxiliaryCountMap_ = -1");
        }
    }
    MEDIA_INFO_LOG("A_ExecuteOnBufferAvailable X");
}
}  // namespace CameraStandard
}  // namespace OHOS