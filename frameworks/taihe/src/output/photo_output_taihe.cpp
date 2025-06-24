/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "photo_output_taihe.h"
#include "camera_buffer_handle_utils.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "picture_proxy.h"
#include "task_manager.h"
#include "video_key_info.h"
#include "buffer_extra_data_impl.h"
#include "dp_utils.h"
#include "deferred_photo_proxy_taihe.h"
#include "video_key_info.h"
#include "image_receiver.h"
#include "hdr_type.h"

#include "metadata_helper.h"
#include <drivers/interface/display/graphic/common/v1_0/cm_color_space.h>

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace taihe;
using namespace ohos::multimedia::camera;
constexpr int32_t CAPTURE_ID_MASK = 0x0000FFFF;
constexpr int32_t CAPTURE_ID_SHIFT = 16;
static std::mutex g_photoImageMutex;
static std::mutex g_assembleImageMutex;
uint32_t PhotoOutputImpl::photoOutputTaskId_ = CAMERA_PHOTO_OUTPUT_TASKID;

static const std::unordered_map<OHOS::CameraStandard::CM_ColorSpaceType, OHOS::ColorManager::ColorSpaceName>
    COLORSPACE_MAP = {
    {OHOS::CameraStandard::CM_COLORSPACE_NONE, OHOS::ColorManager::ColorSpaceName::NONE},
    {OHOS::CameraStandard::CM_BT601_EBU_FULL, OHOS::ColorManager::ColorSpaceName::BT601_EBU},
    {OHOS::CameraStandard::CM_BT601_SMPTE_C_FULL, OHOS::ColorManager::ColorSpaceName::BT601_SMPTE_C},
    {OHOS::CameraStandard::CM_BT709_FULL, OHOS::ColorManager::ColorSpaceName::BT709},
    {OHOS::CameraStandard::CM_BT2020_HLG_FULL, OHOS::ColorManager::ColorSpaceName::BT2020_HLG},
    {OHOS::CameraStandard::CM_BT2020_PQ_FULL, OHOS::ColorManager::ColorSpaceName::BT2020_PQ},
    {OHOS::CameraStandard::CM_BT601_EBU_LIMIT, OHOS::ColorManager::ColorSpaceName::BT601_EBU_LIMIT},
    {OHOS::CameraStandard::CM_BT601_SMPTE_C_LIMIT, OHOS::ColorManager::ColorSpaceName::BT601_SMPTE_C_LIMIT},
    {OHOS::CameraStandard::CM_BT709_LIMIT, OHOS::ColorManager::ColorSpaceName::BT709_LIMIT},
    {OHOS::CameraStandard::CM_BT2020_HLG_LIMIT, OHOS::ColorManager::ColorSpaceName::BT2020_HLG_LIMIT},
    {OHOS::CameraStandard::CM_BT2020_PQ_LIMIT, OHOS::ColorManager::ColorSpaceName::BT2020_PQ_LIMIT},
    {OHOS::CameraStandard::CM_SRGB_FULL, OHOS::ColorManager::ColorSpaceName::SRGB},
    {OHOS::CameraStandard::CM_P3_FULL, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {OHOS::CameraStandard::CM_P3_HLG_FULL, OHOS::ColorManager::ColorSpaceName::P3_HLG},
    {OHOS::CameraStandard::CM_P3_PQ_FULL, OHOS::ColorManager::ColorSpaceName::P3_PQ},
    {OHOS::CameraStandard::CM_ADOBERGB_FULL, OHOS::ColorManager::ColorSpaceName::ADOBE_RGB},
    {OHOS::CameraStandard::CM_SRGB_LIMIT, OHOS::ColorManager::ColorSpaceName::SRGB_LIMIT},
    {OHOS::CameraStandard::CM_P3_LIMIT, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT},
    {OHOS::CameraStandard::CM_P3_HLG_LIMIT, OHOS::ColorManager::ColorSpaceName::P3_HLG_LIMIT},
    {OHOS::CameraStandard::CM_P3_PQ_LIMIT, OHOS::ColorManager::ColorSpaceName::P3_PQ_LIMIT},
    {OHOS::CameraStandard::CM_ADOBERGB_LIMIT, OHOS::ColorManager::ColorSpaceName::ADOBE_RGB_LIMIT},
    {OHOS::CameraStandard::CM_LINEAR_SRGB, OHOS::ColorManager::ColorSpaceName::LINEAR_SRGB},
    {OHOS::CameraStandard::CM_LINEAR_BT709, OHOS::ColorManager::ColorSpaceName::LINEAR_BT709},
    {OHOS::CameraStandard::CM_LINEAR_P3, OHOS::ColorManager::ColorSpaceName::LINEAR_P3},
    {OHOS::CameraStandard::CM_LINEAR_BT2020, OHOS::ColorManager::ColorSpaceName::LINEAR_BT2020},
    {OHOS::CameraStandard::CM_DISPLAY_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_SRGB},
    {OHOS::CameraStandard::CM_DISPLAY_P3_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_SRGB},
    {OHOS::CameraStandard::CM_DISPLAY_P3_HLG, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_HLG},
    {OHOS::CameraStandard::CM_DISPLAY_P3_PQ, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_PQ},
    {OHOS::CameraStandard::CM_DISPLAY_BT2020_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_SRGB},
    {OHOS::CameraStandard::CM_DISPLAY_BT2020_HLG, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_HLG},
    {OHOS::CameraStandard::CM_DISPLAY_BT2020_PQ, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_PQ}
};

AuxiliaryPhotoListener::AuxiliaryPhotoListener(const std::string surfaceName, const sptr<Surface> surface,
    wptr<OHOS::CameraStandard::PhotoOutput> photoOutput) : surfaceName_(surfaceName),
    surface_(surface), photoOutput_(photoOutput)
{
    if (bufferProcessor_ == nullptr && surface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessorAni>(surface);
    }
}

void AuxiliaryPhotoListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AuxiliaryPhotoListener::OnBufferAvailable is called, surfaceName=%{public}s", surfaceName_.c_str());
    CHECK_ERROR_RETURN_LOG(!surface_, "AuxiliaryPhotoListener photoSurface_ is null");
    auto photoOutput = photoOutput_.promote();
    if (photoOutput->taskManager_) {
        wptr<AuxiliaryPhotoListener> thisPtr(this);
        photoOutput->taskManager_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteDeepCopySurfaceBuffer());
        });
    }
    MEDIA_INFO_LOG("AuxiliaryPhotoListener::OnBufferAvailable is end, surfaceName=%{public}s", surfaceName_.c_str());
}

int32_t GetCaptureId(sptr<SurfaceBuffer> surfaceBuffer)
{
    int32_t captureId;
    int32_t burstSeqId = -1;
    int32_t maskBurstSeqId;
    int32_t invalidSeqenceId = -1;
    int32_t captureIdMask = CAPTURE_ID_MASK;
    int32_t captureIdShit = CAPTURE_ID_SHIFT;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, captureId);
    if (burstSeqId != invalidSeqenceId && captureId >= 0) {
        maskBurstSeqId = ((captureId & captureIdMask) << captureIdShit) | burstSeqId;
        MEDIA_INFO_LOG("PhotoListenerAni captureId:%{public}d, burstSeqId:%{public}d, maskBurstSeqId = %{public}d",
            captureId, burstSeqId, maskBurstSeqId);
        return maskBurstSeqId;
    }
    MEDIA_INFO_LOG("PhotoListenerAni captureId:%{public}d, burstSeqId:%{public}d", captureId, burstSeqId);
    return captureId;
}

void CopyMetaData(sptr<SurfaceBuffer> &inBuffer, sptr<SurfaceBuffer> &outBuffer)
{
    std::vector<uint32_t> keys = {};
    CHECK_ERROR_RETURN_LOG(inBuffer == nullptr, "CopyMetaData: inBuffer is nullptr");
    auto ret = inBuffer->ListMetadataKeys(keys);
    CHECK_ERROR_RETURN_LOG(ret != GSError::GSERROR_OK,
        "CopyMetaData: ListMetadataKeys fail! res=%{public}d", ret);
    for (uint32_t key : keys) {
        std::vector<uint8_t> values;
        ret = inBuffer->GetMetadata(key, values);
        if (ret != 0) {
            MEDIA_INFO_LOG("GetMetadata fail! key = %{public}d res = %{public}d", key, ret);
            continue;
        }
        ret = outBuffer->SetMetadata(key, values);
        if (ret != 0) {
            MEDIA_INFO_LOG("SetMetadata fail! key = %{public}d res = %{public}d", key, ret);
            continue;
        }
    }
}

void AuxiliaryPhotoListener::DeepCopyBuffer(
    sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer, int32_t  captureId) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("AuxiliaryPhotoListener::DeepCopyBuffer w=%{public}d, h=%{public}d, f=%{public}d "
        "surfaceName=%{public}s captureId = %{public}d", surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(),
        surfaceBuffer->GetFormat(), surfaceName_.c_str(), captureId);
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
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    MEDIA_DEBUG_LOG("AuxiliaryPhotoListener::DeepCopyBuffer SurfaceBuffer alloc ret: %{public}d surfaceName=%{public}s "
        "captureId = %{public}d", allocErrorCode, surfaceName_.c_str(), captureId);
    CHECK_ERROR_PRINT_LOG(memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK, "PhotoListenerAni memcpy_s failed");
    CopyMetaData(surfaceBuffer, newSurfaceBuffer);
    MEDIA_DEBUG_LOG("AuxiliaryPhotoListener::DeepCopyBuffer memcpy end surfaceName=%{public}s captureId = %{public}d",
        surfaceName_.c_str(), captureId);
}

void AuxiliaryPhotoListener::ExecuteDeepCopySurfaceBuffer() __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto ExecuteDeepCopySurfaceBuffer surfaceName = %{public}s",
        surfaceName_.c_str());
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s AcquireBuffer before", surfaceName_.c_str());
    SurfaceError surfaceRet = surface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s AcquireBuffer end", surfaceName_.c_str());
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "AuxiliaryPhotoListener Failed to acquire surface buffer");
    int32_t captureId = GetCaptureId(surfaceBuffer);
    int32_t dataSize = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataSize, dataSize);
    // deep copy buffer
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, captureId);
    BufferHandle* bufferHandle = newSurfaceBuffer->GetBufferHandle();
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s ReleaseBuffer captureId=%{public}d, before",
        surfaceName_.c_str(), captureId);
    surface_->ReleaseBuffer(surfaceBuffer, -1);
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s ReleaseBuffer captureId=%{public}d, end",
        surfaceName_.c_str(), captureId);
    CHECK_ERROR_PRINT_LOG(bufferHandle == nullptr, "invalid bufferHandle");
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s Map captureId=%{public}d, before",
        surfaceName_.c_str(), captureId);
    newSurfaceBuffer->Map();
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s Map captureId=%{public}d, end",
        surfaceName_.c_str(), captureId);
    if (surfaceName_ == CONST_EXIF_SURFACE) {
        sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
        extraData->ExtraSet("exifDataSize", dataSize);
        newSurfaceBuffer->SetExtraData(extraData);
        MEDIA_INFO_LOG("AuxiliaryPhotoListener exifDataSize = %{public}d", dataSize);
    }
    MEDIA_INFO_LOG("AuxiliaryPhotoListener surfaceName_ = %{public}s w=%{public}d, h=%{public}d, f=%{public}d"
                   "captureId=%{public}d", surfaceName_.c_str(), newSurfaceBuffer->GetWidth(),
                   newSurfaceBuffer->GetHeight(), newSurfaceBuffer->GetFormat(), captureId);
    {
        std::lock_guard<std::mutex> lock(g_photoImageMutex);
        auto photoOutput = photoOutput_.promote();
        if (photoOutput->captureIdAuxiliaryCountMap_.count(captureId)) {
            int32_t auxiliaryCount = photoOutput->captureIdAuxiliaryCountMap_[captureId];
            int32_t expectCount = photoOutput->captureIdCountMap_[captureId];
            if (auxiliaryCount == -1 || (expectCount != 0 && auxiliaryCount == expectCount)) {
                MEDIA_INFO_LOG("AuxiliaryPhotoListener ReleaseBuffer, captureId=%{public}d", captureId);
                return;
            }
        }
        photoOutput->captureIdAuxiliaryCountMap_[captureId]++;
        switch (SurfaceTypeHelper.ToEnum(surfaceName_)) {
            case SurfaceType::GAINMAP_SURFACE: {
                    photoOutput->captureIdGainmapMap_[captureId] = newSurfaceBuffer;
                    MEDIA_INFO_LOG("AuxiliaryPhotoListener gainmapSurfaceBuffer_, captureId=%{public}d", captureId);
                } break;
            case SurfaceType::DEEP_SURFACE: {
                    photoOutput->captureIdDepthMap_[captureId] = newSurfaceBuffer;
                    MEDIA_INFO_LOG("AuxiliaryPhotoListener deepSurfaceBuffer_, captureId=%{public}d", captureId);
                } break;
            case SurfaceType::EXIF_SURFACE: {
                    photoOutput->captureIdExifMap_[captureId] = newSurfaceBuffer;
                    MEDIA_INFO_LOG("AuxiliaryPhotoListener exifSurfaceBuffer_, captureId=%{public}d", captureId);
                } break;
            case SurfaceType::DEBUG_SURFACE: {
                    photoOutput->captureIdDebugMap_[captureId] = newSurfaceBuffer;
                    MEDIA_INFO_LOG("AuxiliaryPhotoListener debugSurfaceBuffer_, captureId=%{public}d", captureId);
                } break;
            default:
                break;
        }
        MEDIA_INFO_LOG("AuxiliaryPhotoListener auxiliaryPhotoCount = %{public}d, captureCount = %{public}d, "
                       "surfaceName=%{public}s, captureId=%{public}d",
            photoOutput->captureIdAuxiliaryCountMap_[captureId], photoOutput->captureIdCountMap_[captureId],
            surfaceName_.c_str(), captureId);
        if (photoOutput->captureIdCountMap_[captureId] != 0 &&
            photoOutput->captureIdAuxiliaryCountMap_[captureId] == photoOutput->captureIdCountMap_[captureId]) {
            uint32_t handle = photoOutput->captureIdHandleMap_[captureId];
            MEDIA_INFO_LOG("AuxiliaryPhotoListener StopMonitor, surfaceName=%{public}s, handle = %{public}d, "
                           "captureId = %{public}d",
                surfaceName_.c_str(), handle, captureId);
            OHOS::CameraStandard::DeferredProcessing::GetGlobalWatchdog().DoTimeout(handle);
            OHOS::CameraStandard::DeferredProcessing::GetGlobalWatchdog().StopMonitor(handle);
            photoOutput->captureIdAuxiliaryCountMap_[captureId] = -1;
            MEDIA_INFO_LOG("AuxiliaryPhotoListener captureIdAuxiliaryCountMap_ = -1");
        }
        MEDIA_INFO_LOG("AuxiliaryPhotoListener auxiliaryPhotoCount = %{public}d, captureCount = %{public}d, "
                       "surfaceName=%{public}s, captureId=%{public}d",
            photoOutput->captureIdAuxiliaryCountMap_[captureId], photoOutput->captureIdCountMap_[captureId],
            surfaceName_.c_str(), captureId);
    }
}

void PictureListener::InitPictureListeners(wptr<OHOS::CameraStandard::PhotoOutput> photoOutput)
{
    CHECK_ERROR_RETURN_LOG(photoOutput == nullptr, "photoOutput is null");
    SurfaceError ret;
    string retStr = "";
    std::string surfaceName = "";
    if (photoOutput->gainmapSurface_ != nullptr) {
        surfaceName = CONST_GAINMAP_SURFACE;
        gainmapImageListener = new (std::nothrow) AuxiliaryPhotoListener(surfaceName, photoOutput->gainmapSurface_,
            photoOutput);
        ret = photoOutput->gainmapSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener>&)gainmapImageListener);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[gainmap]" : retStr;
    }
    if (photoOutput->deepSurface_ != nullptr) {
        surfaceName = CONST_DEEP_SURFACE;
        deepImageListener = new (std::nothrow) AuxiliaryPhotoListener(surfaceName, photoOutput->deepSurface_,
            photoOutput);
        ret = photoOutput->deepSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener>&)deepImageListener);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[deep]" : retStr;
    }
    if (photoOutput->exifSurface_ != nullptr) {
        surfaceName = CONST_EXIF_SURFACE;
        exifImageListener = new (std::nothrow) AuxiliaryPhotoListener(surfaceName, photoOutput->exifSurface_,
            photoOutput);
        ret = photoOutput->exifSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener>&)exifImageListener);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[exif]" : retStr;
    }
    if (photoOutput->debugSurface_ != nullptr) {
        surfaceName = CONST_DEBUG_SURFACE;
        debugImageListener = new (std::nothrow) AuxiliaryPhotoListener(surfaceName, photoOutput->debugSurface_,
            photoOutput);
        ret = photoOutput->debugSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener>&)debugImageListener);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[debug]" : retStr;
    }
    CHECK_ERROR_PRINT_LOG(retStr != "", "register surface consumer listener failed! type = %{public}s", retStr.c_str());
}

void PhotoOutputCallbackAni::OnCaptureStartedWithInfoCallback(const int32_t captureId, uint32_t exposureTime) const
{
    MEDIA_DEBUG_LOG("OnCaptureStartedWithInfoCallback is called, captureId: %{public}d, exposureTime: %{public}d",
        captureId, exposureTime);
    auto sharePtr = shared_from_this();
    auto task = [captureId, exposureTime, sharePtr]() {
        CaptureStartInfo captureStartInfoAni = {
            .captureId = static_cast<int32_t>(captureId),
            .time = static_cast<int32_t>(exposureTime),
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<CaptureStartInfo const&>(CONST_CAPTURE_START_WITH_INFO, 0,
                "Callback is OK", captureStartInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureStartWithInfo", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureEndedCallback(const int32_t captureId, const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnCaptureEndedCallback is called, captureId: %{public}d, frameCount: %{public}d",
        captureId, frameCount);
    auto sharePtr = shared_from_this();
    auto task = [captureId, frameCount, sharePtr]() {
        CaptureEndInfo captureEndInfoAni = {
            .captureId = static_cast<int32_t>(captureId),
            .frameCount = static_cast<int32_t>(frameCount),
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<CaptureEndInfo const&>(CONST_CAPTURE_END, 0,
                "Callback is OK", captureEndInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnFrameShutterCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutterCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr]() {
        FrameShutterInfo frameShutterInfoAni = {
            .captureId = static_cast<int32_t>(captureId),
            .timestamp = static_cast<int64_t>(timestamp),
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<FrameShutterInfo const&>(CONST_CAPTURE_FRAME_SHUTTER, 0,
                "Callback is OK", frameShutterInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameShutter", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnFrameShutterEndCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutterEndCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr]() {
        FrameShutterEndInfo frameShutterEndInfoAni = {
            .captureId = static_cast<int32_t>(captureId)
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<FrameShutterEndInfo const&>(
                CONST_CAPTURE_FRAME_SHUTTER_END, 0, "Callback is OK", frameShutterEndInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameShutterEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureReadyCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnCaptureReadyCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_READY, 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureReady", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureErrorCallback(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureErrorCallback is called, captureId: %{public}d, errorCode: %{public}d",
        captureId, errorCode);
    auto sharePtr = shared_from_this();
    auto task = [captureId, errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback(CONST_CAPTURE_ERROR, errorCode));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnEstimatedCaptureDurationCallback(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called, duration: %{public}d", duration);
    auto sharePtr = shared_from_this();
    auto task = [duration, sharePtr]() {
        double durationAni = static_cast<double>(duration);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, 0, "Callback is OK", durationAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task,
        "OnEstimatedCaptureDuration", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnOfflineDeliveryFinishedCallback(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnOfflineDeliveryFinished is called, captureId: %{public}d", captureId);
    auto sharePtr = shared_from_this();
    auto task = [captureId, sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnOfflineDeliveryFinished", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureStarted(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnCaptureStarted is called, captureId: %{public}d", captureId);
}

void PhotoOutputCallbackAni::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const
{
    MEDIA_DEBUG_LOG("OnCaptureStarted is called, captureId: %{public}d, exposureTime: %{public}d",
        captureId, exposureTime);
    OnCaptureStartedWithInfoCallback(captureId, exposureTime);
}

void PhotoOutputCallbackAni::OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnCaptureEnded is called, captureId: %{public}d, frameCount: %{public}d",
        captureId, frameCount);
    OnCaptureEndedCallback(captureId, frameCount);
}

void PhotoOutputCallbackAni::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutter is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    OnFrameShutterCallback(captureId, timestamp);
}

void PhotoOutputCallbackAni::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutterEnd is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    OnFrameShutterEndCallback(captureId, timestamp);
}

void PhotoOutputCallbackAni::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnCaptureReady is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    OnCaptureReadyCallback(captureId, timestamp);
}

void PhotoOutputCallbackAni::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureError is called, captureId: %{public}d, errorCode: %{public}d",
        captureId, errorCode);
    OnCaptureErrorCallback(captureId, errorCode);
}

void PhotoOutputCallbackAni::OnEstimatedCaptureDuration(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called, duration: %{public}d", duration);
    OnEstimatedCaptureDurationCallback(duration);
}

void PhotoOutputCallbackAni::OnOfflineDeliveryFinished(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnOfflineDeliveryFinished is called, captureId: %{public}d", captureId);
    OnOfflineDeliveryFinishedCallback(captureId);
}

PhotoListenerAni::PhotoListenerAni(ani_env* env, const sptr<Surface> photoSurface,
    wptr<OHOS::CameraStandard::PhotoOutput> photoOutput)
    : ListenerBase(env), photoSurface_(photoSurface), photoOutput_(photoOutput)
{
    if (bufferProcessor_ == nullptr && photoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessorAni>(photoSurface);
    }
    if (taskManager_ == nullptr) {
        constexpr int32_t numThreads = 1;
        taskManager_ = std::make_shared<OHOS::CameraStandard::DeferredProcessing::TaskManager>("PhotoListenerAni",
            numThreads, false);
    }
}

PhotoListenerAni::~PhotoListenerAni()
{
    if (taskManager_) {
        taskManager_->CancelAllTasks();
        taskManager_.reset();
        taskManager_ = nullptr;
    }
}

int32_t PhotoListenerAni::GetAuxiliaryPhotoCount(sptr<SurfaceBuffer> surfaceBuffer)
{
    int32_t auxiliaryCount;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageCount, auxiliaryCount);
    MEDIA_INFO_LOG("PhotoListenerAni auxiliaryCount:%{public}d", auxiliaryCount);
    return auxiliaryCount;
}

sptr<OHOS::CameraStandard::CameraPhotoProxy> CreateCameraPhotoProxy(sptr<SurfaceBuffer> surfaceBuffer)
{
    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("CreateCameraPhotoProxy isDegradedImage:%{public}d", isDegradedImage);
    int64_t imageId = 0;
    int32_t deferredProcessingType;
    int32_t captureId;
    int32_t burstSeqId = -1;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageId, imageId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredProcessingType, deferredProcessingType);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, captureId);
    // When not in burst mode, burstSequenceId is invalid (-1); otherwise,
    // it is an incrementing serial number starting from 1
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    MEDIA_INFO_LOG("CreateCameraPhotoProxy imageId:%{public}" PRId64 ", "
        "deferredProcessingType:%{public}d, captureId = %{public}d, burstSeqId = %{public}d",
        imageId, deferredProcessingType, captureId, burstSeqId);
    // get buffer handle and photo info
    int32_t photoWidth;
    int32_t photoHeight;
    surfaceBuffer->GetExtraData()->ExtraGet(Ani::Camera::dataWidth, photoWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(Ani::Camera::dataHeight, photoHeight);
    uint64_t size = static_cast<uint64_t>(surfaceBuffer->GetSize());
    int32_t extraDataSize = 0;
    auto res = surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataSize, extraDataSize);
    if (res != 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize error %{public}d", res);
    } else if (extraDataSize <= 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize Ok, but size <= 0");
    } else if (static_cast<uint64_t>(extraDataSize) > size) {
        MEDIA_INFO_LOG("ExtraGet dataSize Ok,but dataSize %{public}d is bigger than bufferSize %{public}" PRIu64,
            extraDataSize, size);
    } else {
        MEDIA_INFO_LOG("ExtraGet dataSize %{public}d", extraDataSize);
        size = static_cast<uint64_t>(extraDataSize);
    }
    int32_t deferredImageFormat = 0;
    res = surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredImageFormat, deferredImageFormat);
    bool isHighQuality = (isDegradedImage == 0);
    MEDIA_INFO_LOG("CreateCameraPhotoProxy deferredImageFormat:%{public}d, isHighQuality = %{public}d, "
        "size:%{public}" PRId64, deferredImageFormat, isHighQuality, size);

    sptr<OHOS::CameraStandard::CameraPhotoProxy> photoProxy = new(std::nothrow) OHOS::CameraStandard::CameraPhotoProxy(
        nullptr, deferredImageFormat, photoWidth, photoHeight, isHighQuality, captureId, burstSeqId);
    std::string imageIdStr = std::to_string(imageId);
    photoProxy->SetDeferredAttrs(imageIdStr, deferredProcessingType, size, deferredImageFormat);
    return photoProxy;
}

void PhotoListenerAni::UpdateMainPictureStageOneJSCallback(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) const
{
    MEDIA_INFO_LOG("PhotoListenerAni:UpdateMainPictureStageOneJSCallback called");
    ExecutePhoto(surfaceBuffer, timestamp);
}

int32_t GetBurstSeqId(int32_t captureId)
{
    const uint32_t burstSeqIdMask = 0xFFFF;
    return captureId > 0 ? (static_cast<uint32_t>(captureId) & burstSeqIdMask) : captureId;
}

inline void LoggingSurfaceBufferInfo(sptr<SurfaceBuffer> buffer, std::string bufName)
{
    if (buffer) {
        MEDIA_INFO_LOG("AssembleAuxiliaryPhoto %{public}s w=%{public}d, h=%{public}d, f=%{public}d", bufName.c_str(),
            buffer->GetWidth(), buffer->GetHeight(), buffer->GetFormat());
    }
};

std::shared_ptr<OHOS::CameraStandard::Location> GetLocationBySettings(
    std::shared_ptr<OHOS::CameraStandard::PhotoCaptureSetting> settings)
{
    auto location = std::make_shared<OHOS::CameraStandard::Location>();
    if (settings) {
        settings->GetLocation(location);
        MEDIA_INFO_LOG("GetLocationBySettings latitude:%{private}f, longitude:%{private}f",
            location->latitude, location->longitude);
    } else {
        MEDIA_ERR_LOG("GetLocationBySettings failed!");
    }
    return location;
}

void CleanAfterTransPicture(sptr<OHOS::CameraStandard::PhotoOutput> photoOutput, int32_t captureId)
{
    CHECK_ERROR_RETURN_LOG(!photoOutput, "CleanAfterTransPicture photoOutput is nullptr");
    photoOutput->photoProxyMap_[captureId] = nullptr;
    photoOutput->photoProxyMap_.erase(captureId);
    photoOutput->captureIdPictureMap_.erase(captureId);
    photoOutput->captureIdGainmapMap_.erase(captureId);
    photoOutput->captureIdDepthMap_.erase(captureId);
    photoOutput->captureIdExifMap_.erase(captureId);
    photoOutput->captureIdDebugMap_.erase(captureId);
    photoOutput->captureIdAuxiliaryCountMap_.erase(captureId);
    photoOutput->captureIdCountMap_.erase(captureId);
    photoOutput->captureIdHandleMap_.erase(captureId);
}

void PhotoListenerAni::UpdatePictureJSCallback(int32_t captureId, const string uri, int32_t cameraShotType,
    const std::string burstKey) const
{
}

void PhotoListenerAni::AssembleAuxiliaryPhoto(int64_t timestamp, int32_t captureId) __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto begin captureId %{public}d, burstSeqId %{public}d",
        captureId, GetBurstSeqId(captureId));
    std::lock_guard<std::mutex> lock(g_assembleImageMutex);
    auto photoOutput = photoOutput_.promote();
    if (photoOutput) {
        auto location = GetLocationBySettings(photoOutput->GetDefaultCaptureSetting());
        CHECK_EXECUTE(location && photoOutput->photoProxyMap_[captureId],
            photoOutput->photoProxyMap_[captureId]->SetLocation(location->latitude, location->longitude));
        std::shared_ptr<OHOS::CameraStandard::PictureIntf> picture = photoOutput->captureIdPictureMap_[captureId];
        if (photoOutput->captureIdExifMap_[captureId] && picture) {
            auto buffer = photoOutput->captureIdExifMap_[captureId];
            LoggingSurfaceBufferInfo(buffer, "exifSurfaceBuffer");
            picture->SetExifMetadata(buffer);
            photoOutput->captureIdExifMap_[captureId] = nullptr;
        }
        if (photoOutput->captureIdGainmapMap_[captureId] && picture) {
            LoggingSurfaceBufferInfo(photoOutput->captureIdGainmapMap_[captureId], "gainmapSurfaceBuffer");
            picture->SetAuxiliaryPicture(photoOutput->captureIdGainmapMap_[captureId],
                OHOS::CameraStandard::CameraAuxiliaryPictureType::GAINMAP);
            photoOutput->captureIdGainmapMap_[captureId] = nullptr;
        }
        if (photoOutput->captureIdDepthMap_[captureId] && picture) {
            LoggingSurfaceBufferInfo(photoOutput->captureIdDepthMap_[captureId], "deepSurfaceBuffer");
            picture->SetAuxiliaryPicture(photoOutput->captureIdDepthMap_[captureId],
                OHOS::CameraStandard::CameraAuxiliaryPictureType::DEPTH_MAP);
            photoOutput->captureIdDepthMap_[captureId] = nullptr;
        }
        if (photoOutput->captureIdDebugMap_[captureId] && picture) {
            auto buffer = photoOutput->captureIdDebugMap_[captureId];
            LoggingSurfaceBufferInfo(buffer, "debugSurfaceBuffer");
            picture->SetMaintenanceData(buffer);
            photoOutput->captureIdDebugMap_[captureId] = nullptr;
        }
        MEDIA_INFO_LOG("AssembleAuxiliaryPhoto end captureId %{public}d, burstSeqId %{public}d",
            captureId, GetBurstSeqId(captureId));
        if (!picture) {
            MEDIA_ERR_LOG("CreateMediaLibrary picture is nullptr");
            return;
        }
        std::string uri;
        int32_t cameraShotType;
        std::string burstKey = "";
        MEDIA_DEBUG_LOG("AssembleAuxiliaryPhoto CreateMediaLibrary E");
        photoOutput->CreateMediaLibrary(picture, photoOutput->photoProxyMap_[captureId],
            uri, cameraShotType, burstKey, timestamp);
        MEDIA_DEBUG_LOG("AssembleAuxiliaryPhoto CreateMediaLibrary X");
        MEDIA_INFO_LOG("CreateMediaLibrary result %{public}s, type %{public}d", uri.c_str(), cameraShotType);
        UpdatePictureJSCallback(captureId, uri, cameraShotType, burstKey);
        CleanAfterTransPicture(photoOutput, captureId);
    }
}

void PhotoListenerAni::ExecuteDeepCopySurfaceBuffer() __attribute__((no_sanitize("cfi")))
{
    auto photoOutput = photoOutput_.promote();
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    sptr<SurfaceBuffer> newSurfaceBuffer = nullptr;
    sptr<OHOS::CameraStandard::CameraPhotoProxy> photoProxy = nullptr;
    int32_t auxiliaryCount = 0;
    int32_t captureId = -1;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    MEDIA_DEBUG_LOG("ExecuteDeepCopySurfaceBuffer AcquireBuffer E");
    SurfaceError surfaceRet = photoSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_DEBUG_LOG("ExecuteDeepCopySurfaceBuffer AcquireBuffer X");
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("PhotoListenerAni Failed to acquire surface buffer");
        return;
    }
    auxiliaryCount = GetAuxiliaryPhotoCount(surfaceBuffer);
    captureId = GetCaptureId(surfaceBuffer);
    if (photoOutput != nullptr) {
        photoOutput->AcquireBufferToPrepareProxy(captureId);
    }
    // deep copy buffer
    newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, captureId);
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    {
        std::lock_guard<std::mutex> lock(g_photoImageMutex);
        photoOutput = photoOutput_.promote();
        photoOutput->captureIdCountMap_[captureId] = auxiliaryCount;
        photoOutput->captureIdAuxiliaryCountMap_[captureId]++;
        photoProxy = CreateCameraPhotoProxy(surfaceBuffer);
        photoOutput->photoProxyMap_[captureId] = photoProxy;
        CHECK_ERROR_RETURN_LOG(!photoProxy, "photoProxy is nullptr");
        if (photoProxy->isHighQuality_ && (callbackFlag_ & OHOS::CameraStandard::CAPTURE_PHOTO) != 0) {
            UpdateMainPictureStageOneJSCallback(surfaceBuffer, timestamp);
            return;
        }

        BufferHandle* bufferHandle = newSurfaceBuffer->GetBufferHandle();
        CHECK_ERROR_RETURN_LOG(bufferHandle == nullptr, "invalid bufferHandle");
        newSurfaceBuffer->Map();
        photoProxy->bufferHandle_ = bufferHandle;

        std::shared_ptr<OHOS::CameraStandard::PictureIntf> pictureProxy =
            OHOS::CameraStandard::PictureProxy::CreatePictureProxy();
        CHECK_ERROR_RETURN_LOG(pictureProxy == nullptr, "pictureProxy is nullptr");
        pictureProxy->Create(newSurfaceBuffer);

        Media::ImageInfo imageInfo;
        MEDIA_INFO_LOG("PhotoListenerAni AssembleAuxiliaryPhoto MainSurface w=%{public}d, h=%{public}d, f=%{public}d",
            newSurfaceBuffer->GetWidth(), newSurfaceBuffer->GetHeight(), newSurfaceBuffer->GetFormat());
        photoOutput->captureIdPictureMap_[captureId] = pictureProxy;
        uint32_t pictureHandle;
        constexpr uint32_t delayMilli = 1 * 1000;
        MEDIA_INFO_LOG("PhotoListenerAni AssembleAuxiliaryPhoto GetGlobalWatchdog StartMonitor, captureId=%{public}d",
            captureId);
        OHOS::CameraStandard::DeferredProcessing::GetGlobalWatchdog().StartMonitor(pictureHandle, delayMilli,
            [this, captureId, timestamp](uint32_t handle) {
                MEDIA_INFO_LOG("PhotoListenerAni PhotoListenerAni-Watchdog executed, handle: %{public}d, "
                    "captureId=%{public}d", static_cast<int>(handle), captureId);
                AssembleAuxiliaryPhoto(timestamp, captureId);
                auto photoOutput = photoOutput_.promote();
                if (photoOutput && photoOutput->captureIdAuxiliaryCountMap_.count(captureId)) {
                    photoOutput->captureIdAuxiliaryCountMap_[captureId] = -1;
                    MEDIA_INFO_LOG("PhotoListenerAni AssembleAuxiliaryPhoto captureIdAuxiliaryCountMap_ = -1, "
                        "captureId=%{public}d", captureId);
                }
        });
        photoOutput->captureIdHandleMap_[captureId] = pictureHandle;
        MEDIA_INFO_LOG("PhotoListenerAni AssembleAuxiliaryPhoto, pictureHandle: %{public}d, captureId=%{public}d "
            "captureIdCountMap = %{public}d, captureIdAuxiliaryCountMap = %{public}d",
            pictureHandle, captureId, photoOutput->captureIdCountMap_[captureId],
            photoOutput->captureIdAuxiliaryCountMap_[captureId]);
        if (photoOutput->captureIdCountMap_[captureId] != 0 &&
            photoOutput->captureIdAuxiliaryCountMap_[captureId] == photoOutput->captureIdCountMap_[captureId]) {
            MEDIA_INFO_LOG("PhotoListenerAni AssembleAuxiliaryPhoto auxiliaryCount is complete, StopMonitor DoTimeout "
                "handle = %{public}d, captureId = %{public}d", pictureHandle, captureId);
            OHOS::CameraStandard::DeferredProcessing::GetGlobalWatchdog().DoTimeout(pictureHandle);
            OHOS::CameraStandard::DeferredProcessing::GetGlobalWatchdog().StopMonitor(pictureHandle);
        }
        MEDIA_INFO_LOG("PhotoListenerAni AssembleAuxiliaryPhoto end");
    }
}

void PhotoListenerAni::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer,
    int32_t captureId) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("PhotoListenerAni::DeepCopyBuffer w=%{public}d, h=%{public}d, f=%{public}d surfaceName=%{public}s "
        "captureId = %{public}d", surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), surfaceBuffer->GetFormat(),
        "main", captureId);
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
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    MEDIA_DEBUG_LOG("PhotoListenerAni::DeepCopyBuffer SurfaceBuffer alloc ret: %{public}d surfaceName=%{public}s "
        "captureId = %{public}d", allocErrorCode, "main", captureId);
    CHECK_ERROR_PRINT_LOG(memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK, "PhotoListenerAni memcpy_s failed");
    CopyMetaData(surfaceBuffer, newSurfaceBuffer);
    MEDIA_DEBUG_LOG("PhotoListenerAni::DeepCopyBuffer memcpy_s end surfaceName=%{public}s captureId = %{public}d",
        "main", captureId);
}

void PhotoListenerAni::UpdateJSCallback(sptr<Surface> photoSurface) const
{
    MEDIA_DEBUG_LOG("PhotoListenerAni UpdateJSCallback enter");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = photoSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "PhotoListenerAni Failed to acquire surface buffer");
    MEDIA_INFO_LOG("PhotoListenerAni::UpdateJSCallback ts is:%{public}" PRId64, timestamp);
    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("PhotoListenerAni UpdateJSCallback isDegradedImage:%{public}d", isDegradedImage);
    if ((callbackFlag_ & OHOS::CameraStandard::CAPTURE_PHOTO_ASSET) != 0) {
        auto photoOutput = photoOutput_.promote();
        if (photoOutput != nullptr) {
            int32_t currentCaptureId = GetCaptureId(surfaceBuffer);
            photoOutput->AcquireBufferToPrepareProxy(currentCaptureId);
        }
        ExecutePhotoAsset(surfaceBuffer, isDegradedImage == 0, timestamp);
    } else if (isDegradedImage == 0 && (callbackFlag_ & OHOS::CameraStandard::CAPTURE_PHOTO) != 0) {
        ExecutePhoto(surfaceBuffer, timestamp);
    } else if (isDegradedImage != 0 && (callbackFlag_ & OHOS::CameraStandard::CAPTURE_DEFERRED_PHOTO) != 0) {
        ExecuteDeferredPhoto(surfaceBuffer);
    } else {
        MEDIA_INFO_LOG("PhotoListenerAni on error callback");
    }
}

void PhotoListenerAni::ExecutePhoto(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) const
{
}

void PhotoListenerAni::ExecuteDeferredPhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecuteDeferredPhoto");
    int32_t errCode = 0;
    std::string message = "success";
    BufferHandle* bufferHandle = surfaceBuffer->GetBufferHandle();
    int64_t imageId;
    int32_t deferredProcessingType;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageId, imageId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredProcessingType, deferredProcessingType);
    MEDIA_INFO_LOG("PhotoListener ExecuteDeferredPhoto imageId:%{public}" PRId64 ", deferredProcessingType:%{public}d",
        imageId, deferredProcessingType);

    // create pixelMap to encode
    int32_t thumbnailWidth;
    int32_t thumbnailHeight;
    surfaceBuffer->GetExtraData()->ExtraGet(dataWidth, thumbnailWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(dataHeight, thumbnailHeight);
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailHeight: %{public}d", thumbnailWidth, thumbnailHeight);

    MEDIA_DEBUG_LOG("w:%{public}d, h:%{public}d, s:%{public}d, fd:%{public}d, size: %{public}d, format: %{public}d",
        bufferHandle->width, bufferHandle->height, bufferHandle->stride, bufferHandle->fd, bufferHandle->size,
        bufferHandle->format);

    // deep copy buffer
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, 0);
    BufferHandle *newBufferHandle = OHOS::CameraStandard::CameraCloneBufferHandle(newSurfaceBuffer->GetBufferHandle());
    if (newBufferHandle == nullptr) {
        errCode = OHOS::CameraStandard::CameraErrorCode::INVALID_ARGUMENT;
        message = "invalid bufferHandle";
        MEDIA_ERR_LOG("invalid bufferHandle");
    }

    // call js function
    sptr<OHOS::CameraStandard::DeferredPhotoProxy> deferredPhotoProxy;
    std::string imageIdStr = std::to_string(imageId);
    deferredPhotoProxy = new(std::nothrow) OHOS::CameraStandard::DeferredPhotoProxy(
            newBufferHandle, imageIdStr, deferredProcessingType, thumbnailWidth, thumbnailHeight);
    if (deferredPhotoProxy == nullptr) {
        errCode = OHOS::CameraStandard::CameraErrorCode::SERVICE_FATL_ERROR;
        message = "failed to new deferredPhotoProxy!";
        MEDIA_ERR_LOG("failed to new deferredPhotoProxy!");
    }
    DeferredPhotoProxy result =
        make_holder<Ani::Camera::DeferredPhotoProxyImpl, DeferredPhotoProxy>(deferredPhotoProxy);

    ExecuteAsyncCallback(CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE,  errCode, message, result);

    // return buffer to buffer queue
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void PhotoListenerAni::ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, bool isHighQuality, int64_t timestamp) const
{
}

void PhotoListenerAni::OnBufferAvailable()
{
    MEDIA_INFO_LOG("PhotoListenerAni::OnBufferAvailable is called");
    auto photoOutput = photoOutput_.promote();
    CHECK_ERROR_RETURN_LOG(photoSurface_ == nullptr || photoOutput == nullptr,
        "PhotoListenerAni photoSurface or photoOutput is null");
    if (!photoOutput->IsYuvOrHeifPhoto()) {
        auto sharePtr = shared_from_this();
        auto task = [photoSurface = photoSurface_, sharePtr]() {
            CHECK_EXECUTE(sharePtr != nullptr, sharePtr->UpdateJSCallback(photoSurface));
        };
        CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureStartWithInfo", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
        MEDIA_INFO_LOG("PhotoListenerAni::OnBufferAvailable is end");
        return;
    }
    if (taskManager_) {
        wptr<PhotoListenerAni> thisPtr(this);
        taskManager_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            CHECK_EXECUTE(listener, listener->ExecuteDeepCopySurfaceBuffer());
        });
    }
    MEDIA_INFO_LOG("PhotoListenerAni::OnBufferAvailable is end");
}

void PhotoListenerAni::SaveCallback(const std::string eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("PhotoListenerAni::SaveCallback is called eventName:%{public}s", eventName.c_str());
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "photoOutput_ is nullptr");
    if (eventName == CONST_CAPTURE_PHOTO_AVAILABLE) {
        callbackFlag_ |= OHOS::CameraStandard::CAPTURE_PHOTO;
    } else {
        MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
        return;
    }
    auto photoOutput = photoOutput_.promote();
    if (photoOutput) {
        photoOutput->SetCallbackFlag(callbackFlag_);
    } else {
        MEDIA_ERR_LOG("cannot get photoOutput");
    }
    SaveCallbackReference(eventName, callback, false);
}

void PhotoListenerAni::RemoveCallback(const std::string eventName, std::shared_ptr<uintptr_t> callback)
{
    MEDIA_INFO_LOG("PhotoListenerAni::RemoveCallback is called eventName:%{public}s", eventName.c_str());
    if (eventName == CONST_CAPTURE_PHOTO_AVAILABLE) {
        callbackFlag_ &= ~OHOS::CameraStandard::CAPTURE_PHOTO;
    }
    RemoveCallbackRef(eventName, callback);
}

RawPhotoListenerAni::RawPhotoListenerAni(ani_env* env, const sptr<Surface> rawPhotoSurface)
    : ListenerBase(env), rawPhotoSurface_(rawPhotoSurface)
{
    if (bufferProcessor_ == nullptr && rawPhotoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessorAni>(rawPhotoSurface);
    }
}

void RawPhotoListenerAni::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("RawPhotoListenerAni::OnBufferAvailable is called");
    CHECK_ERROR_RETURN_LOG(!rawPhotoSurface_, "RawPhotoListenerAni taihe rawPhotoSurface_ is null");
    UpdateJSCallback(rawPhotoSurface_);
}

void RawPhotoListenerAni::ExecuteRawPhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
}

void RawPhotoListenerAni::UpdateJSCallback(sptr<Surface> rawPhotoSurface) const
{
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = rawPhotoSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "RawPhotoListenerAni Failed to acquire surface buffer");

    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("RawPhotoListenerAni UpdateJSCallback isDegradedImage:%{public}d", isDegradedImage);

    if (isDegradedImage == 0) {
        ExecuteRawPhoto(surfaceBuffer);
    } else {
        MEDIA_ERR_LOG("RawPhoto not support deferred photo");
    }
}

ThumbnailListener::ThumbnailListener(ani_env* env, const sptr<OHOS::CameraStandard::PhotoOutput> photoOutput)
    : ListenerBase(env), photoOutput_(photoOutput)
{
    if (taskManager_ == nullptr) {
        constexpr int32_t numThreads = 1;
        taskManager_ = std::make_shared<OHOS::CameraStandard::DeferredProcessing::TaskManager>("ThumbnailListener",
            numThreads, true);
    }
}

ThumbnailListener::~ThumbnailListener()
{
    if (taskManager_) {
        taskManager_->CancelAllTasks();
        taskManager_.reset();
        taskManager_ = nullptr;
    }
}

void ThumbnailListener::ClearTaskManager()
{
    std::lock_guard<std::mutex> lock(taskManagerMutex_);
    if (taskManager_) {
        taskManager_->CancelAllTasks();
        taskManager_.reset();
        taskManager_ = nullptr;
    }
}

void ThumbnailListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ThumbnailListener::OnBufferAvailable is called");
    wptr<ThumbnailListener> thisPtr(this);
    {
        std::lock_guard<std::mutex> lock(taskManagerMutex_);
        if (taskManager_ == nullptr) {
            MEDIA_ERR_LOG("ThumbnailListener::OnBufferAvailable taskManager_ is null");
            return;
        }
        taskManager_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            if (listener) {
                listener->ExecuteDeepCopySurfaceBuffer();
            }
        });
    }
    constexpr int32_t memSize = 20 * 1024;
    int32_t retCode = OHOS::CameraStandard::CameraManager::GetInstance()->RequireMemorySize(memSize);
    CHECK_ERROR_RETURN_LOG(retCode != 0, "ThumbnailListener::OnBufferAvailable RequireMemorySize failed");
    MEDIA_INFO_LOG("ThumbnailListener::OnBufferAvailable is end");
}

OHOS::ColorManager::ColorSpaceName GetColorSpace(sptr<SurfaceBuffer> surfaceBuffer)
{
    OHOS::ColorManager::ColorSpaceName colorSpace = OHOS::ColorManager::ColorSpaceName::NONE;
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;
    GSError gsErr = MetadataHelper::GetColorSpaceType(surfaceBuffer, colorSpaceType);
    if (gsErr != GSERROR_OK) {
        MEDIA_ERR_LOG("Failed to get colorSpaceType from surfaceBuffer!");
        return colorSpace;
    } else {
        MEDIA_INFO_LOG("Get current colorSpaceType is : %{public}d", colorSpaceType);
    }
    auto it = COLORSPACE_MAP.find(colorSpaceType);
    if (it != COLORSPACE_MAP.end()) {
        colorSpace = it->second;
        MEDIA_INFO_LOG("Current get colorSpaceName: %{public}d", colorSpace);
    } else {
        MEDIA_ERR_LOG("Current colorSpace is not supported!");
        return colorSpace;
    }
    return colorSpace;
}

void ThumbnailSetColorSpaceAndRotate(std::unique_ptr<Media::PixelMap>& pixelMap, sptr<SurfaceBuffer> surfaceBuffer,
    OHOS::ColorManager::ColorSpaceName colorSpaceName)
{
    int32_t thumbnailrotation = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataRotation, thumbnailrotation);
    MEDIA_DEBUG_LOG("ThumbnailListener current rotation is : %{public}d", thumbnailrotation);
    if (!pixelMap) {
        MEDIA_ERR_LOG("ThumbnailListener Failed to create PixelMap.");
    } else {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(colorSpaceName));
        pixelMap->rotate(thumbnailrotation);
    }
}

void ThumbnailListener::ExecuteDeepCopySurfaceBuffer()
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = photoOutput_.promote();
    CHECK_ERROR_RETURN_LOG(photoOutput == nullptr, "ThumbnailListener photoOutput is nullptr");
    auto surface = photoOutput->thumbnailSurface_;
    CHECK_ERROR_RETURN_LOG(surface == nullptr, "ThumbnailListener surface is nullptr");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    MEDIA_DEBUG_LOG("ThumbnailListener surfaceName = Thumbnail AcquireBuffer before");
    SurfaceError surfaceRet = surface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_DEBUG_LOG("ThumbnailListener surfaceName = Thumbnail AcquireBuffer end");
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "ThumbnailListener Failed to acquire surface buffer");
    int32_t burstSeqId = -1;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    if (burstSeqId != -1) {
        surface->ReleaseBuffer(surfaceBuffer, -1);
        return;
    }
    int32_t thumbnailWidth = 0;
    int32_t thumbnailHeight = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(dataWidth, thumbnailWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(dataHeight, thumbnailHeight);
    int32_t captureId = GetCaptureId(surfaceBuffer);
    MEDIA_INFO_LOG("ThumbnailListener thumbnailWidth:%{public}d, thumbnailheight: %{public}d, captureId: %{public}d,"
        "burstSeqId: %{public}d", thumbnailWidth, thumbnailHeight, captureId, burstSeqId);
    OHOS::ColorManager::ColorSpaceName colorSpace = GetColorSpace(surfaceBuffer);
    CHECK_ERROR_RETURN_LOG(colorSpace == OHOS::ColorManager::ColorSpaceName::NONE, "Thumbnail GetcolorSpace failed!");
    bool isHdr = colorSpace == OHOS::ColorManager::ColorSpaceName::BT2020_HLG;
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, thumbnailWidth, thumbnailHeight, isHdr);
    std::unique_ptr<Media::PixelMap> pixelMap = CreatePixelMapFromSurfaceBuffer(newSurfaceBuffer,
        thumbnailWidth, thumbnailHeight, isHdr);
    CHECK_ERROR_RETURN_LOG(pixelMap == nullptr, "ThumbnailListener create pixelMap is nullptr");
    ThumbnailSetColorSpaceAndRotate(pixelMap, surfaceBuffer, colorSpace);
    MEDIA_DEBUG_LOG("ThumbnailListener ReleaseBuffer begin");
    surface->ReleaseBuffer(surfaceBuffer, -1);
    MEDIA_DEBUG_LOG("ThumbnailListener ReleaseBuffer end");
    UpdateJSCallbackAsync(captureId, timestamp, std::move(pixelMap));
    auto photoProxy = CreateCameraPhotoProxy(surfaceBuffer);
    if (photoOutput->IsYuvOrHeifPhoto()) {
        constexpr int32_t yuvFormat = 3;
        photoProxy->format_ = yuvFormat;
        photoProxy->imageFormat_ = yuvFormat;
        photoOutput->UpdateMediaLibraryPhotoAssetProxy(photoProxy);
    }
}

void ThumbnailListener::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer,
    int32_t thumbnailWidth, int32_t thumbnailHeight, bool isHdr) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ThumbnailListener::DeepCopyBuffer w=%{public}d, h=%{public}d, f=%{public}d ",
        thumbnailWidth, thumbnailHeight, surfaceBuffer->GetFormat());
    int32_t thumbnailStride = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataStride, thumbnailStride);
    MEDIA_INFO_LOG("ThumbnailListener::DeepCopyBuffer current stride : %{public}d", thumbnailStride);
    BufferRequestConfig requestConfig = {
        .width = thumbnailStride,
        .height = thumbnailHeight,
        .strideAlignment = thumbnailStride,
        .format = surfaceBuffer->GetFormat(),
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    CHECK_ERROR_RETURN_LOG(newSurfaceBuffer == nullptr, "Deep copy surfaceBuffer failed");
    GSError allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    if (allocErrorCode != 0) {
        MEDIA_ERR_LOG("Create surfaceBuffer Alloc failed");
        return;
    }
    MEDIA_INFO_LOG("ThumbnailListener::DeepCopyBuffer SurfaceBuffer alloc ret : %{public}d",
        allocErrorCode);
    int32_t colorLength = thumbnailStride * thumbnailHeight * PIXEL_SIZE_HDR_YUV;
    colorLength = isHdr ? colorLength : colorLength / HDR_PIXEL_SIZE;
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), colorLength) != EOK) {
        MEDIA_ERR_LOG("PhotoListener memcpy_s failed");
        return;
    }
    CopyMetaData(surfaceBuffer, newSurfaceBuffer);
    MEDIA_DEBUG_LOG("ThumbnailListener::DeepCopyBuffer SurfaceBuffer end");
}

std::unique_ptr<Media::PixelMap> ThumbnailListener::CreatePixelMapFromSurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer,
    int32_t width, int32_t height, bool isHdr)
{
    CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, nullptr,
        "ThumbnailListener::CreatePixelMapFromSurfaceBuffer surfaceBuffer is nullptr");
    MEDIA_INFO_LOG("ThumbnailListener Width:%{public}d, height:%{public}d, isHdr:%{public}d, format:%{public}d",
        width, height, isHdr, surfaceBuffer->GetFormat());
    Media::InitializationOptions options {
        .size = { .width = width, .height = height } };
    options.srcPixelFormat = isHdr ? Media::PixelFormat::YCRCB_P010 : Media::PixelFormat::NV12;
    options.pixelFormat = isHdr ? Media::PixelFormat::YCRCB_P010 : Media::PixelFormat::NV12;
    options.useDMA = true;
    options.editable = isHdr; // 10bit支持滤镜可编辑
    int32_t colorLength = width * height * PIXEL_SIZE_HDR_YUV;
    colorLength = isHdr ? colorLength : colorLength / HDR_PIXEL_SIZE;
    std::unique_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(options);
    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    RefBase *ref = reinterpret_cast<RefBase *>(nativeBuffer);
    ref->IncStrongRef(ref);
    if (isHdr) {
        pixelMap->SetHdrType(OHOS::Media::ImageHdrType::HDR_VIVID_SINGLE);
    }
    pixelMap->SetPixelsAddr(surfaceBuffer->GetVirAddr(), surfaceBuffer.GetRefPtr(), colorLength,
        Media::AllocatorType::DMA_ALLOC, nullptr);
    
    MEDIA_DEBUG_LOG("ThumbnailListener::CreatePixelMapFromSurfaceBuffer end");
    return SetPixelMapYuvInfo(surfaceBuffer, std::move(pixelMap), isHdr);
}

std::unique_ptr<Media::PixelMap> ThumbnailListener::SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer,
    std::unique_ptr<Media::PixelMap> pixelMap, bool isHdr)
{
    MEDIA_INFO_LOG("ThumbnailListener::SetPixelMapYuvInf enter");
    uint8_t ratio = isHdr ? HDR_PIXEL_SIZE : SDR_PIXEL_SIZE;
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    Media::YUVDataInfo yuvDataInfo = {
        .yWidth = srcWidth,
        .yHeight = srcHeight,
        .uvWidth = srcWidth / 2,
        .uvHeight = srcHeight / 2,
        .yStride = srcWidth,
        .uvStride = srcWidth,
        .uvOffset = srcWidth * srcHeight
    };
    if (surfaceBuffer == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return pixelMap;
    }
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return pixelMap;
    }
    
    yuvDataInfo.yStride = planes->planes[PLANE_Y].columnStride / ratio;
    yuvDataInfo.uvStride = planes->planes[PLANE_U].columnStride / ratio;
    yuvDataInfo.yOffset = planes->planes[PLANE_Y].offset / ratio;
    yuvDataInfo.uvOffset = planes->planes[PLANE_U].offset / ratio;

    pixelMap->SetImageYUVInfo(yuvDataInfo);
    MEDIA_INFO_LOG("ThumbnailListener::SetPixelMapYuvInf end");
    return pixelMap;
}

void ThumbnailListener::UpdateJSCallbackAsync(int32_t captureId, int64_t timestamp,
    std::unique_ptr<Media::PixelMap> pixelMap)
{
}

void ThumbnailListener::UpdateJSCallback(int32_t captureId, int64_t timestamp,
    std::unique_ptr<Media::PixelMap> pixelMap) const
{
}

PhotoOutputImpl::PhotoOutputImpl(sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    photoOutput_ = static_cast<OHOS::CameraStandard::PhotoOutput*>(output.GetRefPtr());
}

void PhotoOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "photoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "photoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->photoOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

const PhotoOutputImpl::EmitterFunctions& PhotoOutputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_CAPTURE_ERROR, {
            &PhotoOutputImpl::RegisterErrorCallbackListener,
            &PhotoOutputImpl::UnregisterErrorCallbackListener } },
        { CONST_CAPTURE_START_WITH_INFO, {
            &PhotoOutputImpl::RegisterCaptureStartWithInfoCallbackListener,
            &PhotoOutputImpl::UnregisterCaptureStartWithInfoCallbackListener } },
        { CONST_CAPTURE_END, {
            &PhotoOutputImpl::RegisterCaptureEndCallbackListener,
            &PhotoOutputImpl::UnregisterCaptureEndCallbackListener } },
        { CONST_CAPTURE_READY, {
            &PhotoOutputImpl::RegisterReadyCallbackListener,
            &PhotoOutputImpl::UnregisterReadyCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER, {
            &PhotoOutputImpl::RegisterFrameShutterCallbackListener,
            &PhotoOutputImpl::UnregisterFrameShutterCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER_END, {
            &PhotoOutputImpl::RegisterFrameShutterEndCallbackListener,
            &PhotoOutputImpl::UnregisterFrameShutterEndCallbackListener } },
        { CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, {
            &PhotoOutputImpl::RegisterEstimatedCaptureDurationCallbackListener,
            &PhotoOutputImpl::UnregisterEstimatedCaptureDurationCallbackListener } },
        { CONST_CAPTURE_PHOTO_AVAILABLE, {
            &PhotoOutputImpl::RegisterPhotoAvailableCallbackListener,
            &PhotoOutputImpl::UnregisterPhotoAvailableCallbackListener } },
        { CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, {
            &PhotoOutputImpl::RegisterDeferredPhotoProxyAvailableCallbackListener,
            &PhotoOutputImpl::UnregisterDeferredPhotoProxyAvailableCallbackListener } },
        { CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, {
            &PhotoOutputImpl::RegisterOfflineDeliveryFinishedCallbackListener,
            &PhotoOutputImpl::UnregisterOfflineDeliveryFinishedCallbackListener } },
        { CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, {
            &PhotoOutputImpl::RegisterPhotoAssetAvailableCallbackListener,
            &PhotoOutputImpl::UnregisterPhotoAssetAvailableCallbackListener } },
        { CONST_CAPTURE_QUICK_THUMBNAIL, {
            &PhotoOutputImpl::RegisterQuickThumbnailCallbackListener,
            &PhotoOutputImpl::UnregisterQuickThumbnailCallbackListener } }, };
    return funMap;
}

void PhotoOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterErrorCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterCaptureStartWithInfoCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterCaptureEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterCaptureEndCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterCaptureEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterReadyCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterReadyCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterReadyCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterFrameShutterCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterFrameShutterCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterFrameShutterCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterFrameShutterEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterFrameShutterEndCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterFrameShutterEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterEstimatedCaptureDurationCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterPhotoAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterPhotoAvailableCallbackListener, photoOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(photoOutput_->GetPhotoSurface() == nullptr, "PhotoSurface_ is null!");
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        ani_env *env = get_env();
        sptr<PhotoListenerAni> photoListener = new (std::nothrow)
            PhotoListenerAni(env, photoOutput_->GetPhotoSurface(), photoOutput_);
        CHECK_ERROR_RETURN_LOG(photoListener == nullptr, "photoListener is null!");
        SurfaceError ret =
            photoOutput_->GetPhotoSurface()->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoListener);
        CHECK_ERROR_PRINT_LOG(ret != SURFACE_ERROR_OK, "register surface consumer listener failed!");
        photoListener_ = photoListener;
    }
    photoListener_->SaveCallback(eventName, callback);

    // Preconfig can't support rawPhotoListener.
    if (photoOutput_ != nullptr && profile_ != nullptr) {
        rawCallback_ = callback;
        CHECK_EXECUTE(profile_->GetCameraFormat() == OHOS::CameraStandard::CAMERA_FORMAT_YUV_420_SP,
            CreateMultiChannelPictureLisenter(get_env()));
    }
}

void PhotoOutputImpl::UnregisterPhotoAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_EXECUTE(photoListener_ != nullptr, photoListener_->RemoveCallback(eventName, callback));
    CHECK_EXECUTE(rawPhotoListener_ != nullptr, rawPhotoListener_->RemoveCallbackRef(eventName, callback));
}

void PhotoOutputImpl::RegisterDeferredPhotoProxyAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterDeferredPhotoProxyAvailableCallbackListener, photoOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(photoOutput_->GetPhotoSurface() == nullptr, "PhotoSurface is null!");
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new deferred photoListener and register surface consumer listener");
        ani_env *env = get_env();
        sptr<PhotoListenerAni> photoListener = new (std::nothrow)
            PhotoListenerAni(env, photoOutput_->GetPhotoSurface(), photoOutput_);
        CHECK_ERROR_RETURN_LOG(photoListener == nullptr, "failed to new photoListener!");
        SurfaceError ret =
            photoOutput_->GetPhotoSurface()->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoListener);
        CHECK_ERROR_PRINT_LOG(ret != SURFACE_ERROR_OK, "register surface consumer listener failed!");
        photoListener_ = photoListener;
    }
    photoListener_->SaveCallback(eventName, callback);
}

void PhotoOutputImpl::UnregisterDeferredPhotoProxyAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_EXECUTE(photoListener_ != nullptr,
        photoListener_->RemoveCallback(eventName, callback));
}

void PhotoOutputImpl::RegisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterOfflineDeliveryFinishedCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::CreateMultiChannelPictureLisenter(ani_env* env)
{
    if (pictureListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        sptr<PictureListener> pictureListener = new (std::nothrow) PictureListener();
        pictureListener->InitPictureListeners(photoOutput_);
        if (photoListener_ == nullptr) {
            sptr<PhotoListenerAni> photoListener = new (std::nothrow)
            PhotoListenerAni(env, photoOutput_->GetPhotoSurface(), photoOutput_);
            SurfaceError ret = photoOutput_->GetPhotoSurface()->RegisterConsumerListener(
                (sptr<IBufferConsumerListener> &)photoListener);
            CHECK_ERROR_PRINT_LOG(ret != SURFACE_ERROR_OK, "register surface consumer listener failed!");
            photoListener_ = photoListener;
            pictureListener_ = pictureListener;
        }
        if (photoOutput_->taskManager_ == nullptr) {
            constexpr int32_t auxiliaryPictureCount = 4;
            photoOutput_->taskManager_ =
                std::make_shared<OHOS::CameraStandard::DeferredProcessing::TaskManager>("AuxilaryPictureListener",
                auxiliaryPictureCount, false);
        }
    }
}

void PhotoOutputImpl::CreateSingleChannelPhotoLisenter(ani_env* env)
{
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        sptr<PhotoListenerAni> photoListener = new (std::nothrow)
        PhotoListenerAni(env, photoOutput_->GetPhotoSurface(), photoOutput_);
        SurfaceError ret =
            photoOutput_->GetPhotoSurface()->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoListener);
        CHECK_ERROR_PRINT_LOG(ret != SURFACE_ERROR_OK, "register surface consumer listener failed!");
        photoListener_ = photoListener;
    }
}

void PhotoOutputImpl::RegisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "photoOutput_ is null!");
    CHECK_ERROR_RETURN_LOG(photoOutput_->GetPhotoSurface() == nullptr, "PhotoSurface is null!");
    if (photoOutput_->IsYuvOrHeifPhoto()) {
        CreateMultiChannelPictureLisenter(get_env());
    } else {
        CreateSingleChannelPhotoLisenter(get_env());
    }
    photoListener_->SaveCallback(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback);
}

void PhotoOutputImpl::UnregisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (photoListener_ != nullptr) {
        photoListener_->RemoveCallback(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback);
        if (photoListener_->taskManager_) {
            photoListener_->taskManager_->CancelAllTasks();
            photoListener_->taskManager_.reset();
            photoListener_->taskManager_ = nullptr;
        }
    }
    if (photoOutput_) {
        if (photoOutput_->taskManager_) {
            photoOutput_->taskManager_->CancelAllTasks();
            photoOutput_->taskManager_.reset();
            photoOutput_->taskManager_ = nullptr;
        }
    }
}

void PhotoOutputImpl::RegisterQuickThumbnailCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi quickThumbnail on is called!");

    // Set callback for exposureStateChange
    if (thumbnailListener_ == nullptr) {
        if (!isQuickThumbnailEnabled_) {
            CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SESSION_NOT_RUNNING,
                "quickThumbnail is not enabled!");
            return;
        }
        thumbnailListener_ = new ThumbnailListener(get_env(), photoOutput_);
        photoOutput_->SetThumbnailListener((sptr<IBufferConsumerListener>&)thumbnailListener_);
    }
    thumbnailListener_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterQuickThumbnailCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi quickThumbnail off is called!");
    if (!isQuickThumbnailEnabled_) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SESSION_NOT_RUNNING,
            "quickThumbnail is not enabled!");
        return;
    }
    if (thumbnailListener_ != nullptr) {
        thumbnailListener_->RemoveCallbackRef(eventName, callback);
        if (thumbnailListener_->taskManager_) {
            thumbnailListener_->ClearTaskManager();
        }
    }
}

void PhotoOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnError");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffError");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputImpl::OnCaptureStartWithInfo(callback_view<void(uintptr_t, CaptureStartInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnCaptureStartWithInfo");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputImpl::OffCaptureStartWithInfo(
    optional_view<callback<void(uintptr_t, CaptureStartInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffCaptureStartWithInfo");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputImpl::OnCaptureEnd(callback_view<void(uintptr_t, CaptureEndInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnCaptureEnd");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_END);
}

void PhotoOutputImpl::OffCaptureEnd(optional_view<callback<void(uintptr_t, CaptureEndInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffCaptureEnd");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_END);
}

void PhotoOutputImpl::OnCaptureReady(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnCaptureReady");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_READY);
}

void PhotoOutputImpl::OffCaptureReady(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffCaptureReady");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_READY);
}

void PhotoOutputImpl::OnFrameShutter(callback_view<void(uintptr_t, FrameShutterInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnFrameShutter");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputImpl::OffFrameShutter(optional_view<callback<void(uintptr_t, FrameShutterInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffFrameShutter");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputImpl::OnFrameShutterEnd(callback_view<void(uintptr_t, FrameShutterEndInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnFrameShutterEnd");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputImpl::OffFrameShutterEnd(optional_view<callback<void(uintptr_t, FrameShutterEndInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffFrameShutterEnd");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputImpl::OnEstimatedCaptureDuration(callback_view<void(uintptr_t, double)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnEstimatedCaptureDuration");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

void PhotoOutputImpl::OffEstimatedCaptureDuration(optional_view<callback<void(uintptr_t, double)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffEstimatedCaptureDuration");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

void PhotoOutputImpl::OnPhotoAvailable(callback_view<void(uintptr_t, weak::Photo)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnPhotoAvailable");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OffPhotoAvailable(optional_view<callback<void(uintptr_t, weak::Photo)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffPhotoAvailable");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OnDeferredPhotoProxyAvailable(callback_view<void(uintptr_t, weak::DeferredPhotoProxy)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnDeferredPhotoProxyAvailable");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OffDeferredPhotoProxyAvailable(
    optional_view<callback<void(uintptr_t, weak::DeferredPhotoProxy)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffDeferredPhotoProxyAvailable");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OnOfflineDeliveryFinished(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnOfflineDeliveryFinished");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED);
}

void PhotoOutputImpl::OffOfflineDeliveryFinished(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffOfflineDeliveryFinished");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED);
}

void PhotoOutputImpl::OnPhotoAssetAvailable(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_PHOTO_ASSET_AVAILABLE);
}
void PhotoOutputImpl::OffPhotoAssetAvailable(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_PHOTO_ASSET_AVAILABLE);
}

void PhotoOutputImpl::OnQuickThumbnail(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_QUICK_THUMBNAIL);
}
void PhotoOutputImpl::OffQuickThumbnail(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_QUICK_THUMBNAIL);
}

bool PhotoOutputImpl::GetEnableMirror()
{
    return isMirrorEnabled_;
}

void PhotoOutputImpl::EnableMirror(bool enabled)
{
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::EnableMirror get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = photoOutput_->EnableMirror(enabled);
    CHECK_ERROR_PRINT_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::EnableMirror fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsMirrorSupported()
{
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsMirrorSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    return photoOutput_->IsMirrorSupported();
}

Profile PhotoOutputImpl::GetActiveProfile()
{
    Profile res {
        .size = {
            .height = -1,
            .width = -1,
        },
        .format = CameraFormat::key_t::CAMERA_FORMAT_YUV_420_SP,
    };
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr, res, "GetActiveProfile failed, photoOutput_ is nullptr");
    auto profile = photoOutput_->GetPhotoProfile();
    CHECK_ERROR_RETURN_RET_LOG(profile == nullptr, res, "GetActiveProfile failed, profile is nullptr");
    CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(profile->GetCameraFormat());
    res.size.height = profile->GetSize().height;
    res.size.width = profile->GetSize().width;
    res.format = cameraFormat;
    return res;
}

void PhotoOutputImpl::EnableMovingPhoto(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "EnableMovingPhoto photoOutput_ is null");
    auto session = GetPhotoOutput()->GetSession();
    CHECK_ERROR_RETURN_LOG(session == nullptr, "EnableMovingPhoto session is null");
    photoOutput_->EnableMovingPhoto(enabled);
    session->LockForControl();
    int32_t retCode = session->EnableMovingPhoto(enabled);
    session->UnlockForControl();
    CHECK_ERROR_RETURN_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode), "EnableMovingPhoto failed");
}

bool PhotoOutputImpl::IsMovingPhotoSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr,
        false, "IsMovingPhotoSupported failed, photoOutput_ is nullptr");
    auto session = photoOutput_->GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "EnableMovingPhoto session is null");
    return session->IsMovingPhotoSupported();
}

ImageRotation PhotoOutputImpl::GetPhotoRotation(int32_t deviceDegree)
{
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr, ImageRotation(static_cast<ImageRotation::key_t>(-1)),
        "GetPhotoRotation failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->GetPhotoRotation(deviceDegree);
    if (retCode == OHOS::CameraStandard::SERVICE_FATL_ERROR) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetPhotoRotation Camera service fatal error.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    int32_t taiheRetCode = CameraUtilsTaihe::ToTaiheImageRotation(retCode);
    return ImageRotation(static_cast<ImageRotation::key_t>(taiheRetCode));
}

void PhotoOutputImpl::EnableQuickThumbnail(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "EnableQuickThumbnail photoOutput_ is null");
    isQuickThumbnailEnabled_ = enabled;
    int32_t retCode = photoOutput_->SetThumbnail(enabled);
    CHECK_ERROR_RETURN(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode));
}

void PhotoOutputImpl::EnableOffline()
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi IsOfflineSupported on is called!");
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "EnableOfflinePhoto photoOutput_ is null");
    auto session = GetPhotoOutput()->GetSession();
    CHECK_ERROR_RETURN_LOG(session == nullptr, "EnableOfflinePhoto session is null");
    photoOutput_->EnableOfflinePhoto();
}

bool PhotoOutputImpl::IsOfflineSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsOfflineSupported is called!");
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr, false, "IsOfflineSupported failed, photoOutput_ is nullptr");
    return photoOutput_->IsOfflineSupported();
}

OHOS::sptr<OHOS::CameraStandard::PhotoOutput> PhotoOutputImpl::GetPhotoOutput()
{
    return photoOutput_;
}

void ProcessCapture(PhotoOutputTaiheAsyncContext* context, bool isBurst)
{
    CHECK_ERROR_RETURN(context == nullptr);
    context->status = true;
    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> photoOutput = context->objectInfo->GetPhotoOutput();
    MEDIA_INFO_LOG("PhotoOutputTaiheAsyncContext objectInfo GetEnableMirror is %{public}d",
        context->objectInfo->GetEnableMirror());
    if (context->hasPhotoSettings) {
        std::shared_ptr<OHOS::CameraStandard::PhotoCaptureSetting> capSettings =
            std::make_shared<OHOS::CameraStandard::PhotoCaptureSetting>();
        CHECK_EXECUTE(context->quality != -1,
            capSettings->SetQuality(static_cast<OHOS::CameraStandard::PhotoCaptureSetting::QualityLevel>(
                context->quality)));
        CHECK_EXECUTE(context->rotation != -1,
            capSettings->SetRotation(static_cast<OHOS::CameraStandard::PhotoCaptureSetting::RotationConfig>(
                context->rotation)));
        if (!context->isMirrorSettedByUser) {
            capSettings->SetMirror(context->objectInfo->GetEnableMirror());
        } else {
            capSettings->SetMirror(context->isMirror);
        }
        CHECK_EXECUTE(context->location != nullptr, capSettings->SetLocation(context->location));
        if (isBurst) {
            MEDIA_ERR_LOG("ProcessContext BurstCapture");
            uint8_t burstState = 1; // 0:end 1:start
            capSettings->SetBurstCaptureState(burstState);
        }
        context->errorCode = photoOutput->Capture(capSettings);
    } else {
        std::shared_ptr<OHOS::CameraStandard::PhotoCaptureSetting> capSettings =
            std::make_shared<OHOS::CameraStandard::PhotoCaptureSetting>();
        capSettings->SetMirror(context->objectInfo->GetEnableMirror());
        context->errorCode = photoOutput->Capture(capSettings);
    }
    context->status = context->errorCode == 0;
}

void PhotoOutputImpl::CaptureSync()
{
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputTaihe::Capture", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputTaihe::Capture");
    asyncContext->objectInfo = this;
    CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "PhotoOutputAni::Capture async info is nullptr");
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    auto context = static_cast<PhotoOutputTaiheAsyncContext*>(asyncContext.release());

    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        ProcessCapture(context, false);
    });

    if (!(context->status)) {
        CameraUtilsTaihe::CheckError(context->errorCode);
    }

    context->objectInfo = nullptr;
    delete context;
}

static bool ParseCaptureSettings(PhotoOutputTaiheAsyncContext* asyncContext, PhotoCaptureSetting const& setting)
{
    CHECK_ERROR_RETURN_RET_LOG(asyncContext == nullptr, false, "ParseCaptureSettings asyncContext is nullptr");
    bool res = false;
    if (setting.quality.has_value()) {
        asyncContext->quality = setting.quality.value().get_value();
        res = true;
    }
    if (setting.rotation.has_value()) {
        asyncContext->rotation = setting.rotation.value().get_value();
        res = true;
    }
    if (setting.mirror.has_value()) {
        asyncContext->isMirror = setting.mirror.value();
        res = true;
    }
    if (setting.location.has_value()) {
        OHOS::CameraStandard::Location settingsLocation;
        settingsLocation.latitude = setting.location.value().latitude;
        settingsLocation.longitude = setting.location.value().longitude;
        settingsLocation.altitude = setting.location.value().altitude;
        asyncContext->location = std::make_shared<OHOS::CameraStandard::Location>(settingsLocation);
        res = true;
    }
    return res;
}

void PhotoOutputImpl::CaptureSyncWithSetting(PhotoCaptureSetting const& setting)
{
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputTaihe::Capture", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputTaihe::Capture");
    asyncContext->objectInfo = this;
    asyncContext->hasPhotoSettings = ParseCaptureSettings(asyncContext.get(), setting);
    CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "PhotoOutputAni::Capture async info is nullptr");
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    auto context = static_cast<PhotoOutputTaiheAsyncContext*>(asyncContext.release());
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        ProcessCapture(context, false);
    });
    if (!(context->status)) {
        CameraUtilsTaihe::CheckError(context->errorCode);
    }
    context->objectInfo = nullptr;
    delete context;
}

void PhotoOutputImpl::BurstCaptureSync(PhotoCaptureSetting const& setting)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi BurstCaptureSync  is called!");
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputTaihe::BurstCapture", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputTaihe::BurstCapture");
    asyncContext->objectInfo = this;
    asyncContext->hasPhotoSettings = ParseCaptureSettings(asyncContext.get(), setting);
    CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "PhotoOutputAni::BurstCapture async info is nullptr");
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    auto context = static_cast<PhotoOutputTaiheAsyncContext*>(asyncContext.release());
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        ProcessCapture(context, false);
    });
    if (!(context->status)) {
        CameraUtilsTaihe::CheckError(context->errorCode);
    }
    context->objectInfo = nullptr;
    delete context;
}

void PhotoOutputImpl::EnableAutoCloudImageEnhancement(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoCloudImageEnhancement is called!");
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "EnableAutoCloudImageEnhancement photoOutput_ is null");
    int32_t retCode = photoOutput_->EnableAutoCloudImageEnhancement(enabled);
    CHECK_ERROR_PRINT_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::EnableAutoCloudImageEnhancement fail %{public}d", retCode);
    MEDIA_DEBUG_LOG("PhotoOutputImpl::EnableAutoCloudImageEnhancement success");
}

bool PhotoOutputImpl::IsAutoCloudImageEnhancementSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsAutoCloudImageEnhancementSupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputImpl::IsAutoCloudImageEnhancementSupported is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsAutoCloudImageEnhancementSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }

    bool isAutoCloudImageEnhancementSupported = false;
    int32_t retCode = photoOutput_->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhancementSupported);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    MEDIA_DEBUG_LOG("PhotoOutputImpl::IsAutoCloudImageEnhancementSupported is %{public}d",
        isAutoCloudImageEnhancementSupported);
    return isAutoCloudImageEnhancementSupported;
}

bool PhotoOutputImpl::IsDepthDataDeliverySupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDepthDataDeliverySupported is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsDepthDataDeliverySupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    return photoOutput_->IsDepthDataDeliverySupported();
}

void PhotoOutputImpl::EnableDepthDataDelivery(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableDepthDataDelivery is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::EnableDepthDataDelivery get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = photoOutput_->EnableDepthDataDelivery(enabled);
    CHECK_ERROR_PRINT_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputNapi::EnableDepthDataDelivery fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsAutoHighQualityPhotoSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsAutoHighQualityPhotoSupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputImpl::IsAutoHighQualityPhotoSupported is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsAutoHighQualityPhotoSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }

    int32_t isAutoHighQualityPhotoSupported;
    int32_t retCode = photoOutput_->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    return isAutoHighQualityPhotoSupported != -1;
}

void PhotoOutputImpl::EnableAutoHighQualityPhoto(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoHighQualityPhoto is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::EnableAutoHighQualityPhoto get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = photoOutput_->EnableAutoHighQualityPhoto(enabled);
    CHECK_ERROR_PRINT_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputNapi::EnableAutoHighQualityPhoto fail %{public}d", retCode);
}

void PhotoOutputImpl::EnableRawDelivery(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi quickThumbnail on is called!");
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "EnableRawDelivery photoOutput_ is null");
    int32_t retCode = photoOutput_->EnableRawDelivery(enabled);
    CHECK_ERROR_PRINT_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::EnableRawDelivery fail %{public}d", retCode);

    MEDIA_INFO_LOG("new rawPhotoListener and register surface consumer listener");
    auto rawSurface = photoOutput_->rawPhotoSurface_;
    CHECK_ERROR_RETURN_LOG(rawSurface == nullptr, "rawPhotoSurface_ is null!");
    sptr<RawPhotoListenerAni> rawPhotoListener = new (std::nothrow) RawPhotoListenerAni(get_env(), rawSurface);
    CHECK_ERROR_RETURN_LOG(rawPhotoListener == nullptr, "failed to new rawPhotoListener");
    SurfaceError ret = rawSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)rawPhotoListener);
    CHECK_ERROR_PRINT_LOG(ret != SURFACE_ERROR_OK, "register surface consumer listener failed!");
    rawPhotoListener_ = rawPhotoListener;
    rawPhotoListener_->SaveCallbackReference(CONST_CAPTURE_PHOTO_AVAILABLE, rawCallback_, false);
}

bool PhotoOutputImpl::IsRawDeliverySupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsRawDeliverySupported is called!");
    bool isSupported = false;
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr,
        false, "IsRawDeliverySupported failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsRawDeliverySupported(isSupported);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

void PhotoOutputImpl::SetMovingPhotoVideoCodecType(VideoCodecType codecType)
{
    MEDIA_DEBUG_LOG("PhotoOutputImpl::SetMovingPhotoVideoCodecType is called");
    int32_t retCode = photoOutput_->SetMovingPhotoVideoCodecType(static_cast<int32_t>(codecType.get_value()));
    CHECK_ERROR_PRINT_LOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::SetMovingPhotoVideoCodecType fail %{public}d", retCode);
}

array<VideoCodecType> PhotoOutputImpl::GetSupportedMovingPhotoVideoCodecTypes()
{
    MEDIA_DEBUG_LOG("IsMotionPhotoSupported is called");
    std::vector<VideoCodecType> videoCodecTypes;
    videoCodecTypes.emplace_back(VideoCodecType::key_t::AVC);
    videoCodecTypes.emplace_back(VideoCodecType::key_t::HEVC);
    return array<VideoCodecType>(videoCodecTypes);
}

void PhotoOutputImpl::ConfirmCapture()
{
    MEDIA_INFO_LOG("ConfirmCapture is called");
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "PhotoOutputImpl::ConfirmCapture photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->ConfirmCapture();
    CHECK_ERROR_PRINT_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::ConfirmCapture fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsDeferredImageDeliverySupported(DeferredDeliveryImageType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDeferredImageDeliverySupported is called!");
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr,
        false, "IsDeferredImageDeliverySupported failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsDeferredImageDeliverySupported(
        static_cast<OHOS::CameraStandard::DeferredDeliveryImageType>(type.get_value()));
    bool isSupported = (retCode == 0);
    CHECK_ERROR_RETURN_RET(retCode > 0 && !CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

bool PhotoOutputImpl::IsDeferredImageDeliveryEnabled(DeferredDeliveryImageType type)
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDeferredImageDeliveryEnabled is called!");
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr,
        false, "IsDeferredImageDeliveryEnabled failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsDeferredImageDeliveryEnabled(
        static_cast<OHOS::CameraStandard::DeferredDeliveryImageType>(type.get_value()));
    bool isSupported = (retCode == 0);
    CHECK_ERROR_RETURN_RET(retCode > 0 && !CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

bool PhotoOutputImpl::IsQuickThumbnailSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsQuickThumbnailSupported is called!");
    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr,
        false, "IsQuickThumbnailSupported failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsQuickThumbnailSupported();
    bool isSupported = (retCode == 0);
    CHECK_ERROR_RETURN_RET(retCode > 0 && !CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

void PhotoOutputImpl::DeferImageDelivery(DeferredDeliveryImageType type)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi DeferImageDelivery is called!");
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "photoOutput_ is nullptr");
    photoOutput_->DeferImageDeliveryFor(
        static_cast<OHOS::CameraStandard::DeferredDeliveryImageType>(type.get_value()));
    isDeferredPhotoEnabled_ = type.get_value() == OHOS::CameraStandard::DeferredDeliveryImageType::DELIVERY_PHOTO;
}
} // namespace Camera
} // namespace Ani