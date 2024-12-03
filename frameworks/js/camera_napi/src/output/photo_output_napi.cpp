/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "output/photo_output_napi.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <uv.h>

#include "buffer_extra_data_impl.h"
#include "camera_buffer_handle_utils.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_napi_const.h"
#include "camera_napi_object_types.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_napi_worker_queue_keeper.h"
#include "camera_output_capability.h"
#include "camera_photo_proxy.h"
#include "camera_report_dfx_uitls.h"
#include "camera_util.h"
#include "dp_utils.h"
#include "image_napi.h"
#include "image_packer.h"
#include "image_receiver.h"
#include "ipc_skeleton.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "listener_base.h"
#include "media_library_comm_napi.h"
#include "media_library_manager.h"
#include "metadata.h"
#include "output/deferred_photo_proxy_napi.h"
#include "output/photo_napi.h"
#include "output/photo_output_napi.h"
#include "photo_output.h"
#include "picture.h"
#include "pixel_map_napi.h"
#include "refbase.h"
#include "securec.h"
#include "task_manager.h"
#include "video_key_info.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<PhotoOutputAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "CameraInputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("CameraInputNapi AsyncCompleteCallback %{public}s, status = %{public}d", context->funcName.c_str(),
        context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}

void ProcessCapture(PhotoOutputAsyncContext* context, bool isBurst)
{
    context->status = true;
    sptr<PhotoOutput> photoOutput = context->objectInfo->GetPhotoOutput();
    MEDIA_INFO_LOG("PhotoOutputAsyncContext objectInfo GetEnableMirror is %{public}d",
        context->objectInfo->GetEnableMirror());
    if (context->hasPhotoSettings) {
        std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();
        if (context->quality != -1) {
            capSettings->SetQuality(static_cast<PhotoCaptureSetting::QualityLevel>(context->quality));
        }
        if (context->rotation != -1) {
            capSettings->SetRotation(static_cast<PhotoCaptureSetting::RotationConfig>(context->rotation));
        }
        if (!context->isMirrorSettedByUser) {
            capSettings->SetMirror(context->objectInfo->GetEnableMirror());
        } else {
            capSettings->SetMirror(context->isMirror);
        }
        if (context->location != nullptr) {
            capSettings->SetLocation(context->location);
        }
        if (isBurst) {
            MEDIA_ERR_LOG("ProcessContext BurstCapture");
            uint8_t burstState = 1; // 0:end 1:start
            capSettings->SetBurstCaptureState(burstState);
        }
        context->errorCode = photoOutput->Capture(capSettings);
    } else {
        std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();
        capSettings->SetMirror(context->objectInfo->GetEnableMirror());
        context->errorCode = photoOutput->Capture(capSettings);
    }
    context->status = context->errorCode == 0;
}

bool ValidQualityLevelFromJs(int32_t jsQuality)
{
    MEDIA_INFO_LOG("PhotoOutputNapi::ValidQualityLevelFromJs quality level = %{public}d", jsQuality);
    switch (jsQuality) {
        case QUALITY_LEVEL_HIGH:
        // Fallthrough
        case QUALITY_LEVEL_MEDIUM:
        // Fallthrough
        case QUALITY_LEVEL_LOW:
            return true;
        default:
            MEDIA_ERR_LOG("Invalid quality value received from application");
            return false;
    }
    return false;
}

bool ValidImageRotationFromJs(int32_t jsRotation)
{
    MEDIA_INFO_LOG("js rotation = %{public}d", jsRotation);
    switch (jsRotation) {
        case ROTATION_0:
            // Fallthrough
        case ROTATION_90:
            // Fallthrough
        case ROTATION_180:
            // Fallthrough
        case ROTATION_270:
            return true;
        default:
            MEDIA_ERR_LOG("Invalid rotation value received from application");
            return false;
    }
    return false;
}
} // namespace

thread_local napi_ref PhotoOutputNapi::sConstructor_ = nullptr;
thread_local sptr<PhotoOutput> PhotoOutputNapi::sPhotoOutput_ = nullptr;
thread_local sptr<Surface> PhotoOutputNapi::sPhotoSurface_ = nullptr;
thread_local uint32_t PhotoOutputNapi::photoOutputTaskId = CAMERA_PHOTO_OUTPUT_TASKID;
thread_local napi_ref PhotoOutputNapi::rawCallback_ = nullptr;
static uv_sem_t g_captureStartSem;
static bool g_isSemInited;
static std::mutex g_photoImageMutex;
static std::mutex g_assembleImageMutex;
static int32_t g_captureId;

PhotoListener::PhotoListener(napi_env env, const sptr<Surface> photoSurface, wptr<PhotoOutput> photoOutput)
    : ListenerBase(env), photoSurface_(photoSurface), photoOutput_(photoOutput)
{
    if (bufferProcessor_ == nullptr && photoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor>(photoSurface);
    }
    if (taskManager_ == nullptr) {
        constexpr int32_t numThreads = 1;
        taskManager_ = std::make_shared<DeferredProcessing::TaskManager>("PhotoListener",
            numThreads, false);
    }
}
PhotoListener::~PhotoListener()
{
    if (taskManager_) {
        taskManager_->CancelAllTasks();
        taskManager_.reset();
        taskManager_ = nullptr;
    }
}
RawPhotoListener::RawPhotoListener(napi_env env, const sptr<Surface> rawPhotoSurface)
    : ListenerBase(env), rawPhotoSurface_(rawPhotoSurface)
{
    if (bufferProcessor_ == nullptr && rawPhotoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor>(rawPhotoSurface);
    }
}

AuxiliaryPhotoListener::AuxiliaryPhotoListener(const std::string surfaceName, const sptr<Surface> surface,
    wptr<PhotoOutput> photoOutput) : surfaceName_(surfaceName), surface_(surface), photoOutput_(photoOutput)
{
    if (bufferProcessor_ == nullptr && surface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor>(surface);
    }
}

int32_t GetCaptureId(sptr<SurfaceBuffer> surfaceBuffer)
{
    int32_t captureId;
    int32_t burstSeqId = -1;
    int32_t maskBurstSeqId;
    int32_t invalidSeqenceId = -1;
    int32_t captureIdMask = 0x0000FFFF;
    int32_t captureIdShit = 16;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, captureId);
    if (burstSeqId != invalidSeqenceId && captureId >= 0) {
        maskBurstSeqId = ((captureId & captureIdMask) << captureIdShit) | burstSeqId;
        MEDIA_INFO_LOG("PhotoListener captureId:%{public}d, burstSeqId:%{public}d, maskBurstSeqId = %{public}d",
            captureId, burstSeqId, maskBurstSeqId);
        return maskBurstSeqId;
    }
    MEDIA_INFO_LOG("PhotoListener captureId:%{public}d, burstSeqId:%{public}d", captureId, burstSeqId);
    return captureId;
}

void PictureListener::InitPictureListeners(napi_env env, wptr<PhotoOutput> photoOutput)
{
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("photoOutput is null");
        return;
    }
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
    if (retStr != "") {
        MEDIA_ERR_LOG("register surface consumer listener failed! type = %{public}s", retStr.c_str());
    }
}

void AuxiliaryPhotoListener::DeepCopyBuffer(
    sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer, int32_t  captureId) const
{
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
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK) {
        MEDIA_ERR_LOG("PhotoListener memcpy_s failed");
    }
    MEDIA_DEBUG_LOG("AuxiliaryPhotoListener::DeepCopyBuffer memcpy end surfaceName=%{public}s captureId = %{public}d",
        surfaceName_.c_str(), captureId);
}

void AuxiliaryPhotoListener::ExecuteDeepCopySurfaceBuffer() __attribute__((no_sanitize("cfi")))
{
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto ExecuteDeepCopySurfaceBuffer surfaceName = %{public}s",
        surfaceName_.c_str());
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s AcquireBuffer before", surfaceName_.c_str());
    SurfaceError surfaceRet = surface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto surfaceName = %{public}s AcquireBuffer end", surfaceName_.c_str());
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("AuxiliaryPhotoListener Failed to acquire surface buffer");
        return;
    }
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
    if (bufferHandle == nullptr) {
        MEDIA_ERR_LOG("invalid bufferHandle");
    }
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
            DeferredProcessing::GetGlobalWatchdog().DoTimeout(handle);
            DeferredProcessing::GetGlobalWatchdog().StopMonitor(handle);
            photoOutput->captureIdAuxiliaryCountMap_[captureId] = -1;
            MEDIA_INFO_LOG("AuxiliaryPhotoListener captureIdAuxiliaryCountMap_ = -1");
        }
        MEDIA_INFO_LOG("AuxiliaryPhotoListener auxiliaryPhotoCount = %{public}d, captureCount = %{public}d, "
                       "surfaceName=%{public}s, captureId=%{public}d",
            photoOutput->captureIdAuxiliaryCountMap_[captureId], photoOutput->captureIdCountMap_[captureId],
            surfaceName_.c_str(), captureId);
    }
}

void AuxiliaryPhotoListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AuxiliaryPhotoListener::OnBufferAvailable is called, surfaceName=%{public}s", surfaceName_.c_str());
    if (!surface_) {
        MEDIA_ERR_LOG("AuxiliaryPhotoListener napi photoSurface_ is null");
        return;
    }
    auto photoOutput = photoOutput_.promote();
    if (photoOutput->taskManager_) {
        wptr<AuxiliaryPhotoListener> thisPtr(this);
        photoOutput->taskManager_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            if (listener) {
                listener->ExecuteDeepCopySurfaceBuffer();
            }
        });
    }
    MEDIA_INFO_LOG("AuxiliaryPhotoListener::OnBufferAvailable is end, surfaceName=%{public}s", surfaceName_.c_str());
}

int32_t PhotoListener::GetAuxiliaryPhotoCount(sptr<SurfaceBuffer> surfaceBuffer)
{
    int32_t auxiliaryCount;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageCount, auxiliaryCount);
    MEDIA_INFO_LOG("PhotoListener auxiliaryCount:%{public}d", auxiliaryCount);
    return auxiliaryCount;
}

sptr<CameraPhotoProxy> PhotoListener::CreateCameraPhotoProxy(sptr<SurfaceBuffer> surfaceBuffer)
{
    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("PhotoListener CreateCameraPhotoProxy isDegradedImage:%{public}d", isDegradedImage);
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
    MEDIA_INFO_LOG("PhotoListener CreateCameraPhotoProxy imageId:%{public}" PRId64 ", "
        "deferredProcessingType:%{public}d, captureId = %{public}d, burstSeqId = %{public}d",
        imageId, deferredProcessingType, captureId, burstSeqId);
    // get buffer handle and photo info
    int32_t photoWidth;
    int32_t photoHeight;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, photoWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, photoHeight);
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
    MEDIA_INFO_LOG("PhotoListener CreateCameraPhotoProxy deferredImageFormat:%{public}d, isHighQuality = %{public}d, "
        "size:%{public}" PRId64, deferredImageFormat, isHighQuality, size);
    sptr<CameraPhotoProxy> photoProxy = new(std::nothrow) CameraPhotoProxy(
        nullptr, deferredImageFormat, photoWidth, photoHeight, isHighQuality, captureId, burstSeqId);
    std::string imageIdStr = std::to_string(imageId);
    photoProxy->SetDeferredAttrs(imageIdStr, deferredProcessingType, size, deferredImageFormat);
    return photoProxy;
}

void PhotoListener::ExecuteDeepCopySurfaceBuffer() __attribute__((no_sanitize("cfi")))
{
    auto photoOutput = photoOutput_.promote();
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    sptr<SurfaceBuffer> newSurfaceBuffer = nullptr;
    sptr<CameraPhotoProxy> photoProxy = nullptr;
    int32_t auxiliaryCount = 0;
    int32_t captureId = -1;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = photoSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 0");
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("PhotoListener Failed to acquire surface buffer");
        return;
    }
    auxiliaryCount = GetAuxiliaryPhotoCount(surfaceBuffer);
    captureId = GetCaptureId(surfaceBuffer);
    // deep copy buffer
    newSurfaceBuffer = SurfaceBuffer::Create();
    MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 1");
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, captureId);
    MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 2");
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    {
        std::lock_guard<std::mutex> lock(g_photoImageMutex);
        photoOutput = photoOutput_.promote();
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 3");
        photoOutput->captureIdCountMap_[captureId] = auxiliaryCount;
        photoOutput->captureIdAuxiliaryCountMap_[captureId]++;
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 4 captureId = %{public}d", captureId);
        photoProxy = CreateCameraPhotoProxy(surfaceBuffer);
        photoOutput->photoProxyMap_[captureId] = photoProxy;
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 5");
        if (!photoProxy) {
            MEDIA_ERR_LOG("photoProxy is nullptr");
            return;
        }
        if (photoProxy->isHighQuality_ && (callbackFlag_ & CAPTURE_PHOTO) != 0) {
            UpdateMainPictureStageOneJSCallback(surfaceBuffer, timestamp);
            return;
        }

        BufferHandle* bufferHandle = newSurfaceBuffer->GetBufferHandle();
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 6");
        if (bufferHandle == nullptr) {
            MEDIA_ERR_LOG("invalid bufferHandle");
            return;
        }
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 7");
        newSurfaceBuffer->Map();
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto 8");
        photoProxy->bufferHandle_ = bufferHandle;
        std::unique_ptr<Media::Picture> picture = Media::Picture::Create(newSurfaceBuffer);
        if (!picture) {
            MEDIA_ERR_LOG("picture is nullptr");
            return;
        }
        Media::ImageInfo imageInfo;
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto MainSurface w=%{public}d, h=%{public}d, f=%{public}d",
            newSurfaceBuffer->GetWidth(), newSurfaceBuffer->GetHeight(), newSurfaceBuffer->GetFormat());
        photoOutput->captureIdPictureMap_[captureId] = std::move(picture);
        uint32_t pictureHandle;
        constexpr uint32_t delayMilli = 1 * 1000;
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto GetGlobalWatchdog StartMonitor, captureId=%{public}d",
            captureId);
        DeferredProcessing::GetGlobalWatchdog().StartMonitor(pictureHandle, delayMilli,
            [this, captureId, timestamp](uint32_t handle) {
                MEDIA_INFO_LOG("PhotoListener PhotoListener-Watchdog executed, handle: %{public}d, "
                    "captureId=%{public}d", static_cast<int>(handle), captureId);
                AssembleAuxiliaryPhoto(timestamp, captureId);
                auto photoOutput = photoOutput_.promote();
                if (photoOutput && photoOutput->captureIdAuxiliaryCountMap_.count(captureId)) {
                    photoOutput->captureIdAuxiliaryCountMap_[captureId] = -1;
                    MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto captureIdAuxiliaryCountMap_ = -1, "
                        "captureId=%{public}d", captureId);
                }
        });
        photoOutput->captureIdHandleMap_[captureId] = pictureHandle;
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto, pictureHandle: %{public}d, captureId=%{public}d "
            "captureIdCountMap = %{public}d, captureIdAuxiliaryCountMap = %{public}d",
            pictureHandle, captureId, photoOutput->captureIdCountMap_[captureId],
            photoOutput->captureIdAuxiliaryCountMap_[captureId]);
        if (photoOutput->captureIdCountMap_[captureId] != 0 &&
            photoOutput->captureIdAuxiliaryCountMap_[captureId] == photoOutput->captureIdCountMap_[captureId]) {
            MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto auxiliaryCount is complete, StopMonitor DoTimeout "
                "handle = %{public}d, captureId = %{public}d", pictureHandle, captureId);
            DeferredProcessing::GetGlobalWatchdog().DoTimeout(pictureHandle);
            DeferredProcessing::GetGlobalWatchdog().StopMonitor(pictureHandle);
        }
        MEDIA_INFO_LOG("PhotoListener AssembleAuxiliaryPhoto end");
    }
}

void PhotoListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable is called");
    auto photoOutput = photoOutput_.promote();
    if (photoSurface_ == nullptr || photoOutput == nullptr) {
        MEDIA_ERR_LOG("PhotoListener photoSurface or photoOutput is null");
        return;
    }
    if (!photoOutput->IsYuvOrHeifPhoto()) {
        UpdateJSCallbackAsync(photoSurface_);
        MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable is end");
        return;
    }
    if (taskManager_) {
        wptr<PhotoListener> thisPtr(this);
        taskManager_->SubmitTask([thisPtr]() {
            auto listener = thisPtr.promote();
            if (listener) {
                listener->ExecuteDeepCopySurfaceBuffer();
            }
        });
    }
    MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable is end");
}

void PhotoListener::UpdatePictureJSCallback(const string uri, int32_t cameraShotType, const std::string burstKey) const
{
    MEDIA_INFO_LOG("PhotoListener:UpdatePictureJSCallback called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("PhotoListenerInfo:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("PhotoListenerInfo:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<PhotoListenerInfo> callbackInfo = std::make_unique<PhotoListenerInfo>(nullptr, shared_from_this());
    callbackInfo->uri = uri;
    callbackInfo->cameraShotType = cameraShotType;
    callbackInfo->burstKey = burstKey;
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            PhotoListenerInfo* callbackInfo = reinterpret_cast<PhotoListenerInfo*>(work->data);
            auto listener = callbackInfo->listener_.lock();
            if (callbackInfo && listener != nullptr) {
                MEDIA_INFO_LOG("ExecutePhotoAsset picture");
                napi_value result[ARGS_TWO] = { nullptr, nullptr };
                napi_value retVal;
                napi_get_undefined(listener->env_, &result[PARAM0]);
                napi_get_undefined(listener->env_, &result[PARAM1]);
                result[PARAM1] = Media::MediaLibraryCommNapi::CreatePhotoAssetNapi(listener->env_,
                    callbackInfo->uri, callbackInfo->cameraShotType, callbackInfo->burstKey);
                MEDIA_INFO_LOG("UpdatePictureJSCallback result %{public}s, type %{public}d, burstKey %{public}s",
                    callbackInfo->uri.c_str(), callbackInfo->cameraShotType, callbackInfo->burstKey.c_str());
                ExecuteCallbackNapiPara callbackPara {
                    .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
                listener->ExecuteCallback(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callbackPara);
                MEDIA_INFO_LOG("PhotoListener:UpdateJSCallbackAsync() complete");
                callbackInfo->listener_.reset();
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PhotoListener::UpdateMainPictureStageOneJSCallback(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) const
{
    MEDIA_INFO_LOG("PhotoListener:UpdateMainPictureStageOneJSCallback called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("PhotoListenerInfo:UpdateMainPictureStageOneJSCallback() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("PhotoListenerInfo:UpdateMainPictureStageOneJSCallback() failed to allocate work");
        return;
    }
    std::unique_ptr<PhotoListenerInfo> callbackInfo = std::make_unique<PhotoListenerInfo>(nullptr, shared_from_this());
    callbackInfo->surfaceBuffer = surfaceBuffer;
    callbackInfo->timestamp = timestamp;
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            PhotoListenerInfo* callbackInfo = reinterpret_cast<PhotoListenerInfo*>(work->data);
            if (callbackInfo && !callbackInfo->listener_.expired()) {
                MEDIA_INFO_LOG("ExecutePhotoAsset picture");
                sptr<SurfaceBuffer> surfaceBuffer = callbackInfo->surfaceBuffer;
                int64_t timestamp = callbackInfo->timestamp;
                auto listener = callbackInfo->listener_.lock();
                if (listener != nullptr) {
                    listener->ExecutePhoto(surfaceBuffer, timestamp);
                }
                callbackInfo->listener_.reset();
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

inline void LoggingSurfaceBufferInfo(sptr<SurfaceBuffer> buffer, std::string bufName)
{
    if (buffer) {
        MEDIA_INFO_LOG("AssembleAuxiliaryPhoto %{public}s w=%{public}d, h=%{public}d, f=%{public}d", bufName.c_str(),
            buffer->GetWidth(), buffer->GetHeight(), buffer->GetFormat());
    }
};

std::shared_ptr<Location> GetLocationBySettings(std::shared_ptr<PhotoCaptureSetting> settings)
{
    auto location = make_shared<Location>();
    if (settings) {
        settings->GetLocation(location);
        MEDIA_INFO_LOG("GetLocationBySettings latitude:%{private}f, longitude:%{private}f",
            location->latitude, location->longitude);
    } else {
        MEDIA_ERR_LOG("GetLocationBySettings failed!");
    }
    return location;
}

int32_t GetBurstSeqId(int32_t captureId)
{
    const uint32_t burstSeqIdMask = 0xFFFF;
    return captureId > 0 ? (static_cast<uint32_t>(captureId) & burstSeqIdMask) : captureId;
}

void CleanAfterTransPicture(sptr<PhotoOutput> photoOutput, int32_t captureId)
{
    if (!photoOutput) {
        MEDIA_ERR_LOG("CleanAfterTransPicture photoOutput is nullptr");
        return;
    }
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

void PhotoListener::AssembleAuxiliaryPhoto(int64_t timestamp, int32_t captureId) __attribute__((no_sanitize("cfi")))
{
    MEDIA_INFO_LOG("AssembleAuxiliaryPhoto begin captureId %{public}d, burstSeqId %{public}d",
        captureId, GetBurstSeqId(captureId));
    std::lock_guard<std::mutex> lock(g_assembleImageMutex);
    auto photoOutput = photoOutput_.promote();
    if (photoOutput && photoOutput->GetSession()) {
        auto location = GetLocationBySettings(photoOutput->GetDefaultCaptureSetting());
        if (location && photoOutput->photoProxyMap_[captureId]) {
            photoOutput->photoProxyMap_[captureId]->SetLocation(location->latitude, location->longitude);
        }
        std::unique_ptr<Media::Picture> picture = std::move(photoOutput->captureIdPictureMap_[captureId]);
        if (photoOutput->captureIdExifMap_[captureId] && picture) {
            auto buffer = photoOutput->captureIdExifMap_[captureId];
            LoggingSurfaceBufferInfo(buffer, "exifSurfaceBuffer");
            picture->SetExifMetadata(buffer);
            photoOutput->captureIdExifMap_[captureId] = nullptr;
        }
        if (photoOutput->captureIdGainmapMap_[captureId] && picture) {
            std::unique_ptr<Media::AuxiliaryPicture> uniptr = Media::AuxiliaryPicture::Create(
                photoOutput->captureIdGainmapMap_[captureId], Media::AuxiliaryPictureType::GAINMAP);
            std::shared_ptr<Media::AuxiliaryPicture> picturePtr = std::move(uniptr);
            LoggingSurfaceBufferInfo(photoOutput->captureIdGainmapMap_[captureId], "gainmapSurfaceBuffer");
            picture->SetAuxiliaryPicture(picturePtr);
            photoOutput->captureIdGainmapMap_[captureId] = nullptr;
        }
        if (photoOutput->captureIdDepthMap_[captureId] && picture) {
            std::unique_ptr<Media::AuxiliaryPicture> uniptr = Media::AuxiliaryPicture::Create(
                photoOutput->captureIdDepthMap_[captureId], Media::AuxiliaryPictureType::DEPTH_MAP);
            std::shared_ptr<Media::AuxiliaryPicture> picturePtr = std::move(uniptr);
            LoggingSurfaceBufferInfo(photoOutput->captureIdDepthMap_[captureId], "deepSurfaceBuffer");
            picture->SetAuxiliaryPicture(picturePtr);
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
        if (picture) {
            std::string uri;
            int32_t cameraShotType;
            std::string burstKey = "";
            photoOutput->GetSession()->CreateMediaLibrary(std::move(picture), photoOutput->photoProxyMap_[captureId],
                uri, cameraShotType, burstKey, timestamp);
            MEDIA_INFO_LOG("CreateMediaLibrary result %{public}s, type %{public}d", uri.c_str(), cameraShotType);
            UpdatePictureJSCallback(uri, cameraShotType, burstKey);
            CleanAfterTransPicture(photoOutput, captureId);
        } else {
            MEDIA_ERR_LOG("CreateMediaLibrary picture is nullptr");
        }
    }
}

void PhotoListener::ExecutePhoto(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) const
{
    MEDIA_INFO_LOG("ExecutePhoto");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;
    napi_value mainImage = nullptr;
    std::shared_ptr<Media::NativeImage> image = std::make_shared<Media::NativeImage>(surfaceBuffer,
        bufferProcessor_, timestamp);
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    mainImage = Media::ImageNapi::Create(env_, image);
    if (mainImage == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &mainImage);
    }
    result[PARAM1] = PhotoNapi::CreatePhoto(env_, mainImage);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_PHOTO_AVAILABLE, callbackNapiPara);
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void PhotoListener::ExecuteDeferredPhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecuteDeferredPhoto");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;

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
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, thumbnailWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, thumbnailHeight);
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailHeight: %{public}d", thumbnailWidth, thumbnailHeight);

    MEDIA_DEBUG_LOG("w:%{public}d, h:%{public}d, s:%{public}d, fd:%{public}d, size: %{public}d, format: %{public}d",
        bufferHandle->width, bufferHandle->height, bufferHandle->stride, bufferHandle->fd, bufferHandle->size,
        bufferHandle->format);

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);

    // deep copy buffer
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, 0);
    BufferHandle *newBufferHandle = CameraCloneBufferHandle(newSurfaceBuffer->GetBufferHandle());
    if (newBufferHandle == nullptr) {
        napi_value errorCode;
        napi_create_int32(env_, CameraErrorCode::INVALID_ARGUMENT, &errorCode);
        result[PARAM0] = errorCode;
        MEDIA_ERR_LOG("invalid bufferHandle");
    }

    // call js function
    sptr<DeferredPhotoProxy> deferredPhotoProxy;
    std::string imageIdStr = std::to_string(imageId);
    deferredPhotoProxy = new(std::nothrow) DeferredPhotoProxy(newBufferHandle, imageIdStr, deferredProcessingType,
        thumbnailWidth, thumbnailHeight);
    if (deferredPhotoProxy == nullptr) {
        napi_value errorCode;
        napi_create_int32(env_, CameraErrorCode::SERVICE_FATL_ERROR, &errorCode);
        result[PARAM0] = errorCode;
        MEDIA_ERR_LOG("failed to new deferredPhotoProxy!");
    }
    result[PARAM1] = DeferredPhotoProxyNapi::CreateDeferredPhotoProxy(env_, deferredPhotoProxy);

    ExecuteCallbackNapiPara callbackPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, callbackPara);

    // return buffer to buffer queue
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void PhotoListener::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer,
    int32_t captureId) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("PhotoListener::DeepCopyBuffer w=%{public}d, h=%{public}d, f=%{public}d surfaceName=%{public}s "
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
    MEDIA_DEBUG_LOG("PhotoListener::DeepCopyBuffer SurfaceBuffer alloc ret: %{public}d surfaceName=%{public}s "
        "captureId = %{public}d", allocErrorCode, "main", captureId);
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK) {
        MEDIA_ERR_LOG("PhotoListener memcpy_s failed");
    }
    MEDIA_DEBUG_LOG("PhotoListener::DeepCopyBuffer memcpy_s end surfaceName=%{public}s captureId = %{public}d",
        "main", captureId);
}

void PhotoListener::ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, bool isHighQuality, int64_t timestamp) const
{
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyStartInfo();
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ExecutePhotoAsset");
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    // deep copy buffer
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer, 0);
    BufferHandle* bufferHandle = newSurfaceBuffer->GetBufferHandle();
    if (bufferHandle == nullptr) {
        napi_value errorCode;
        napi_create_int32(env_, CameraErrorCode::INVALID_ARGUMENT, &errorCode);
        result[PARAM0] = errorCode;
        MEDIA_ERR_LOG("invalid bufferHandle");
    }
    newSurfaceBuffer->Map();
    auto photoOutput = photoOutput_.promote();
    string uri = "";
    int32_t cameraShotType = 0;

    std::string burstKey = "";
    CreateMediaLibrary(surfaceBuffer, bufferHandle, isHighQuality, uri, cameraShotType, burstKey, timestamp);
    MEDIA_INFO_LOG("CreateMediaLibrary result uri:%{public}s cameraShotType:%{public}d burstKey:%{public}s",
        uri.c_str(), cameraShotType, burstKey.c_str());
    result[PARAM1] = Media::MediaLibraryCommNapi::CreatePhotoAssetNapi(env_, uri, cameraShotType, burstKey);
    ExecuteCallbackNapiPara callbackPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callbackPara);
    // return buffer to buffer queue
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void PhotoListener::CreateMediaLibrary(sptr<SurfaceBuffer> surfaceBuffer, BufferHandle *bufferHandle,
    bool isHighQuality, std::string &uri, int32_t &cameraShotType, std::string &burstKey, int64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    if (bufferHandle == nullptr) {
        MEDIA_ERR_LOG("bufferHandle is nullptr");
        return;
    }
    // get buffer handle and photo info
    int32_t captureId;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, captureId);
    int32_t burstSeqId = -1;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    int64_t imageId = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageId, imageId);
    int32_t deferredProcessingType;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredProcessingType, deferredProcessingType);
    MEDIA_INFO_LOG(
        "PhotoListener ExecutePhotoAsset captureId:%{public}d "
        "imageId:%{public}" PRId64 ", deferredProcessingType:%{public}d, burstSeqId:%{public}d",
        captureId, imageId, deferredProcessingType, burstSeqId);
    int32_t photoWidth;
    int32_t photoHeight;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, photoWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, photoHeight);
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
    MEDIA_INFO_LOG("deferredImageFormat:%{public}d, width:%{public}d, height:%{public}d, size:%{public}" PRId64,
        deferredImageFormat, photoWidth, photoHeight, size);
    int32_t format = bufferHandle->format;
    sptr<CameraPhotoProxy> photoProxy;
    std::string imageIdStr = std::to_string(imageId);
    photoProxy = new(std::nothrow) CameraPhotoProxy(bufferHandle, format, photoWidth, photoHeight,
                                                    isHighQuality, captureId, burstSeqId);
    if (photoProxy == nullptr) {
        MEDIA_ERR_LOG("failed to new photoProxy");
        return;
    }
    photoProxy->SetDeferredAttrs(imageIdStr, deferredProcessingType, size, deferredImageFormat);
    auto photoOutput = photoOutput_.promote();
    if (photoOutput && photoOutput->GetSession()) {
        auto settings = photoOutput->GetDefaultCaptureSetting();
        if (settings) {
            auto location = make_shared<Location>();
            settings->GetLocation(location);
            photoProxy->SetLocation(location->latitude, location->longitude);
        }
        CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo();
        CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo();
        photoOutput->GetSession()->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
        CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo();
    }
}

void PhotoListener::UpdateJSCallback(sptr<Surface> photoSurface) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("PhotoListener UpdateJSCallback enter");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = photoSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("PhotoListener Failed to acquire surface buffer");
        return;
    }
    MEDIA_INFO_LOG("PhotoListener::UpdateJSCallback ts is:%{public}" PRId64, timestamp);
    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("PhotoListener UpdateJSCallback isDegradedImage:%{public}d", isDegradedImage);
    if ((callbackFlag_ & CAPTURE_PHOTO_ASSET) != 0) {
        CameraReportDfxUtils::GetInstance()->SetFirstBufferEndInfo();
        ExecutePhotoAsset(surfaceBuffer, isDegradedImage == 0, timestamp);
    } else if (isDegradedImage == 0 && (callbackFlag_ & CAPTURE_PHOTO) != 0) {
        ExecutePhoto(surfaceBuffer, timestamp);
    } else if (isDegradedImage != 0 && (callbackFlag_ & CAPTURE_DEFERRED_PHOTO) != 0) {
        ExecuteDeferredPhoto(surfaceBuffer);
    } else {
        MEDIA_INFO_LOG("PhotoListener on error callback");
    }
}

void PhotoListener::UpdateJSCallbackAsync(sptr<Surface> photoSurface) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("PhotoListener UpdateJSCallbackAsync enter");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    MEDIA_INFO_LOG("PhotoListener UpdateJSCallbackAsync get loop");
    if (!loop) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<PhotoListenerInfo> callbackInfo =
        std::make_unique<PhotoListenerInfo>(photoSurface, shared_from_this());
    work->data = callbackInfo.get();
    MEDIA_DEBUG_LOG("PhotoListener UpdateJSCallbackAsync uv_queue_work_with_qos start");
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            PhotoListenerInfo* callbackInfo = reinterpret_cast<PhotoListenerInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.lock();
                if (listener != nullptr) {
                    listener->UpdateJSCallback(callbackInfo->photoSurface_);
                }
                MEDIA_INFO_LOG("PhotoListener:UpdateJSCallbackAsync() complete");
                callbackInfo->photoSurface_ = nullptr;
                callbackInfo->listener_.reset();
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PhotoListener::SaveCallback(const std::string eventName, napi_value callback)
{
    MEDIA_INFO_LOG("PhotoListener::SaveCallback is called eventName:%{public}s", eventName.c_str());
    auto eventTypeEnum = PhotoOutputEventTypeHelper.ToEnum(eventName);
    switch (eventTypeEnum) {
        case PhotoOutputEventType::CAPTURE_PHOTO_AVAILABLE:
            callbackFlag_ |= CAPTURE_PHOTO;
            break;
        case PhotoOutputEventType::CAPTURE_DEFERRED_PHOTO_AVAILABLE:
            callbackFlag_ |= CAPTURE_DEFERRED_PHOTO;
            break;
        case PhotoOutputEventType::CAPTURE_PHOTO_ASSET_AVAILABLE:
            callbackFlag_ |= CAPTURE_PHOTO_ASSET;
            break;
        default:
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

void PhotoListener::RemoveCallback(const std::string eventName, napi_value callback)
{
    MEDIA_INFO_LOG("PhotoListener::RemoveCallback is called eventName:%{public}s", eventName.c_str());
    if (eventName == CONST_CAPTURE_PHOTO_AVAILABLE) {
        callbackFlag_ &= ~CAPTURE_PHOTO;
    } else if (eventName == CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE) {
        callbackFlag_ &= ~CAPTURE_DEFERRED_PHOTO;
    } else if (eventName == CONST_CAPTURE_PHOTO_ASSET_AVAILABLE) {
        auto photoOutput = photoOutput_.promote();
        if (photoOutput != nullptr) {
            photoOutput_->DeferImageDeliveryFor(DeferredDeliveryImageType::DELIVERY_NONE);
        }
        callbackFlag_ &= ~CAPTURE_PHOTO_ASSET;
    }
    RemoveCallbackRef(eventName, callback);
}

void RawPhotoListener::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("RawPhotoListener::OnBufferAvailable is called");
    if (!rawPhotoSurface_) {
        MEDIA_ERR_LOG("RawPhotoListener napi rawPhotoSurface_ is null");
        return;
    }
    UpdateJSCallbackAsync(rawPhotoSurface_);
}

void RawPhotoListener::ExecuteRawPhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecuteRawPhoto");
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_value rawImage = nullptr;
    std::shared_ptr<Media::NativeImage> image = std::make_shared<Media::NativeImage>(surfaceBuffer, bufferProcessor_);
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    rawImage = Media::ImageNapi::Create(env_, image);
    if (rawImage == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &rawImage);
    }
    result[PARAM1] = PhotoNapi::CreateRawPhoto(env_, rawImage);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_PHOTO_AVAILABLE, callbackNapiPara);
    rawPhotoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void RawPhotoListener::UpdateJSCallback(sptr<Surface> rawPhotoSurface) const
{
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = rawPhotoSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("RawPhotoListener Failed to acquire surface buffer");
        return;
    }

    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("RawPhotoListener UpdateJSCallback isDegradedImage:%{public}d", isDegradedImage);

    if (isDegradedImage == 0) {
        ExecuteRawPhoto(surfaceBuffer);
    } else {
        MEDIA_ERR_LOG("RawPhoto not support deferred photo");
    }
}

void RawPhotoListener::UpdateJSCallbackAsync(sptr<Surface> rawPhotoSurface) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<RawPhotoListenerInfo> callbackInfo =
        std::make_unique<RawPhotoListenerInfo>(rawPhotoSurface, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            RawPhotoListenerInfo* callbackInfo = reinterpret_cast<RawPhotoListenerInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.lock();
                if (listener != nullptr) {
                    listener->UpdateJSCallback(callbackInfo->rawPhotoSurface_);
                }
                MEDIA_INFO_LOG("RawPhotoListener:UpdateJSCallbackAsync() complete");
                callbackInfo->rawPhotoSurface_ = nullptr;
                callbackInfo->listener_.reset();
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

PhotoOutputCallback::PhotoOutputCallback(napi_env env) : ListenerBase(env) {}

void UpdateJSExecute(uv_work_t* work)
{
    PhotoOutputCallbackInfo* callbackInfo = reinterpret_cast<PhotoOutputCallbackInfo*>(work->data);
    if (callbackInfo) {
        if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_START ||
            callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_START_WITH_INFO) {
            g_captureId = callbackInfo->info_.captureID;
            MEDIA_DEBUG_LOG("UpdateJSExecute CAPTURE_START g_captureId:%{public}d", g_captureId);
        }
        if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_FRAME_SHUTTER &&
            g_captureId != callbackInfo->info_.captureID) {
            uv_sem_wait(&g_captureStartSem);
        }
    }
}

void PhotoOutputCallback::UpdateJSCallbackAsync(PhotoOutputEventType eventType, const CallbackInfo &info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        MEDIA_ERR_LOG("failed to get event loop or failed to allocate work");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        MEDIA_ERR_LOG("UpdateJSCallbackAsync work is null");
        return;
    }
    if (!g_isSemInited) {
        uv_sem_init(&g_captureStartSem, 0);
        g_isSemInited = true;
    }
    std::unique_ptr<PhotoOutputCallbackInfo> callbackInfo =
        std::make_unique<PhotoOutputCallbackInfo>(eventType, info, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, UpdateJSExecute, [] (uv_work_t* work, int status) {
        PhotoOutputCallbackInfo* callbackInfo = reinterpret_cast<PhotoOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->info_);
                if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_START ||
                    callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_START_WITH_INFO) {
                    MEDIA_DEBUG_LOG("PhotoOutputEventType::CAPTURE_START work done execute!");
                    uv_sem_post(&g_captureStartSem);
                } else if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_FRAME_SHUTTER) {
                    MEDIA_DEBUG_LOG("PhotoOutputEventType::CAPTURE_FRAME_SHUTTER work done execute!");
                    uv_sem_destroy(&g_captureStartSem);
                    g_isSemInited = false;
                }
            }
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PhotoOutputCallback::OnCaptureStarted(const int32_t captureID) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
    CallbackInfo info;
    info.captureID = captureID;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_START_WITH_INFO, info);
}

void PhotoOutputCallback::OnCaptureStarted(const int32_t captureID, uint32_t exposureTime) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
    CallbackInfo info;
    info.captureID = captureID;
    info.timestamp = exposureTime;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_START, info);
}

void PhotoOutputCallback::OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnCaptureEnded is called!, captureID: %{public}d, frameCount: %{public}d",
        captureID, frameCount);
    CallbackInfo info;
    info.captureID = captureID;
    info.frameCount = frameCount;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_END, info);
}

void PhotoOutputCallback::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnFrameShutter is called, captureID: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_FRAME_SHUTTER, info);
}

void PhotoOutputCallback::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnFrameShutterEnd is called, captureID: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END, info);
}

void PhotoOutputCallback::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnCaptureReady is called, captureID: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_READY, info);
}

void PhotoOutputCallback::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureError is called!, captureID: %{public}d, errorCode: %{public}d", captureId, errorCode);
    CallbackInfo info;
    info.captureID = captureId;
    info.errorCode = errorCode;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_ERROR, info);
}

void PhotoOutputCallback::OnEstimatedCaptureDuration(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called!, duration: %{public}d", duration);
    CallbackInfo info;
    info.duration = duration;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION, info);
}

void PhotoOutputCallback::ExecuteCaptureStartCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    if (IsEmpty(CONST_CAPTURE_START_WITH_INFO)) {
        napi_create_int32(env_, info.captureID, &result[PARAM1]);
        ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO,
            .argv = result, .result = &retVal };
        ExecuteCallback(CONST_CAPTURE_START, callbackNapiPara);
    } else {
        napi_value propValue;
        napi_create_object(env_, &result[PARAM1]);
        napi_create_int32(env_, info.captureID, &propValue);
        napi_set_named_property(env_, result[PARAM1], "captureId", propValue);
        int32_t invalidExposureTime = -1;
        napi_create_int32(env_, invalidExposureTime, &propValue);
        napi_set_named_property(env_, result[PARAM1], "time", propValue);
        ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO,
            .argv = result, .result = &retVal };
        ExecuteCallback(CONST_CAPTURE_START_WITH_INFO, callbackNapiPara);
    }
}

void PhotoOutputCallback::ExecuteCaptureStartWithInfoCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);
    napi_create_int32(env_, info.captureID, &propValue);
    napi_set_named_property(env_, result[PARAM1], "captureId", propValue);
    napi_create_int32(env_, info.timestamp, &propValue);
    napi_set_named_property(env_, result[PARAM1], "time", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_START_WITH_INFO, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteCaptureEndCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);
    napi_create_int32(env_, info.captureID, &propValue);
    napi_set_named_property(env_, result[PARAM1], "captureId", propValue);
    napi_create_int32(env_, info.frameCount, &propValue);
    napi_set_named_property(env_, result[PARAM1], "frameCount", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_END, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteFrameShutterCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);
    napi_create_int32(env_, info.captureID, &propValue);
    napi_set_named_property(env_, result[PARAM1], "captureId", propValue);
    napi_create_int64(env_, info.timestamp, &propValue);
    napi_set_named_property(env_, result[PARAM1], "timestamp", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_FRAME_SHUTTER, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteFrameShutterEndCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);
    napi_create_int32(env_, info.captureID, &propValue);
    napi_set_named_property(env_, result[PARAM1], "captureId", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_FRAME_SHUTTER_END, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteCaptureReadyCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_ONE] = { nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_READY, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteCaptureErrorCb(const CallbackInfo& info) const
{
    napi_value errJsResult[ARGS_ONE] = { nullptr };
    napi_value retVal;
    napi_value propValue;

    napi_create_object(env_, &errJsResult[PARAM0]);
    napi_create_int32(env_, info.errorCode, &propValue);
    napi_set_named_property(env_, errJsResult[PARAM0], "code", propValue);
    ExecuteCallbackNapiPara callbackNapiPara {
        .recv = nullptr, .argc = ARGS_ONE, .argv = errJsResult, .result = &retVal
    };
    ExecuteCallback(CONST_CAPTURE_ERROR, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteEstimatedCaptureDurationCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_int32(env_, info.duration, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, callbackNapiPara);
}

void PhotoOutputCallback::UpdateJSCallback(PhotoOutputEventType eventType, const CallbackInfo& info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    switch (eventType) {
        case PhotoOutputEventType::CAPTURE_START:
            ExecuteCaptureStartCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_END:
            ExecuteCaptureEndCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER:
            ExecuteFrameShutterCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_ERROR:
            ExecuteCaptureErrorCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END:
            ExecuteFrameShutterEndCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_READY:
            ExecuteCaptureReadyCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION:
            ExecuteEstimatedCaptureDurationCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_START_WITH_INFO:
            ExecuteCaptureStartWithInfoCb(info);
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
    }
}

ThumbnailListener::ThumbnailListener(napi_env env, const sptr<PhotoOutput> photoOutput)
    : ListenerBase(env), photoOutput_(photoOutput)
{}

void ThumbnailListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ThumbnailListener::OnBufferAvailable is called");
    ExecuteDeepCopySurfaceBuffer();
    constexpr int32_t memSize = 20 * 1024;
    int32_t retCode = CameraManager::GetInstance()->RequireMemorySize(memSize);
    CHECK_ERROR_RETURN_LOG(retCode != 0, "ThumbnailListener::OnBufferAvailable RequireMemorySize failed");
    MEDIA_INFO_LOG("ThumbnailListener::OnBufferAvailable is end");
}

void ThumbnailListener::ExecuteDeepCopySurfaceBuffer()
{
    auto photoOutput = photoOutput_.promote();
    CHECK_ERROR_RETURN_LOG(photoOutput == nullptr, "ThumbnailListener photoOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(photoOutput->thumbnailSurface_ == nullptr, "ThumbnailListener thumbnailSurface_ is nullptr");
    auto surface = photoOutput->thumbnailSurface_;
    string surfaceName = "Thumbnail";
    MEDIA_INFO_LOG("ThumbnailListener ExecuteDeepCopySurfaceBuffer surfaceName = %{public}s",
        surfaceName.c_str());
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    MEDIA_INFO_LOG("ThumbnailListener surfaceName = %{public}s AcquireBuffer before", surfaceName.c_str());
    SurfaceError surfaceRet = surface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    MEDIA_INFO_LOG("ThumbnailListener surfaceName = %{public}s AcquireBuffer end", surfaceName.c_str());
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("ThumbnailListener Failed to acquire surface buffer");
        return;
    }
    int32_t thumbnailWidth;
    int32_t thumbnailHeight;
    int32_t burstSeqId = -1;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, thumbnailWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, thumbnailHeight);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    int32_t captureId = GetCaptureId(surfaceBuffer);
    MEDIA_INFO_LOG("ThumbnailListener thumbnailWidth:%{public}d, thumbnailheight: %{public}d, captureId: %{public}d,"
        "burstSeqId: %{public}d", thumbnailWidth, thumbnailHeight, captureId, burstSeqId);
    if (burstSeqId != -1) {
        surface->ReleaseBuffer(surfaceBuffer, -1);
        return;
    }
    Media::InitializationOptions opts {
        .size = { .width = thumbnailWidth, .height = thumbnailHeight },
        .srcPixelFormat = Media::PixelFormat::RGBA_8888,
        .pixelFormat = Media::PixelFormat::RGBA_8888,
    };
    const int32_t formatSize = 4;
    auto pixelMap = Media::PixelMap::Create(static_cast<const uint32_t*>(surfaceBuffer->GetVirAddr()),
        thumbnailWidth * thumbnailHeight * formatSize, 0, thumbnailWidth, opts, true);
    MEDIA_DEBUG_LOG("ThumbnailListener ReleaseBuffer begin");
    surface->ReleaseBuffer(surfaceBuffer, -1);
    MEDIA_DEBUG_LOG("ThumbnailListener ReleaseBuffer end");
    UpdateJSCallbackAsync(std::move(pixelMap));
    MEDIA_INFO_LOG("ThumbnailListener surfaceName = %{public}s UpdateJSCallbackAsync captureId=%{public}d, end",
        surfaceName.c_str(), captureId);
}

void ThumbnailListener::UpdateJSCallbackAsync(unique_ptr<Media::PixelMap> pixelMap)
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<ThumbnailListenerInfo> callbackInfo =
        std::make_unique<ThumbnailListenerInfo>(this, std::move(pixelMap));
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            ThumbnailListenerInfo* callbackInfo = reinterpret_cast<ThumbnailListenerInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.promote();
                if (listener != nullptr) {
                    listener->UpdateJSCallback(std::move(callbackInfo->pixelMap_));
                    MEDIA_INFO_LOG("ThumbnailListener:UpdateJSCallbackAsync() complete");
                }
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void ThumbnailListener::UpdateJSCallback(unique_ptr<Media::PixelMap> pixelMap) const
{
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("ThumbnailListener::UpdateJSCallback surfaceBuffer is nullptr");
        return;
    }
    napi_value result[ARGS_TWO] = { 0 };
    napi_get_undefined(env_, &result[0]);
    napi_get_undefined(env_, &result[1]);
    napi_value retVal;
    MEDIA_INFO_LOG("enter ImageNapi::Create start");
    napi_value valueParam = Media::PixelMapNapi::CreatePixelMap(env_, std::move(pixelMap));
    if (valueParam == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &valueParam);
    }
    MEDIA_INFO_LOG("enter ImageNapi::Create end");
    result[1] = valueParam;
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_QUICK_THUMBNAIL, callbackNapiPara);
}

void ThumbnailListener::UpdateJSCallback() const
{
    auto photoOutput = photoOutput_.promote();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("ThumbnailListener::UpdateJSCallback photoOutput is nullptr");
        return;
    }
    napi_value result[ARGS_TWO] = { 0 };
    napi_get_undefined(env_, &result[0]);
    napi_get_undefined(env_, &result[1]);
    napi_value retVal;
    MEDIA_INFO_LOG("enter ImageNapi::Create start");
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> thumbnailBuffer = nullptr;
    SurfaceError surfaceRet = photoOutput->thumbnailSurface_->AcquireBuffer(thumbnailBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("ThumbnailListener Failed to acquire surface buffer");
        return;
    }
    int32_t thumbnailWidth;
    int32_t thumbnailHeight;
    thumbnailBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, thumbnailWidth);
    thumbnailBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, thumbnailHeight);
    Media::InitializationOptions opts;
    opts.srcPixelFormat = Media::PixelFormat::RGBA_8888;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = { .width = thumbnailWidth, .height = thumbnailHeight };
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailheight: %{public}d", thumbnailWidth, thumbnailHeight);
    const int32_t formatSize = 4;
    auto pixelMap = Media::PixelMap::Create(static_cast<const uint32_t*>(thumbnailBuffer->GetVirAddr()),
        thumbnailWidth * thumbnailHeight * formatSize, 0, thumbnailWidth, opts, true);
    napi_value valueParam = Media::PixelMapNapi::CreatePixelMap(env_, std::move(pixelMap));
    if (valueParam == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &valueParam);
    }
    MEDIA_INFO_LOG("enter ImageNapi::Create end");
    result[1] = valueParam;

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_QUICK_THUMBNAIL, callbackNapiPara);
    photoOutput->thumbnailSurface_->ReleaseBuffer(thumbnailBuffer, -1);
}

void ThumbnailListener::UpdateJSCallbackAsync()
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<ThumbnailListenerInfo> callbackInfo = std::make_unique<ThumbnailListenerInfo>(this, nullptr);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            ThumbnailListenerInfo* callbackInfo = reinterpret_cast<ThumbnailListenerInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.promote();
                if (listener != nullptr) {
                    listener->UpdateJSCallback();
                    MEDIA_INFO_LOG("ThumbnailListener:UpdateJSCallbackAsync() complete");
                }
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

PhotoOutputNapi::PhotoOutputNapi() {}

PhotoOutputNapi::~PhotoOutputNapi()
{
    if (pictureListener_) {
        pictureListener_->gainmapImageListener = nullptr;
        pictureListener_->deepImageListener = nullptr;
        pictureListener_->exifImageListener = nullptr;
        pictureListener_->debugImageListener = nullptr;
    }
    pictureListener_ = nullptr;
    MEDIA_DEBUG_LOG("~PhotoOutputNapi is called");
}

void PhotoOutputNapi::PhotoOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapiDestructor is called");
    PhotoOutputNapi* photoOutput = reinterpret_cast<PhotoOutputNapi*>(nativeObject);
    if (photoOutput != nullptr) {
        delete photoOutput;
    }
}

napi_value PhotoOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor photo_output_props[] = {
        DECLARE_NAPI_FUNCTION("isMovingPhotoSupported", IsMovingPhotoSupported),
        DECLARE_NAPI_FUNCTION("enableMovingPhoto", EnableMovingPhoto),
        DECLARE_NAPI_FUNCTION("capture", Capture),
        DECLARE_NAPI_FUNCTION("burstCapture", BurstCapture),
        DECLARE_NAPI_FUNCTION("confirmCapture", ConfirmCapture),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("isMirrorSupported", IsMirrorSupported),
        DECLARE_NAPI_FUNCTION("enableMirror", EnableMirror),
        DECLARE_NAPI_FUNCTION("enableQuickThumbnail", EnableQuickThumbnail),
        DECLARE_NAPI_FUNCTION("isQuickThumbnailSupported", IsQuickThumbnailSupported),
        DECLARE_NAPI_FUNCTION("enableRawDelivery", EnableRawDelivery),
        DECLARE_NAPI_FUNCTION("isRawDeliverySupported", IsRawDeliverySupported),
        DECLARE_NAPI_FUNCTION("getSupportedMovingPhotoVideoCodecTypes", GetSupportedMovingPhotoVideoCodecTypes),
        DECLARE_NAPI_FUNCTION("setMovingPhotoVideoCodecType", SetMovingPhotoVideoCodecType),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off),
        DECLARE_NAPI_FUNCTION("deferImageDelivery", DeferImageDeliveryFor),
        DECLARE_NAPI_FUNCTION("deferImageDeliveryFor", DeferImageDeliveryFor),
        DECLARE_NAPI_FUNCTION("isDeferredImageDeliverySupported", IsDeferredImageDeliverySupported),
        DECLARE_NAPI_FUNCTION("isDeferredImageDeliveryEnabled", IsDeferredImageDeliveryEnabled),
        DECLARE_NAPI_FUNCTION("isAutoHighQualityPhotoSupported", IsAutoHighQualityPhotoSupported),
        DECLARE_NAPI_FUNCTION("enableAutoHighQualityPhoto", EnableAutoHighQualityPhoto),
        DECLARE_NAPI_FUNCTION("getActiveProfile", GetActiveProfile),
        DECLARE_NAPI_FUNCTION("getPhotoRotation", GetPhotoRotation),
        DECLARE_NAPI_FUNCTION("isAutoCloudImageEnhancementSupported", IsAutoCloudImageEnhancementSupported),
        DECLARE_NAPI_FUNCTION("enableAutoCloudImageEnhancement", EnableAutoCloudImageEnhancement),
        DECLARE_NAPI_FUNCTION("isDepthDataDeliverySupported", IsDepthDataDeliverySupported),
        DECLARE_NAPI_FUNCTION("enableDepthDataDelivery", EnableDepthDataDelivery)
    };

    status = napi_define_class(env, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, PhotoOutputNapiConstructor,
        nullptr, sizeof(photo_output_props) / sizeof(photo_output_props[PARAM0]), photo_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value PhotoOutputNapi::PhotoOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoOutputNapi> obj = std::make_unique<PhotoOutputNapi>();
        obj->photoOutput_ = sPhotoOutput_;
        obj->profile_ = sPhotoOutput_->GetPhotoProfile();
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
		    PhotoOutputNapi::PhotoOutputNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoOutputNapiConstructor call Failed!");
    return result;
}

sptr<PhotoOutput> PhotoOutputNapi::GetPhotoOutput()
{
    return photoOutput_;
}

bool PhotoOutputNapi::GetEnableMirror()
{
    return isMirrorEnabled_;
}

bool PhotoOutputNapi::IsPhotoOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsPhotoOutput is called");
    bool result = false;
    napi_status status;
    napi_value constructor = nullptr;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        status = napi_instanceof(env, obj, constructor, &result);
        if (status != napi_ok) {
            result = false;
        }
    }
    return result;
}

void PhotoOutputNapi::CreateMultiChannelPictureLisenter(napi_env env)
{
    if (pictureListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        sptr<PictureListener> pictureListener = new (std::nothrow) PictureListener();
        pictureListener->InitPictureListeners(env, photoOutput_);
        if (photoListener_ == nullptr) {
            sptr<PhotoListener> photoListener = new (std::nothrow) PhotoListener(env, sPhotoSurface_, photoOutput_);
            SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener);
            if (ret != SURFACE_ERROR_OK) {
                MEDIA_ERR_LOG("register surface consumer listener failed!");
            }
            photoListener_ = photoListener;
            pictureListener_ = pictureListener;
        }
        if (photoOutput_->taskManager_ == nullptr) {
            constexpr int32_t auxiliaryPictureCount = 4;
            photoOutput_->taskManager_ = std::make_shared<DeferredProcessing::TaskManager>("AuxilaryPictureListener",
                auxiliaryPictureCount, false);
        }
    }
}

void PhotoOutputNapi::CreateSingleChannelPhotoLisenter(napi_env env)
{
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        sptr<PhotoListener> photoListener = new (std::nothrow) PhotoListener(env, sPhotoSurface_, photoOutput_);
        SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        photoListener_ = photoListener;
    }
}

napi_value PhotoOutputNapi::CreatePhotoOutput(napi_env env, Profile& profile, std::string surfaceId)
{
    MEDIA_DEBUG_LOG("CreatePhotoOutput is called, profile CameraFormat= %{public}d", profile.GetCameraFormat());
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value constructor;
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        MEDIA_INFO_LOG("CreatePhotoOutput surfaceId: %{public}s", surfaceId.c_str());
        sptr<Surface> photoSurface;
        if (surfaceId == "") {
            MEDIA_INFO_LOG("create surface as consumer");
            photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
            sPhotoSurface_ = photoSurface;
        } else {
            MEDIA_INFO_LOG("get surface by surfaceId");
            photoSurface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        if (photoSurface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }
        photoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
        sptr<IBufferProducer> surfaceProducer = photoSurface->GetProducer();
        MEDIA_INFO_LOG("profile width: %{public}d, height: %{public}d, format = %{public}d, "
                       "surface width: %{public}d, height: %{public}d", profile.GetSize().width,
                       profile.GetSize().height, static_cast<int32_t>(profile.GetCameraFormat()),
                       photoSurface->GetDefaultWidth(), photoSurface->GetDefaultHeight());
        int retCode = CameraManager::GetInstance()->CreatePhotoOutput(profile, surfaceProducer, &sPhotoOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode) || sPhotoOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create CreatePhotoOutput");
            return result;
        }
        if (surfaceId == "") {
            sPhotoOutput_->SetNativeSurface(true);
        }
        if (sPhotoOutput_->IsYuvOrHeifPhoto()) {
            sPhotoOutput_->CreateMultiChannel();
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPhotoOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_INFO_LOG("Success to create photo output instance");
            return result;
        }
    }
    MEDIA_ERR_LOG("CreatePhotoOutput call Failed!");
    return result;
}

napi_value PhotoOutputNapi::CreatePhotoOutput(napi_env env, std::string surfaceId)
{
    MEDIA_INFO_LOG("CreatePhotoOutput with only surfaceId is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        MEDIA_INFO_LOG("CreatePhotoOutput surfaceId: %{public}s", surfaceId.c_str());
        sptr<Surface> photoSurface;
        if (surfaceId == "") {
            MEDIA_INFO_LOG("create surface as consumer");
            photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
            sPhotoSurface_ = photoSurface;
        } else {
            MEDIA_INFO_LOG("get surface by surfaceId");
            photoSurface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        if (photoSurface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }
        sptr<IBufferProducer> surfaceProducer = photoSurface->GetProducer();
        MEDIA_INFO_LOG("surface width: %{public}d, height: %{public}d", photoSurface->GetDefaultWidth(),
            photoSurface->GetDefaultHeight());
        int retCode = CameraManager::GetInstance()->CreatePhotoOutputWithoutProfile(surfaceProducer, &sPhotoOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode) || sPhotoOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create CreatePhotoOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPhotoOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("Success to create photo output instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create photo output instance");
        }
    }
    MEDIA_ERR_LOG("CreatePhotoOutput call Failed!");
    return result;
}

bool ParseCaptureSettings(napi_env env, napi_callback_info info, PhotoOutputAsyncContext* asyncContext,
    std::shared_ptr<CameraNapiAsyncFunction>& asyncFunction, bool isSettingOptional)
{
    Location settingsLocation;
    CameraNapiObject settingsLocationNapiOjbect { {
        { "latitude", &settingsLocation.latitude },
        { "longitude", &settingsLocation.longitude },
        { "altitude", &settingsLocation.altitude },
    } };
    CameraNapiObject settingsNapiOjbect { {
        { "quality", &asyncContext->quality },
        { "rotation", &asyncContext->rotation },
        { "location", &settingsLocationNapiOjbect },
        { "mirror", &asyncContext->isMirror },
    } };
    unordered_set<std::string> optionalKeys = { "quality", "rotation", "location", "mirror" };
    settingsNapiOjbect.SetOptionalKeys(optionalKeys);

    asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Capture", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction, settingsNapiOjbect);
    if (jsParamParser.IsStatusOk()) {
        if (settingsNapiOjbect.IsKeySetted("quality") && !ValidQualityLevelFromJs(asyncContext->quality)) {
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "quality field not legal");
            return false;
        }
        if (settingsNapiOjbect.IsKeySetted("rotation") && !ValidImageRotationFromJs(asyncContext->rotation)) {
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "rotation field not legal");
            return false;
        }
        if (settingsNapiOjbect.IsKeySetted("mirror") && asyncContext->isMirror) {
            MEDIA_INFO_LOG("GetMirrorStatus is ok!");
            asyncContext->isMirrorSettedByUser = true;
        }
        MEDIA_INFO_LOG("ParseCaptureSettings with capture settings pass");
        asyncContext->hasPhotoSettings = true;
        if (settingsNapiOjbect.IsKeySetted("location")) {
            asyncContext->location = std::make_shared<Location>(settingsLocation);
        }
    } else if (isSettingOptional) {
        MEDIA_WARNING_LOG("ParseCaptureSettings check capture settings fail, try capture without settings");
        jsParamParser = CameraNapiParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    } else {
        // Do nothing.
    }
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("ParseCaptureSettings invalid argument");
        return false;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    return true;
}

napi_value PhotoOutputNapi::Capture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Capture is called");
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>(
        "PhotoOutputNapi::Capture", CameraNapiUtils::IncrementAndGet(photoOutputTaskId));
    std::shared_ptr<CameraNapiAsyncFunction> asyncFunction;
    if (!ParseCaptureSettings(env, info, asyncContext.get(), asyncFunction, true)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::Capture parse parameters fail.");
        return nullptr;
    }
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PhotoOutputNapi::Capture running on worker");
            auto context = static_cast<PhotoOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "PhotoOutputNapi::Capture async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() { ProcessCapture(context, false); });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Capture");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputNapi::Capture");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PhotoOutputNapi::BurstCapture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("BurstCapture is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoHighQualityPhoto is called!");
        return nullptr;
    }
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>(
        "PhotoOutputNapi::BurstCapture", CameraNapiUtils::IncrementAndGet(photoOutputTaskId));
    std::shared_ptr<CameraNapiAsyncFunction> asyncFunction;
    if (!ParseCaptureSettings(env, info, asyncContext.get(), asyncFunction, false)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::BurstCapture parse parameters fail.");
        return nullptr;
    }
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PhotoOutputNapi::BurstCapture running on worker");
            auto context = static_cast<PhotoOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(
                context->objectInfo == nullptr, "PhotoOutputNapi::BurstCapture async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() { ProcessCapture(context, true); });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::BurstCapture");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputNapi::BurstCapture");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PhotoOutputNapi::ConfirmCapture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ConfirmCapture is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO] = {};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t retCode = photoOutputNapi->photoOutput_->ConfirmCapture();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>(
        "PhotoOutputNapi::Release", CameraNapiUtils::IncrementAndGet(photoOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::Release invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PhotoOutputNapi::Release running on worker");
            auto context = static_cast<PhotoOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "PhotoOutputNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->photoOutput_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Release");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PhotoOutputNapi::IsMirrorSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsMirrorSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        bool isSupported = photoOutputNapi->photoOutput_->IsMirrorSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsMirrorSupported call Failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::EnableMirror(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableMirror is called");
    bool isMirror = false;
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isMirror);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableMirror invalid argument");
        return nullptr;
    }
    auto session = photoOutputNapi->GetPhotoOutput()->GetSession();
    if (session != nullptr) {
        photoOutputNapi->isMirrorEnabled_ = isMirror;
        int32_t retCode = session->EnableMovingPhotoMirror(isMirror);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::IsQuickThumbnailSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsQuickThumbnailSupported is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t retCode = photoOutputNapi->photoOutput_->IsQuickThumbnailSupported();
        bool isSupported = (retCode == 0);
        if (retCode > 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::DeferImageDeliveryFor(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi DeferImageDeliveryFor is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t deliveryType;
        napi_get_value_int32(env, argv[PARAM0], &deliveryType);
        photoOutputNapi->photoOutput_->DeferImageDeliveryFor(static_cast<DeferredDeliveryImageType>(deliveryType));
        photoOutputNapi->isDeferredPhotoEnabled_ = deliveryType == DELIVERY_PHOTO;
    }
    return result;
}

napi_value PhotoOutputNapi::IsDeferredImageDeliverySupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsDeferredImageDeliverySupported is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t deliveryType;
        napi_get_value_int32(env, argv[PARAM0], &deliveryType);
        int32_t retCode = photoOutputNapi->photoOutput_->IsDeferredImageDeliverySupported(
            static_cast<DeferredDeliveryImageType>(deliveryType));
        bool isSupported = (retCode == 0);
        if (retCode > 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::IsDeferredImageDeliveryEnabled(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsDeferredImageDeliveryEnabled is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t deliveryType;
        napi_get_value_int32(env, argv[PARAM0], &deliveryType);
        int32_t retCode = photoOutputNapi->photoOutput_->IsDeferredImageDeliveryEnabled(
            static_cast<DeferredDeliveryImageType>(deliveryType));
        bool isSupported = (retCode == 0);
        if (retCode > 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::GetPhotoRotation(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPhotoRotation is called!");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t value;
        napi_status ret = napi_get_value_int32(env, argv[PARAM0], &value);
        if (ret != napi_ok) {
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT,
                "GetPhotoRotation parameter missing or parameter type incorrect.");
            return result;
        }
        int32_t retCode = photoOutputNapi->photoOutput_->GetPhotoRotation(value);
        if (retCode == SERVICE_FATL_ERROR) {
            CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR,
                "GetPhotoRotation Camera service fatal error.");
            return result;
        }
        napi_create_int32(env, retCode, &result);
        MEDIA_INFO_LOG("PhotoOutputNapi GetPhotoRotation! %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("PhotoOutputNapi GetPhotoRotation! called failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::IsMovingPhotoSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsMotionPhotoSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status != napi_ok || photoOutputNapi == nullptr) {
        MEDIA_ERR_LOG("IsMotionPhotoSupported photoOutputNapi is null!");
        return result;
    }
    auto session = photoOutputNapi->GetPhotoOutput()->GetSession();
    if (session != nullptr) {
        bool isSupported = session->IsMovingPhotoSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        napi_get_boolean(env, false, &result);
        MEDIA_ERR_LOG("IsMotionPhotoSupported call Failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::EnableMovingPhoto(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("enableMovingPhoto is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status != napi_ok || photoOutputNapi == nullptr) {
        MEDIA_ERR_LOG("EnableMovingPhoto photoOutputNapi is null!");
        return result;
    }
    auto session = photoOutputNapi->GetPhotoOutput()->GetSession();
    if (session != nullptr) {
        bool isEnableMovingPhoto;
        napi_get_value_bool(env, argv[PARAM0], &isEnableMovingPhoto);
        session->LockForControl();
        int32_t retCode = session->EnableMovingPhoto(isEnableMovingPhoto);
        session->UnlockForControl();
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::GetSupportedMovingPhotoVideoCodecTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsMotionPhotoSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status != napi_ok || photoOutputNapi == nullptr) {
        MEDIA_ERR_LOG("IsMotionPhotoSupported photoOutputNapi is null!");
        return result;
    }
    vector<int32_t> videoCodecTypes = {VideoCodecType::VIDEO_ENCODE_TYPE_AVC, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC};
    result = CameraNapiUtils::CreateJSArray(env, status, videoCodecTypes);
    if (status != napi_ok) {
        result = CameraNapiUtils::CreateJSArray(env, status, {});
    }
    return result;
}

napi_value PhotoOutputNapi::SetMovingPhotoVideoCodecType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetMovingPhotoVideoCodecType is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_number && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status != napi_ok || photoOutputNapi == nullptr) {
        MEDIA_ERR_LOG("SetMovingPhotoVideoCodecType photoOutputNapi is null!");
        return result;
    }
    if (photoOutputNapi->GetPhotoOutput() != nullptr) {
        int32_t codecType;
        napi_get_value_int32(env, argv[PARAM0], &codecType);
        int32_t retCode = photoOutputNapi->GetPhotoOutput()->SetMovingPhotoVideoCodecType(codecType);
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::EnableQuickThumbnail(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableQuickThumbnail is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    bool thumbnailSwitch;
    if (status == napi_ok && photoOutputNapi != nullptr) {
        napi_get_value_bool(env, argv[PARAM0], &thumbnailSwitch);
        photoOutputNapi->isQuickThumbnailEnabled_ = thumbnailSwitch;
        int32_t retCode = photoOutputNapi->photoOutput_->SetThumbnail(thumbnailSwitch);
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::IsRawDeliverySupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsRawDeliverySupported is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    bool isSupported = false;
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t retCode = photoOutputNapi->photoOutput_->IsRawDeliverySupported(isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }
    napi_get_boolean(env, isSupported, &result);
    return result;
}

napi_value PhotoOutputNapi::EnableRawDelivery(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableRawDelivery is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    bool rawDeliverySwitch;
    if (status == napi_ok && photoOutputNapi != nullptr) {
        napi_get_value_bool(env, argv[PARAM0], &rawDeliverySwitch);
        int32_t retCode = photoOutputNapi->photoOutput_->EnableRawDelivery(rawDeliverySwitch);
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    MEDIA_INFO_LOG("new rawPhotoListener and register surface consumer listener");
    CHECK_ERROR_RETURN_RET_LOG(photoOutputNapi == nullptr, result, "photoOutputNapi is null!");
    auto rawSurface = photoOutputNapi->photoOutput_->rawPhotoSurface_;
    if (rawSurface == nullptr) {
        MEDIA_ERR_LOG("rawPhotoSurface_ is null!");
        return result;
    }
    sptr<RawPhotoListener> rawPhotoListener = new (std::nothrow) RawPhotoListener(env, rawSurface);
    if (rawPhotoListener == nullptr) {
        MEDIA_ERR_LOG("failed to new rawPhotoListener");
        return result;
    }
    SurfaceError ret = rawSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)rawPhotoListener);
    if (ret != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("register surface consumer listener failed!");
    }
    photoOutputNapi->rawPhotoListener_ = rawPhotoListener;
    napi_value callback;
    napi_get_reference_value(env, rawCallback_, &callback);
    photoOutputNapi->rawPhotoListener_->SaveCallbackReference(CONST_CAPTURE_PHOTO_AVAILABLE, callback, false);
    return result;
}

napi_value PhotoOutputNapi::GetActiveProfile(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapi::GetActiveProfile is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::GetActiveProfile parse parameter occur error");
        return nullptr;
    }
    auto profile = photoOutputNapi->photoOutput_->GetPhotoProfile();
    if (profile == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return CameraNapiObjProfile(*profile).GenerateNapiValue(env);
}

void PhotoOutputNapi::RegisterQuickThumbnailCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi quickThumbnail on is called!");
        return;
    }

    // Set callback for exposureStateChange
    if (thumbnailListener_ == nullptr) {
        if (!isQuickThumbnailEnabled_) {
            MEDIA_ERR_LOG("quickThumbnail is not enabled!");
            napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
            return;
        }
        thumbnailListener_ = new ThumbnailListener(env, photoOutput_);
        photoOutput_->SetThumbnailListener((sptr<IBufferConsumerListener>&)thumbnailListener_);
    }
    thumbnailListener_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputNapi::UnregisterQuickThumbnailCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi quickThumbnail off is called!");
        return;
    }
    if (!isQuickThumbnailEnabled_) {
        MEDIA_ERR_LOG("quickThumbnail is not enabled!");
        napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
        return;
    }
    if (thumbnailListener_ != nullptr) {
        thumbnailListener_->RemoveCallbackRef(eventName, callback);
    }
}

void PhotoOutputNapi::RegisterPhotoAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sPhotoSurface_ == nullptr) {
        MEDIA_ERR_LOG("sPhotoSurface_ is null!");
        return;
    }
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        sptr<PhotoListener> photoListener = new (std::nothrow) PhotoListener(env, sPhotoSurface_, photoOutput_);
        if (photoListener == nullptr) {
            MEDIA_ERR_LOG("photoListener is null!");
            return;
        }
        SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        photoListener_ = photoListener;
    }
    photoListener_->SaveCallback(CONST_CAPTURE_PHOTO_AVAILABLE, callback);

    // Preconfig can't support rawPhotoListener.
    if (photoOutput_ != nullptr && profile_ != nullptr) {
        napi_ref rawCallback;
        napi_create_reference(env, callback, 1, &rawCallback);
        rawCallback_ = rawCallback;
        if (profile_->GetCameraFormat() == CAMERA_FORMAT_YUV_420_SP) {
            CreateMultiChannelPictureLisenter(env);
        }
    }
}

void PhotoOutputNapi::UnregisterPhotoAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoListener_ != nullptr) {
        photoListener_->RemoveCallback(CONST_CAPTURE_PHOTO_AVAILABLE, callback);
    }
    if (rawPhotoListener_ != nullptr) {
        rawPhotoListener_->RemoveCallbackRef(CONST_CAPTURE_PHOTO_AVAILABLE, callback);
    }
}

void PhotoOutputNapi::RegisterDeferredPhotoProxyAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sPhotoSurface_ == nullptr) {
        MEDIA_ERR_LOG("sPhotoSurface_ is null!");
        return;
    }
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new deferred photoListener and register surface consumer listener");
        sptr<PhotoListener> photoListener = new (std::nothrow) PhotoListener(env, sPhotoSurface_, photoOutput_);
        if (photoListener == nullptr) {
            MEDIA_ERR_LOG("failed to new photoListener!");
            return;
        }
        SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        photoListener_ = photoListener;
    }
    photoListener_->SaveCallback(CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, callback);
}

void PhotoOutputNapi::UnregisterDeferredPhotoProxyAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoListener_ != nullptr) {
        photoListener_->RemoveCallback(CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, callback);
    }
}

void PhotoOutputNapi::RegisterPhotoAssetAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sPhotoSurface_ == nullptr) {
        MEDIA_ERR_LOG("sPhotoSurface_ is null!");
        return;
    }
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photoOutput_ is null!");
        return;
    }
    if (photoOutput_->IsYuvOrHeifPhoto()) {
        CreateMultiChannelPictureLisenter(env);
    } else {
        CreateSingleChannelPhotoLisenter(env);
    }
    photoListener_->SaveCallback(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback);
}

void PhotoOutputNapi::UnregisterPhotoAssetAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
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

void PhotoOutputNapi::RegisterCaptureStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_START, callback, isOnce);
}

void PhotoOutputNapi::UnregisterCaptureStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_START, callback);
}

void PhotoOutputNapi::RegisterCaptureStartWithInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_START_WITH_INFO, callback, isOnce);
}

void PhotoOutputNapi::UnregisterCaptureStartWithInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_START_WITH_INFO, callback);
}

void PhotoOutputNapi::RegisterCaptureEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_END, callback, isOnce);
}

void PhotoOutputNapi::UnregisterCaptureEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_END, callback);
}

void PhotoOutputNapi::RegisterFrameShutterCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_FRAME_SHUTTER, callback, isOnce);
}

void PhotoOutputNapi::UnregisterFrameShutterCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_FRAME_SHUTTER, callback);
}

void PhotoOutputNapi::RegisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_ERROR, callback, isOnce);
}

void PhotoOutputNapi::UnregisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_ERROR, callback);
}

void PhotoOutputNapi::RegisterFrameShutterEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_FRAME_SHUTTER_END, callback, isOnce);
}

void PhotoOutputNapi::UnregisterFrameShutterEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_FRAME_SHUTTER_END, callback);
}

void PhotoOutputNapi::RegisterReadyCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_READY, callback, isOnce);
}

void PhotoOutputNapi::UnregisterReadyCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_READY, callback);
}

void PhotoOutputNapi::RegisterEstimatedCaptureDurationCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, callback, isOnce);
}

void PhotoOutputNapi::UnregisterEstimatedCaptureDurationCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, callback);
}

const PhotoOutputNapi::EmitterFunctions& PhotoOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_CAPTURE_QUICK_THUMBNAIL, {
            &PhotoOutputNapi::RegisterQuickThumbnailCallbackListener,
            &PhotoOutputNapi::UnregisterQuickThumbnailCallbackListener } },
        { CONST_CAPTURE_PHOTO_AVAILABLE, {
            &PhotoOutputNapi::RegisterPhotoAvailableCallbackListener,
            &PhotoOutputNapi::UnregisterPhotoAvailableCallbackListener } },
        { CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, {
            &PhotoOutputNapi::RegisterDeferredPhotoProxyAvailableCallbackListener,
            &PhotoOutputNapi::UnregisterDeferredPhotoProxyAvailableCallbackListener } },
        { CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, {
            &PhotoOutputNapi::RegisterPhotoAssetAvailableCallbackListener,
            &PhotoOutputNapi::UnregisterPhotoAssetAvailableCallbackListener } },
        { CONST_CAPTURE_START, {
            &PhotoOutputNapi::RegisterCaptureStartCallbackListener,
            &PhotoOutputNapi::UnregisterCaptureStartCallbackListener } },
        { CONST_CAPTURE_END, {
            &PhotoOutputNapi::RegisterCaptureEndCallbackListener,
            &PhotoOutputNapi::UnregisterCaptureEndCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER, {
            &PhotoOutputNapi::RegisterFrameShutterCallbackListener,
            &PhotoOutputNapi::UnregisterFrameShutterCallbackListener } },
        { CONST_CAPTURE_ERROR, {
            &PhotoOutputNapi::RegisterErrorCallbackListener,
            &PhotoOutputNapi::UnregisterErrorCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER_END, {
            &PhotoOutputNapi::RegisterFrameShutterEndCallbackListener,
            &PhotoOutputNapi::UnregisterFrameShutterEndCallbackListener } },
        { CONST_CAPTURE_READY, {
            &PhotoOutputNapi::RegisterReadyCallbackListener,
            &PhotoOutputNapi::UnregisterReadyCallbackListener } },
        { CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, {
            &PhotoOutputNapi::RegisterEstimatedCaptureDurationCallbackListener,
            &PhotoOutputNapi::UnregisterEstimatedCaptureDurationCallbackListener } },
        { CONST_CAPTURE_START_WITH_INFO, {
            &PhotoOutputNapi::RegisterCaptureStartWithInfoCallbackListener,
            &PhotoOutputNapi::UnregisterCaptureStartWithInfoCallbackListener } } };
    return funMap;
}

napi_value PhotoOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PhotoOutputNapi>::On(env, info);
}

napi_value PhotoOutputNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PhotoOutputNapi>::Once(env, info);
}

napi_value PhotoOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PhotoOutputNapi>::Off(env, info);
}

napi_value PhotoOutputNapi::IsAutoHighQualityPhotoSupported(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoHighQualityPhotoSupported is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t isAutoHighQualityPhotoSupported;
    int32_t retCode = photoOutputNapi->photoOutput_->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    if (retCode == 0 && isAutoHighQualityPhotoSupported != -1) {
        napi_get_boolean(env, true, &result);
        return result;
    }
    MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported is not supported");
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value PhotoOutputNapi::EnableAutoHighQualityPhoto(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoHighQualityPhoto is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableAutoHighQualityPhoto(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto fail %{public}d", retCode);
    }
    return result;
}

napi_value PhotoOutputNapi::IsAutoCloudImageEnhancementSupported(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoCloudImageEnhancementSupported is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    bool isAutoCloudImageEnhanceSupported = false;
    int32_t retCode = photoOutputNapi->photoOutput_->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhanceSupported);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return nullptr;
    }
    if (retCode == 0 && isAutoCloudImageEnhanceSupported != false) {
        napi_get_boolean(env, true, &result);
        return result;
    }
    MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported is not supported");
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value PhotoOutputNapi::EnableAutoCloudImageEnhancement(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoCloudImageEnhancement is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableAutoCloudImageEnhancement(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement fail %{public}d", retCode);
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement success");
    return result;
}

napi_value PhotoOutputNapi::IsDepthDataDeliverySupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsDepthDataDeliverySupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsDepthDataDeliverySupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsDepthDataDeliverySupported parse parameter occur error");
        return nullptr;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsDepthDataDeliverySupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    napi_value result = nullptr;
    int32_t retCode = photoOutputNapi->photoOutput_->IsDepthDataDeliverySupported();
    if (retCode == 0) {
        napi_get_boolean(env, true, &result);
        return result;
    }
    MEDIA_ERR_LOG("PhotoOutputNapi::IsDepthDataDeliverySupported is not supported");
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value PhotoOutputNapi::EnableDepthDataDelivery(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableDepthDataDelivery is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableDepthDataDelivery is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableDepthDataDelivery parse parameter occur error");
        return nullptr;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableDepthDataDelivery get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableDepthDataDelivery(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableDepthDataDelivery fail %{public}d", retCode);
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}
} // namespace CameraStandard
} // namespace OHOS