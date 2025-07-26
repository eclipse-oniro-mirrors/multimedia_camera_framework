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
#include "image_napi.h"
#include "image_receiver.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "listener_base.h"
#include "media_library_comm_napi.h"
#include "output/photo_napi.h"
#include "photo_output.h"
#include "pixel_map_napi.h"
#include "refbase.h"
#include "native_common_napi.h"
#include "camera_dynamic_loader.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
namespace {

void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto photoOutputAsyncContext = static_cast<PhotoOutputAsyncContext*>(data);
    CHECK_RETURN_ELOG(photoOutputAsyncContext == nullptr,
        "CameraInputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("CameraInputNapi AsyncCompleteCallback %{public}s, status = %{public}d",
        photoOutputAsyncContext->funcName.c_str(), photoOutputAsyncContext->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = photoOutputAsyncContext->status;
 
    if (!photoOutputAsyncContext->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, photoOutputAsyncContext->errorCode,
            photoOutputAsyncContext->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }
    if (!photoOutputAsyncContext->funcName.empty() && photoOutputAsyncContext->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(photoOutputAsyncContext->funcName, photoOutputAsyncContext->taskId);
        jsContext->funcName = photoOutputAsyncContext->funcName;
    }
    CHECK_EXECUTE(photoOutputAsyncContext->work != nullptr,
        CameraNapiUtils::InvokeJSAsyncMethod(env, photoOutputAsyncContext->deferred,
            photoOutputAsyncContext->callbackRef, photoOutputAsyncContext->work, *jsContext));
    photoOutputAsyncContext->FreeHeldNapiValue(env);
    delete photoOutputAsyncContext;
}

void ProcessCapture(PhotoOutputAsyncContext* context, bool isBurst)
{
    context->status = true;
    sptr<PhotoOutput> photoOutput = context->objectInfo->GetPhotoOutput();
    MEDIA_INFO_LOG("PhotoOutputAsyncContext objectInfo GetEnableMirror is %{public}d",
        context->objectInfo->GetEnableMirror());
    if (context->hasPhotoSettings) {
        std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();
        CHECK_EXECUTE(context->quality != -1,
            capSettings->SetQuality(static_cast<PhotoCaptureSetting::QualityLevel>(context->quality)));
        CHECK_EXECUTE(context->rotation != -1,
            capSettings->SetRotation(static_cast<PhotoCaptureSetting::RotationConfig>(context->rotation)));
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
thread_local uint32_t PhotoOutputNapi::photoOutputTaskId = CAMERA_PHOTO_OUTPUT_TASKID;
thread_local napi_ref PhotoOutputNapi::rawCallback_ = nullptr;
static uv_sem_t g_captureStartSem;
static bool g_isSemInited;
static std::mutex g_photoImageMutex;
static std::mutex g_assembleImageMutex;
static int32_t g_captureId;

void FillNapiObjectWithCaptureId(napi_env env, int32_t captureId, napi_value &photoAsset)
{
    napi_value propertyName;
    napi_value propertyValue;
    napi_create_string_utf8(env, "captureId", NAPI_AUTO_LENGTH, &propertyName);
    napi_create_int32(env, captureId, &propertyValue);
    napi_set_property(env, photoAsset, propertyName, propertyValue);
    MEDIA_INFO_LOG("FillNapiObjectWithCaptureId captureId %{public}d", captureId);
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
    CHECK_RETURN_ELOG(!photoOutput, "CleanAfterTransPicture photoOutput is nullptr");
    photoOutput->photoProxyMap_[captureId] = nullptr;
    photoOutput->photoProxyMap_.erase(captureId);
    photoOutput->captureIdPictureMap_.erase(captureId);
    photoOutput->captureIdGainmapMap_.erase(captureId);
    photoOutput->captureIdDepthMap_.Erase(captureId);
    photoOutput->captureIdExifMap_.erase(captureId);
    photoOutput->captureIdDebugMap_.erase(captureId);
    photoOutput->captureIdAuxiliaryCountMap_.erase(captureId);
    photoOutput->captureIdCountMap_.erase(captureId);
    photoOutput->captureIdHandleMap_.erase(captureId);
}

void FillPixelMapWithCaptureIdAndTimestamp(napi_env env, int32_t captureId, int64_t timestamp, napi_value pixelMapNapi)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, pixelMapNapi, &valueType) != napi_ok || valueType == napi_undefined) {
        MEDIA_ERR_LOG("FillPixelMapWithCaptureIdAndTimestamp err, pixelMapNapi is undefined = %{public}d",
            valueType == napi_undefined);
        return;
    }
    napi_value propertyName;
    napi_value propertyValue;
    napi_get_undefined(env, &propertyName);
    napi_get_undefined(env, &propertyValue);
    napi_create_string_utf8(env, "captureId", NAPI_AUTO_LENGTH, &propertyName);
    napi_create_int32(env, captureId, &propertyValue);
    napi_set_property(env, pixelMapNapi, propertyName, propertyValue);
    MEDIA_INFO_LOG("FillPixelMapWithCaptureIdAndTimestamp captureId %{public}d", captureId);

    napi_create_string_utf8(env, "timestamp", NAPI_AUTO_LENGTH, &propertyName);
    napi_create_int64(env, timestamp, &propertyValue);
    napi_set_property(env, pixelMapNapi, propertyName, propertyValue);
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
        CHECK_EXECUTE(callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_FRAME_SHUTTER &&
            g_captureId != callbackInfo->info_.captureID, uv_sem_wait(&g_captureStartSem));
    }
}

void PhotoOutputCallback::UpdateJSCallbackAsync(PhotoOutputEventType eventType, const CallbackInfo &info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
    if (!g_isSemInited) {
        uv_sem_init(&g_captureStartSem, 0);
        g_isSemInited = true;
    }
    std::unique_ptr<PhotoOutputCallbackInfo> callbackInfo =
        std::make_unique<PhotoOutputCallbackInfo>(eventType, info, shared_from_this());
    PhotoOutputCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        PhotoOutputCallbackInfo* callbackInfo = reinterpret_cast<PhotoOutputCallbackInfo *>(event);
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
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
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
    MEDIA_INFO_LOG("OnCaptureEnded is called!, captureID: %{public}d, frameCount: %{public}d",
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
    MEDIA_INFO_LOG(
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

void PhotoOutputCallback::OnOfflineDeliveryFinished(const int32_t captureId) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnOfflineDeliveryFinished is called, captureID: %{public}d", captureId);
    CallbackInfo info;
    info.captureID = captureId;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_OFFLINE_DELIVERY_FINISHED, info);
}

void PhotoOutputCallback::OnPhotoAvailable(const std::shared_ptr<Media::NativeImage> nativeImage, bool isRaw) const
{
    MEDIA_DEBUG_LOG("PhotoOutputCallback::OnPhotoAvailable is called!");
    CallbackInfo info;
    info.nativeImage = nativeImage;
    info.isRaw = isRaw;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_PHOTO_AVAILABLE, info);
}

void PhotoOutputCallback::OnPhotoAssetAvailable(
    const int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey) const
{
    MEDIA_DEBUG_LOG("PhotoOutputCallback::OnPhotoAssetAvailable is called!");
    CallbackInfo info;
    info.captureID = captureId;
    info.uri = uri;
    info.cameraShotType = cameraShotType;
    info.burstKey = burstKey;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_PHOTO_ASSET_AVAILABLE, info);
}

void PhotoOutputCallback::OnThumbnailAvailable(
    const int32_t captureId, const int64_t timestamp, unique_ptr<Media::PixelMap> pixelMap) const
{
    MEDIA_DEBUG_LOG("PhotoOutputCallback::OnThumbnailAvailable is called!");
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    info.pixelMap = std::move(pixelMap);
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_THUMBNAIL_AVAILABLE, info);
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

void PhotoOutputCallback::ExecuteOfflineDeliveryFinishedCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_ONE] = { nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, callbackNapiPara);
}

void PhotoOutputCallback::ExecutePhotoAvailableCb(const CallbackInfo& info) const
{
    MEDIA_INFO_LOG("ExecutePhotoAvailableCb");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;
    napi_value mainImage = nullptr;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    mainImage = Media::ImageNapi::Create(env_, info.nativeImage);
    if (mainImage == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &mainImage);
    }
    sptr<SurfaceBuffer> imageBuffer;
    if (info.nativeImage) {
        // bind imageBuffer life cycle with photoNapiObj
        imageBuffer = info.nativeImage->GetBuffer();
    }
    result[PARAM1] = PhotoNapi::CreatePhoto(env_, mainImage, info.isRaw, imageBuffer);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_PHOTO_AVAILABLE, callbackNapiPara);
}

void PhotoOutputCallback::ExecutePhotoAssetAvailableCb(const CallbackInfo& info) const
{
    MEDIA_INFO_LOG("ExecutePhotoAssetAvailableCb");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;
    napi_value photoAsset = nullptr;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    photoAsset = Media::MediaLibraryCommNapi::CreatePhotoAssetNapi(env_, info.uri, info.cameraShotType, info.burstKey);
    if (photoAsset == nullptr) {
        napi_get_undefined(env_, &photoAsset);
    }
    FillNapiObjectWithCaptureId(env_, info.captureID, photoAsset);
    result[PARAM1] = photoAsset;
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callbackNapiPara);
}

void PhotoOutputCallback::ExecuteThumbnailAvailableCb(const CallbackInfo& info) const
{
    MEDIA_INFO_LOG("ExecuteThumbnailAvailableCb E");
    napi_value result[ARGS_TWO] = { 0 };
    napi_get_undefined(env_, &result[0]);
    napi_get_undefined(env_, &result[1]);
    napi_value retVal;
    MEDIA_INFO_LOG("enter ImageNapi::Create start");
    napi_value valueParam = Media::PixelMapNapi::CreatePixelMap(env_, info.pixelMap);
    if (valueParam == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &valueParam);
    }
    FillPixelMapWithCaptureIdAndTimestamp(env_, info.captureID, info.timestamp, valueParam);
    MEDIA_INFO_LOG("enter ImageNapi::Create end");
    result[1] = valueParam;
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_CAPTURE_QUICK_THUMBNAIL, callbackNapiPara);
    MEDIA_INFO_LOG("ExecuteThumbnailAvailableCb X");
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
        case PhotoOutputEventType::CAPTURE_OFFLINE_DELIVERY_FINISHED:
            ExecuteOfflineDeliveryFinishedCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_PHOTO_AVAILABLE:
            ExecutePhotoAvailableCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_PHOTO_ASSET_AVAILABLE:
            ExecutePhotoAssetAvailableCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_THUMBNAIL_AVAILABLE:
            ExecuteThumbnailAvailableCb(info);
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
    }
}

PhotoOutputNapi::PhotoOutputNapi() {}

PhotoOutputNapi::~PhotoOutputNapi()
{
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
        DECLARE_NAPI_FUNCTION_WRITABLE("capture", Capture),
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
        DECLARE_NAPI_FUNCTION("enableDepthDataDelivery", EnableDepthDataDelivery),
        DECLARE_NAPI_FUNCTION("isAutoAigcPhotoSupported", IsAutoAigcPhotoSupported),
        DECLARE_NAPI_FUNCTION("enableAutoAigcPhoto", EnableAutoAigcPhoto),
        DECLARE_NAPI_FUNCTION("isOfflineSupported", IsOfflineSupported),
        DECLARE_NAPI_FUNCTION("enableOffline", EnableOfflinePhoto)
    };

    status = napi_define_class(env, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, PhotoOutputNapiConstructor,
        nullptr, sizeof(photo_output_props) / sizeof(photo_output_props[PARAM0]), photo_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            CHECK_RETURN_RET(status == napi_ok, exports);
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
            MEDIA_DEBUG_LOG("PhotoOutputNapi::IsPhotoOutput is failed");
            result = false;
        }
    }
    return result;
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
        int retCode = SUCCESS;
        if (surfaceId == "") {
            MEDIA_INFO_LOG("create surface as consumer");
            retCode = CameraManager::GetInstance()->CreatePhotoOutput(profile, &sPhotoOutput_);
        } else {
            MEDIA_INFO_LOG("get surface by surfaceId");
            sptr<Surface> photoSurface;
            photoSurface = Media::ImageReceiver::getSurfaceById(surfaceId);
            CHECK_RETURN_RET_ELOG(photoSurface == nullptr, result, "failed to get photoSurface");
            photoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
            sptr<IBufferProducer> producer = photoSurface->GetProducer();
            CHECK_RETURN_RET_ELOG(producer == nullptr, result, "failed to create GetProducer");
            MEDIA_INFO_LOG("profile width: %{public}d, height: %{public}d, format = %{public}d, "
                           "surface width: %{public}d, height: %{public}d",
                profile.GetSize().width,
                profile.GetSize().height,
                static_cast<int32_t>(profile.GetCameraFormat()),
                photoSurface->GetDefaultWidth(),
                photoSurface->GetDefaultHeight());
            retCode =
                CameraManager::GetInstance()->CreatePhotoOutput(profile, producer, &sPhotoOutput_, photoSurface);
        }
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode) || sPhotoOutput_ == nullptr,
            result, "failed to create CreatePhotoOutput");
        CHECK_EXECUTE(surfaceId == "", sPhotoOutput_->SetNativeSurface(true));
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
        int retCode = SUCCESS;
        if (surfaceId == "") {
            MEDIA_INFO_LOG("create surface as consumer");
            retCode = CameraManager::GetInstance()->CreatePhotoOutputWithoutProfile(surfaceId, &sPhotoOutput_);
        } else {
            MEDIA_INFO_LOG("get surface by surfaceId");
            sptr<Surface> photoSurface = Media::ImageReceiver::getSurfaceById(surfaceId);
            CHECK_RETURN_RET_ELOG(photoSurface == nullptr, result, "failed to get photoSurface");
            sptr<IBufferProducer> producer = photoSurface->GetProducer();
            CHECK_RETURN_RET_ELOG(producer == nullptr, result, "failed to create GetProducer");
            MEDIA_INFO_LOG("surface width: %{public}d, height: %{public}d",
                           photoSurface->GetDefaultWidth(), photoSurface->GetDefaultHeight());
            retCode = CameraManager::GetInstance()->CreatePhotoOutputWithoutProfile(
                producer, &sPhotoOutput_, photoSurface);
        }
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode) || sPhotoOutput_ == nullptr,
            result, "failed to create CreatePhotoOutput");
        CHECK_EXECUTE(surfaceId == "", sPhotoOutput_->SetNativeSurface(true));
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPhotoOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("Success to create photo output instance");
            return result;
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
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), false,
        "ParseCaptureSettings invalid argument");
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    return true;
}

napi_value PhotoOutputNapi::Capture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Capture is called");
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>(
        "PhotoOutputNapi::Capture", CameraNapiUtils::IncrementAndGet(photoOutputTaskId));
    std::shared_ptr<CameraNapiAsyncFunction> asyncFunction;
    CHECK_RETURN_RET_ELOG(!ParseCaptureSettings(env, info, asyncContext.get(), asyncFunction, true), nullptr,
        "PhotoOutputNapi::Capture parse parameters fail.");
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PhotoOutputNapi::Capture running on worker");
            auto context = static_cast<PhotoOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->objectInfo == nullptr, "PhotoOutputNapi::Capture async info is nullptr");
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
    CHECK_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PhotoOutputNapi::BurstCapture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("BurstCapture is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi EnableAutoHighQualityPhoto is called!");
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>(
        "PhotoOutputNapi::BurstCapture", CameraNapiUtils::IncrementAndGet(photoOutputTaskId));
    std::shared_ptr<CameraNapiAsyncFunction> asyncFunction;
    CHECK_RETURN_RET_ELOG(!ParseCaptureSettings(env, info, asyncContext.get(), asyncFunction, false),
        nullptr, "PhotoOutputNapi::BurstCapture parse parameters fail.");
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PhotoOutputNapi::BurstCapture running on worker");
            auto context = static_cast<PhotoOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
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
    CHECK_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value PhotoOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>(
        "PhotoOutputNapi::Release", CameraNapiUtils::IncrementAndGet(photoOutputTaskId));
    auto asyncFunc =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunc);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "PhotoOutputNapi::Release invalid argument");
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunc->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PhotoOutputNapi::Release running on worker");
            auto context = static_cast<PhotoOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->objectInfo == nullptr, "PhotoOutputNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->photoOutput_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Release");
        asyncFunc->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    CHECK_RETURN_RET(asyncFunc->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunc->GetPromise());
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
        int32_t retCode = photoOutputNapi->photoOutput_->EnableMirror(isMirror);
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

    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsQuickThumbnailSupported get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t retCode = photoOutputNapi->photoOutput_->IsQuickThumbnailSupported();
        bool isSupported = (retCode == 0);
        CHECK_RETURN_RET(retCode > 0 && !CameraNapiUtils::CheckError(env, retCode), result);
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::DeferImageDeliveryFor(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi DeferImageDeliveryFor is called!");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    MEDIA_DEBUG_LOG("PhotoOutputNapi::DeferImageDeliveryFor get js args");
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
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsDeferredImageDeliverySupported is called!");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsDeferredImageDeliverySupported get js args");
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
        CHECK_RETURN_RET(retCode > 0 && !CameraNapiUtils::CheckError(env, retCode), result);
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::IsDeferredImageDeliveryEnabled(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsDeferredImageDeliveryEnabled is called!");
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
        CHECK_RETURN_RET(retCode > 0 && !CameraNapiUtils::CheckError(env, retCode), result);
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
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsMovingPhotoSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || photoOutputNapi == nullptr, result,
        "PhotoOutputNapi::IsMovingPhotoSupported photoOutputNapi is null!");
    auto session = photoOutputNapi->GetPhotoOutput()->GetSession();
    if (session != nullptr) {
        bool isSupported = session->IsMovingPhotoSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        napi_get_boolean(env, false, &result);
        MEDIA_ERR_LOG("PhotoOutputNapi::IsMovingPhotoSupported call Failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::EnableMovingPhoto(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapi::enableMovingPhoto is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    CHECK_RETURN_RET(valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || photoOutputNapi == nullptr, result,
        "PhotoOutputNapi::EnableMovingPhoto photoOutputNapi is null!");
    auto session = photoOutputNapi->GetPhotoOutput()->GetSession();
    if (session != nullptr) {
        bool isEnableMovingPhoto;
        napi_get_value_bool(env, argv[PARAM0], &isEnableMovingPhoto);
        if (photoOutputNapi->GetPhotoOutput()) {
            photoOutputNapi->GetPhotoOutput()->EnableMovingPhoto(isEnableMovingPhoto);
        }
        session->LockForControl();
        int32_t retCode = session->EnableMovingPhoto(isEnableMovingPhoto);
        session->UnlockForControl();
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

enum VideoCodecType : int32_t {
    VIDEO_ENCODE_TYPE_AVC = 0,
    VIDEO_ENCODE_TYPE_HEVC,
};

napi_value PhotoOutputNapi::GetSupportedMovingPhotoVideoCodecTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapi::GetSupportedMovingPhotoVideoCodecTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || photoOutputNapi == nullptr, result,
        "PhotoOutputNapi::GetSupportedMovingPhotoVideoCodecTypes photoOutputNapi is null!");
    vector<int32_t> videoCodecTypes = {VideoCodecType::VIDEO_ENCODE_TYPE_AVC, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC};
    result = CameraNapiUtils::CreateJSArray(env, status, videoCodecTypes);
    if (status != napi_ok) {
        result = CameraNapiUtils::CreateJSArray(env, status, {});
    }
    return result;
}

napi_value PhotoOutputNapi::SetMovingPhotoVideoCodecType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapi::SetMovingPhotoVideoCodecType is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    CHECK_RETURN_RET(valueType != napi_number && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || photoOutputNapi == nullptr, result,
        "PhotoOutputNapi::SetMovingPhotoVideoCodecType photoOutputNapi is null!");
    if (photoOutputNapi->GetPhotoOutput() != nullptr) {
        int32_t codecType;
        napi_get_value_int32(env, argv[PARAM0], &codecType);
        int32_t retCode = photoOutputNapi->GetPhotoOutput()->SetMovingPhotoVideoCodecType(codecType);
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value PhotoOutputNapi::EnableQuickThumbnail(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi PhotoOutputNapi::EnableQuickThumbnail is called!");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    CHECK_RETURN_RET(valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    bool thumbnailSwitch;
    if (status == napi_ok && photoOutputNapi != nullptr) {
        napi_get_value_bool(env, argv[PARAM0], &thumbnailSwitch);
        photoOutputNapi->isQuickThumbnailEnabled_ = thumbnailSwitch;
        int32_t retCode = photoOutputNapi->photoOutput_->SetThumbnail(thumbnailSwitch);
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value PhotoOutputNapi::IsRawDeliverySupported(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsRawDeliverySupported is called!");
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    }
    napi_get_boolean(env, isSupported, &result);
    return result;
}

napi_value PhotoOutputNapi::EnableRawDelivery(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi PhotoOutputNapi::EnableRawDelivery is called!");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    CHECK_RETURN_RET(valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    bool rawDeliverySwitch;
    if (status == napi_ok && photoOutputNapi != nullptr) {
        napi_get_value_bool(env, argv[PARAM0], &rawDeliverySwitch);
        int32_t retCode = photoOutputNapi->photoOutput_->EnableRawDelivery(rawDeliverySwitch);
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value PhotoOutputNapi::GetActiveProfile(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapi::GetActiveProfile is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        nullptr, "PhotoOutputNapi::GetActiveProfile parse parameter occur error");
    auto profile = photoOutputNapi->photoOutput_->GetPhotoProfile();
    CHECK_RETURN_RET(profile == nullptr, CameraNapiUtils::GetUndefinedValue(env));
    return CameraNapiObjProfile(*profile).GenerateNapiValue(env);
}

void PhotoOutputNapi::RegisterQuickThumbnailCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi!");
    MEDIA_INFO_LOG("PhotoOutputNapi RegisterQuickThumbnailCallbackListener!");
    if (!isQuickThumbnailEnabled_) {
        MEDIA_ERR_LOG("quickThumbnail is not enabled!");
        napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
        return;
    }
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutput_->SetThumbnailCallback(photoOutputCallback_);
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_QUICK_THUMBNAIL, callback, isOnce);
}

void PhotoOutputNapi::UnregisterQuickThumbnailCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi!");
    if (!isQuickThumbnailEnabled_) {
        MEDIA_ERR_LOG("quickThumbnail is not enabled!");
        napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
        return;
    }

    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null!");
    photoOutput_->UnSetThumbnailAvailableCallback();
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_QUICK_THUMBNAIL, callback);
}

void PhotoOutputNapi::RegisterPhotoAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoOutputNapi RegisterPhotoAvailableCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutput_->SetPhotoAvailableCallback(photoOutputCallback_);
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_PHOTO_AVAILABLE, callback, isOnce);
    callbackFlag_ |= CAPTURE_PHOTO;
    photoOutput_->SetCallbackFlag(callbackFlag_);
}

void PhotoOutputNapi::UnregisterPhotoAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null!");
    photoOutput_->UnSetPhotoAvailableCallback();
    callbackFlag_ &= ~CAPTURE_PHOTO;
    photoOutput_->SetCallbackFlag(callbackFlag_);
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_PHOTO_AVAILABLE, callback);
}

void PhotoOutputNapi::RegisterDeferredPhotoProxyAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoOutputNapi RegisterDeferredPhotoProxyAvailableCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
}

void PhotoOutputNapi::UnregisterDeferredPhotoProxyAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("PhotoOutputNapi UnregisterDeferredPhotoProxyAvailableCallbackListener!");
}

void PhotoOutputNapi::RegisterPhotoAssetAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoOutputNapi RegisterPhotoAssetAvailableCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutput_->SetPhotoAssetAvailableCallback(photoOutputCallback_);
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback, isOnce);
    callbackFlag_ |= CAPTURE_PHOTO_ASSET;
    photoOutput_->SetCallbackFlag(callbackFlag_);
}

void PhotoOutputNapi::UnregisterPhotoAssetAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null!");
    photoOutput_->UnSetPhotoAssetAvailableCallback();
    callbackFlag_ &= ~CAPTURE_PHOTO_ASSET;
    photoOutput_->SetCallbackFlag(callbackFlag_);
    photoOutput_->DeferImageDeliveryFor(DeferredDeliveryImageType::DELIVERY_NONE);
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback);
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
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
            &PhotoOutputNapi::UnregisterCaptureStartWithInfoCallbackListener } },
        { CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, {
            &PhotoOutputNapi::RegisterOfflineDeliveryFinishedCallbackListener,
            &PhotoOutputNapi::UnregisterOfflineDeliveryFinishedCallbackListener } } };
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
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), result,
        "SystemApi IsAutoHighQualityPhotoSupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        result, "PhotoOutputNapi::IsAutoHighQualityPhotoSupported parse parameter occur error");
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
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), result,
        "SystemApi EnableAutoHighQualityPhoto is called!");
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        result, "PhotoOutputNapi::EnableAutoHighQualityPhoto parse parameter occur error");
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableAutoHighQualityPhoto(isEnable);
    CHECK_PRINT_ELOG(!CameraNapiUtils::CheckError(env, retCode),
        "PhotoOutputNapi::EnableAutoHighQualityPhoto fail %{public}d", retCode);
    return result;
}

napi_value PhotoOutputNapi::IsAutoCloudImageEnhancementSupported(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), result,
        "SystemApi IsAutoCloudImageEnhancementSupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        result, "PhotoOutputNapi::IsAutoCloudImageEnhancementSupported parse parameter occur error");
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    bool isAutoCloudImageEnhancementSupported = false;
    int32_t retCode =
        photoOutputNapi->photoOutput_->IsAutoCloudImageEnhancementSupported(
            isAutoCloudImageEnhancementSupported);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    napi_get_boolean(env, isAutoCloudImageEnhancementSupported, &result);
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsAutoCloudImageEnhancementSupported is %{public}d",
        isAutoCloudImageEnhancementSupported);
    return result;
}

napi_value PhotoOutputNapi::EnableAutoCloudImageEnhancement(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), result,
        "SystemApi EnableAutoCloudImageEnhancement is called!");
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        result, "PhotoOutputNapi::EnableAutoCloudImageEnhancement parse parameter occur error");
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableAutoCloudImageEnhancement(isEnable);
    CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), result,
        "PhotoOutputNapi::EnableAutoCloudImageEnhancement fail %{public}d", retCode);
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoCloudImageEnhancement success");
    return result;
}

napi_value PhotoOutputNapi::IsDepthDataDeliverySupported(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsDepthDataDeliverySupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsDepthDataDeliverySupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        nullptr, "PhotoOutputNapi::IsDepthDataDeliverySupported parse parameter occur error");
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
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi EnableDepthDataDelivery is called!");
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableDepthDataDelivery is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "PhotoOutputNapi::EnableDepthDataDelivery parse parameter occur error");
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableDepthDataDelivery get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableDepthDataDelivery(isEnable);
    CHECK_PRINT_ELOG(!CameraNapiUtils::CheckError(env, retCode),
        "PhotoOutputNapi::EnableDepthDataDelivery fail %{public}d", retCode);
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PhotoOutputNapi::IsAutoAigcPhotoSupported(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoAigcPhotoSupported is called!");
        return result;
    }
    MEDIA_INFO_LOG("PhotoOutputNapi::IsAutoAigcPhotoSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoAigcPhotoSupported parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoAigcPhotoSupported get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return result;
    }
    bool isAutoAigcPhotoSupported = false;
    int32_t retCode =
        photoOutputNapi->photoOutput_->IsAutoAigcPhotoSupported(
            isAutoAigcPhotoSupported);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return nullptr;
    }
    napi_get_boolean(env, isAutoAigcPhotoSupported, &result);
    MEDIA_INFO_LOG("PhotoOutputNapi::IsAutoAigcPhotoSupported is %{public}d",
        isAutoAigcPhotoSupported);
    return result;
}

napi_value PhotoOutputNapi::EnableAutoAigcPhoto(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoAigcPhoto is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoAigcPhoto is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoAigcPhoto parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoAigcPhoto get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return result;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableAutoAigcPhoto(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoAigcPhoto fail %{public}d", retCode);
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoAigcPhoto success");
    return result;
}

void PhotoOutputNapi::RegisterOfflineDeliveryFinishedCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env),
        "PhotoOutputNapi::RegisterOfflineDeliveryFinishedCallbackListener:SystemApi is called");
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, callback, isOnce);
}

void PhotoOutputNapi::UnregisterOfflineDeliveryFinishedCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env),
        "PhotoOutputNapi::UnregisterOfflineDeliveryFinishedCallbackListener:SystemApi is called");
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, callback);
}

napi_value PhotoOutputNapi::IsOfflineSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsOfflineSupported is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("PhotoOutputNapi::IsOfflineSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsOfflineSupported parse parameter occur error");
        return nullptr;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsOfflineSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    napi_value result = nullptr;
    bool isSupported = photoOutputNapi->photoOutput_->IsOfflineSupported();
    napi_get_boolean(env, isSupported, &result);
    MEDIA_ERR_LOG("PhotoOutputNapi::IsOfflineSupported is support %{public}d", isSupported);
    return result;
}

napi_value PhotoOutputNapi::EnableOfflinePhoto(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsOfflineSupported is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("EnableOfflinePhoto is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status != napi_ok || photoOutputNapi == nullptr) {
        MEDIA_ERR_LOG("EnableOfflinePhoto photoOutputNapi is null!");
        return result;
    }
    auto session = photoOutputNapi->GetPhotoOutput()->GetSession();
    if (session != nullptr && photoOutputNapi->GetPhotoOutput()) {
        photoOutputNapi->GetPhotoOutput()->EnableOfflinePhoto();
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS