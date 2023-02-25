/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PHOTO_OUTPUT_NAPI_H_
#define PHOTO_OUTPUT_NAPI_H_

#include <cinttypes>
#include <securec.h>

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "input/camera_manager.h"
#include "input/camera_device.h"
#include "output/camera_output_capability.h"
#include "output/photo_output.h"

#include "hilog/log.h"
#include "camera_napi_utils.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include "image_receiver.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME[] = "PhotoOutput";

struct CallbackInfo {
    int32_t captureID;
    uint64_t timestamp = 0;
    int32_t frameCount = 0;
    int32_t errorCode;
};

class PhotoOutputCallback : public PhotoStateCallback {
public:
    explicit PhotoOutputCallback(napi_env env);
    ~PhotoOutputCallback() = default;

    void OnCaptureStarted(const int32_t captureID) const override;
    void OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const override;
    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override;
    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override;
    void SetCallbackRef(const std::string &eventType, const napi_ref &callbackRef);

private:
    void UpdateJSCallback(std::string propName, const CallbackInfo &info) const;
    void UpdateJSCallbackAsync(std::string propName, const CallbackInfo &info) const;

    napi_env env_;
    napi_ref captureStartCallbackRef_ = nullptr;
    napi_ref captureEndCallbackRef_ = nullptr;
    napi_ref frameShutterCallbackRef_ = nullptr;
    napi_ref errorCallbackRef_ = nullptr;
};

struct PhotoOutputCallbackInfo {
    std::string eventName_;
    CallbackInfo info_;
    const PhotoOutputCallback* listener_;
    PhotoOutputCallbackInfo(std::string eventName, CallbackInfo info, const PhotoOutputCallback* listener)
        : eventName_(eventName), info_(info), listener_(listener) {}
};

class PhotoOutputNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePhotoOutput(napi_env env, Profile &profile, std::string surfaceId);
    static napi_value GetDefaultCaptureSetting(napi_env env, napi_callback_info info);

    static napi_value Capture(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value IsMirrorSupported(napi_env env, napi_callback_info info);
    static napi_value SetMirror(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);

    static bool IsPhotoOutput(napi_env env, napi_value obj);
    PhotoOutputNapi();
    ~PhotoOutputNapi();

    sptr<PhotoOutput> GetPhotoOutput();

private:
    static void PhotoOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value PhotoOutputNapiConstructor(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<PhotoOutput> sPhotoOutput_;

    napi_env env_;
    napi_ref wrapper_;
    sptr<PhotoOutput> photoOutput_;
    std::shared_ptr<PhotoOutputCallback> photoCallback_ = nullptr;
    static thread_local uint32_t photoOutputTaskId;
};

struct PhotoOutputAsyncContext : public AsyncContext {
    int32_t quality = -1;
    int32_t rotation = -1;
    double latitude = -1.0;
    double longitude = -1.0;
    bool isMirror = false;
    bool hasPhotoSettings = false;
    bool bRetBool;
    bool isSupported = false;
    std::unique_ptr<Location> location;
    PhotoOutputNapi* objectInfo;
    std::string surfaceId;
    ~PhotoOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* PHOTO_OUTPUT_NAPI_H_ */
