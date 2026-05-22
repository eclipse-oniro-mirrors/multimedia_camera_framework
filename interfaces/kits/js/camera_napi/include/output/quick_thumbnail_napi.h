/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef QUICK_THUMBNAIL_NAPI_H_
#define QUICK_THUMBNAIL_NAPI_H_

#include "camera_napi_utils.h"
#include "camera_napi_const.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_QUICK_THUMBNAIL_NAPI_CLASS_NAME[] = "QuickThumbnail";

class QuickThumbnailNapi {
public:
    QuickThumbnailNapi();
    ~QuickThumbnailNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateQuickThumbnail(napi_env env, int32_t captureId, napi_value pixelMap);
    static napi_value GetCaptureId(napi_env env, napi_callback_info info);
    static napi_value GetThumbnailImage(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

private:
    static napi_value QuickThumbnailNapiConstructor(napi_env env, napi_callback_info info);
    static void QuickThumbnailNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

private:
    napi_env env_;
    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref sCaptureIdRef_;
    static thread_local napi_ref sPixelMapRef_;
    static thread_local uint32_t quickThumbnailTaskId;

    napi_ref captureId_ = nullptr;
    napi_ref pixelMap_ = nullptr;
};

struct QuickThumbnailAsyncContext : public AsyncContext {
    QuickThumbnailNapi* objectInfo;

    ~QuickThumbnailAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* QUICK_THUMBNAIL_NAPI_H_ */
