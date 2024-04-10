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

#ifndef DEFERRED_PHOTO_PROXY_NAPI_H_
#define DEFERRED_PHOTO_PROXY_NAPI_H_

#include "camera_napi_utils.h"
#include "deferred_photo_proxy.h"

namespace OHOS {
namespace CameraStandard {
static const char DEFERRED_PHOTO_NAPI_CLASS_NAME[] = "DeferredPhotoProxy";

class DeferredPhotoProxyNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateDeferredPhotoProxy(napi_env env, sptr<DeferredPhotoProxy> deferredPhotoProxy);
    DeferredPhotoProxyNapi();
    ~DeferredPhotoProxyNapi();

    static napi_value GetThumbnail(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

    sptr<DeferredPhotoProxy> deferredPhotoProxy_;

private:
    static void DeferredPhotoProxyNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value DeferredPhotoProxyNapiConstructor(napi_env env, napi_callback_info info);
    static void DeferredPhotoAsyncTaskComplete(napi_env env, napi_status status, void* data);

    static thread_local napi_ref sConstructor_;
    static thread_local napi_value sThumbnailPixelMap_;
    static thread_local sptr<DeferredPhotoProxy> sDeferredPhotoProxy_;
    static thread_local uint32_t deferredPhotoProxyTaskId;

    napi_env env_;
    napi_ref wrapper_;
    napi_value thumbnailPixelMap_;
};

struct DeferredPhotoProxAsyncContext : public AsyncContext {
    DeferredPhotoProxyNapi* objectInfo;

    ~DeferredPhotoProxAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* DEFERRED_PHOTO_PROXY_NAPI_H_ */