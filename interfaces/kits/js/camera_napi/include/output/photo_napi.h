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

#ifndef PHOTO_NAPI_H_
#define PHOTO_NAPI_H_

#include "camera_napi_utils.h"

namespace OHOS {
namespace CameraStandard {
static const char PHOTO_NAPI_CLASS_NAME[] = "Photo";

class PhotoNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePhoto(napi_env env, napi_value mainImage);
    static napi_value CreateRawPhoto(napi_env env, napi_value mainImage);
    PhotoNapi();
    ~PhotoNapi();

    static napi_value GetMain(napi_env env, napi_callback_info info);
    static napi_value GetRaw(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

private:
    static void PhotoNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value PhotoNapiConstructor(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;
    static thread_local napi_value sMainImage_;
    static thread_local napi_value sRawImage_;
    static thread_local uint32_t photoTaskId;

    napi_env env_;
    napi_ref wrapper_;
    napi_value mainImage_;
    napi_value rawImage_;
};

struct PhotoAsyncContext : public AsyncContext {
    PhotoNapi* objectInfo;

    ~PhotoAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* PHOTO_NAPI_H_ */