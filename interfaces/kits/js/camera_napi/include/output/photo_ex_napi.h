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

#ifndef PHOTO_EX_NAPI_H_
#define PHOTO_EX_NAPI_H_

#include "camera_napi_utils.h"
#include "surface_buffer.h"

namespace OHOS {
namespace CameraStandard {
static const char PHOTO_EX_NAPI_CLASS_NAME[] = "PhotoEx";

class PhotoExNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePhoto(
        napi_env env, napi_value mainImage, sptr<SurfaceBuffer> imageBuffer = nullptr);
    static napi_value CreatePicture(
        napi_env env, napi_value picture, sptr<SurfaceBuffer> pictureBuffer = nullptr);
    PhotoExNapi();
    ~PhotoExNapi();

    static napi_value GetMain(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

private:
    static void PhotoExNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value PhotoExNapiConstructor(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref sMainImageRef_;
    static thread_local napi_ref sPictureRef_;
    static thread_local uint32_t photoTaskId;
    static sptr<SurfaceBuffer> imageBuffer_;
    static bool isCompressed_;

    napi_env env_;
    napi_ref mainImageRef_;
    napi_ref pictureRef_;
};

struct PictureAsyncContext : public AsyncContext {
    PhotoExNapi* objectInfo;

    ~PictureAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* PHOTO_EX_NAPI_H_ */