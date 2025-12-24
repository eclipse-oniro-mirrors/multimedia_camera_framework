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

#ifndef VIDEO_CAPABILITY_NAPI_H_
#define VIDEO_CAPABILITY_NAPI_H_

#include "js_native_api.h"
#include "output/video_capability.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_VIDEO_CAPABILITY_NAPI_CLASS_NAME[] = "VideoCapability";

class VideoCapabilityNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateVideoCapability(napi_env env, sptr<VideoCapability>& videoCapability);
    static napi_value IsBFrameSupported(napi_env env, napi_callback_info info);
    VideoCapabilityNapi();
    ~VideoCapabilityNapi();

private:
    static void VideoCapabilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value VideoCapabilityNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    sptr<VideoCapability> videoCapability_;
    
    static thread_local napi_ref sConstructor_;
    static thread_local sptr<VideoCapability> sVideoCapability_;
    static thread_local uint32_t videoCapabilityTaskId;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* VIDEO_CAPABILITY_NAPI_H_ */
