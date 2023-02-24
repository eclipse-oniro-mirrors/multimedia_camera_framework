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

#ifndef VIDEO_OUTPUT_NAPI_H_
#define VIDEO_OUTPUT_NAPI_H_
#include <securec.h>

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "output/video_output.h"
#include "hilog/log.h"
#include "camera_napi_utils.h"
#include "input/camera_manager.h"

#include <cinttypes>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include "surface_utils.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_VIDEO_OUTPUT_NAPI_CLASS_NAME[] = "VideoOutput";

class VideoCallbackListener : public VideoStateCallback  {
public:
    explicit VideoCallbackListener(napi_env env);
    ~VideoCallbackListener() = default;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void SetCallbackRef(const std::string &eventType, const napi_ref &callbackRef);

private:
    void UpdateJSCallback(std::string propName, const int32_t value) const;
    void UpdateJSCallbackAsync(std::string propName, const int32_t value) const;

    napi_env env_;
    napi_ref frameStartCallbackRef_ = nullptr;
    napi_ref frameEndCallbackRef_ = nullptr;
    napi_ref errorCallbackRef_ = nullptr;
};

struct VideoOutputCallbackInfo {
    std::string eventName_;
    int32_t value_;
    const VideoCallbackListener* listener_;
    VideoOutputCallbackInfo(std::string eventName, int32_t value, const VideoCallbackListener* listener)
        : eventName_(eventName), value_(value), listener_(listener) {}
};

class VideoOutputNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateVideoOutput(napi_env env, VideoProfile &profile, std::string surfaceId);
    static bool IsVideoOutput(napi_env env, napi_value obj);
    VideoOutputNapi();
    ~VideoOutputNapi();
    sptr<VideoOutput> GetVideoOutput();

private:
    static void VideoOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value VideoOutputNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value GetFrameRateRange(napi_env env, napi_callback_info info);
    static napi_value SetFrameRateRange(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<VideoOutput> sVideoOutput_;

    napi_env env_;
    napi_ref wrapper_;
    sptr<VideoOutput> videoOutput_;
    std::shared_ptr<VideoCallbackListener> videoCallback_;
    static thread_local uint32_t videoOutputTaskId;
};

struct VideoOutputAsyncContext : public AsyncContext {
    VideoOutputNapi* objectInfo;
    std::string errorMsg;
    bool bRetBool;
    std::vector<int32_t> vecFrameRateRangeList;
    int32_t minFrameRate;
    int32_t maxFrameRate;
    ~VideoOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* VIDEO_OUTPUT_NAPI_H_ */
