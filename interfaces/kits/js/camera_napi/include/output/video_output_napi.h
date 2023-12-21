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

#include "output/video_output.h"
#include "hilog/log.h"
#include "camera_napi_utils.h"
#include "input/camera_manager.h"
#include "surface_utils.h"

#include "listener_base.h"
namespace OHOS {
namespace CameraStandard {
static const char CAMERA_VIDEO_OUTPUT_NAPI_CLASS_NAME[] = "VideoOutput";

enum VideoOutputEventType {
    VIDEO_FRAME_START,
    VIDEO_FRAME_END,
    VIDEO_FRAME_ERROR,
    VIDEO_INVALID_TYPE
};

static EnumHelper<VideoOutputEventType> VideoOutputEventTypeHelper({
        {VIDEO_FRAME_START, "frameStart"},
        {VIDEO_FRAME_END, "frameEnd"},
        {VIDEO_FRAME_ERROR, "error"},
    },
    VideoOutputEventType::VIDEO_INVALID_TYPE
);

class VideoCallbackListener : public VideoStateCallback, public std::enable_shared_from_this<VideoCallbackListener> {
public:
    explicit VideoCallbackListener(napi_env env);
    ~VideoCallbackListener() = default;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback, const std::string &eventType);
    void RemoveAllCallbacks(const std::string &eventType);

private:
    void UpdateJSCallback(VideoOutputEventType eventType, const int32_t value) const;
    void UpdateJSCallbackAsync(VideoOutputEventType eventType, const int32_t value) const;
    std::mutex videoOutputMutex_;
    napi_env env_;
    mutable std::vector<std::shared_ptr<AutoRef>> frameStartCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> frameEndCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> errorCbList_;
};

struct VideoOutputCallbackInfo {
    VideoOutputEventType eventType_;
    int32_t value_;
    weak_ptr<const VideoCallbackListener> listener_;
    VideoOutputCallbackInfo(VideoOutputEventType eventType, int32_t value,
        shared_ptr<const VideoCallbackListener> listener)
        : eventType_(eventType), value_(value), listener_(listener) {}
};

class VideoOutputNapi : public ListenerBase {
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
    static napi_value RegisterCallback(napi_env env, napi_value jsThis,
        const std::string& eventType, napi_value callback, bool isOnce) override;
    static napi_value UnregisterCallback(napi_env env, napi_value jsThis,
        const std::string& eventType, napi_value callback) override;

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
