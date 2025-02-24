/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef VIDEO_SESSION_FOR_SYS_NAPI_H
#define VIDEO_SESSION_FOR_SYS_NAPI_H

#include "mode/video_session_napi.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "session/camera_session_napi.h"
#include "video_session.h"

namespace OHOS {
namespace CameraStandard {
static const char VIDEO_SESSION_FOR_SYS_NAPI_CLASS_NAME[] = "VideoSessionForSys";

class FocusTrackingCallbackListener : public FocusTrackingCallback, public ListenerBase,
    public std::enable_shared_from_this<FocusTrackingCallbackListener> {
public:
    explicit FocusTrackingCallbackListener(napi_env env) : ListenerBase(env) {}
    virtual ~FocusTrackingCallbackListener() = default;
    void OnFocusTrackingInfoAvailable(FocusTrackingInfo &focusTrackingInfo) const override;

private:
    void OnFocusTrackingInfoCallback(FocusTrackingInfo &focusTrackingInfo) const;
    void OnFocusTrackingInfoCallbackAsync(FocusTrackingInfo &focusTrackingInfo) const;
};

struct FocusTrackingCallbackInfo {
    FocusTrackingInfo focusTrackingInfo_;
    weak_ptr<const FocusTrackingCallbackListener> listener_;
    FocusTrackingCallbackInfo(FocusTrackingInfo focusTrackingInfo,
        shared_ptr<const FocusTrackingCallbackListener> listener)
        : focusTrackingInfo_(focusTrackingInfo), listener_(listener) {}
};

class VideoSessionForSysNapi : public VideoSessionNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSession(napi_env env);
    VideoSessionForSysNapi();
    ~VideoSessionForSysNapi();

    static void VideoSessionForSysNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value VideoSessionForSysNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    sptr<VideoSession> videoSession_;
    static thread_local napi_ref sConstructor_;
    std::shared_ptr<FocusTrackingCallbackListener> focusTrackingInfoCallback_;

protected:
    void RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* VIDEO_SESSION_FOR_SYS_NAPI_H */
