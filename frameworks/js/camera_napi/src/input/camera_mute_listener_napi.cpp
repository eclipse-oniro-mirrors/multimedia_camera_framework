/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <uv.h>
#include "input/camera_mute_listener_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;

CameraMuteListenerNapi::CameraMuteListenerNapi(napi_env env, napi_ref ref): env_(env), callbackRef_(ref)
{
    MEDIA_INFO_LOG("Enter CameraMuteListenerNapi::CameraMuteListenerNapi");
}

CameraMuteListenerNapi::~CameraMuteListenerNapi()
{
    MEDIA_INFO_LOG("Enter CameraMuteListenerNapi::~CameraMuteListenerNapi");
}


void CameraMuteListenerNapi::OnCameraMuteCallbackAsync(const CameraMuteInfo &cameraMuteInfo) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("CameraMuteListenerNapi::OnCameraMuteCallbackAsync failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("CameraMuteListenerNapi::OnCameraMuteCallbackAsync failed to allocate work");
        return;
    }
    std::unique_ptr<CameraMuteCallbackInfo> callbackInfo =
        std::make_unique<CameraMuteCallbackInfo>(cameraMuteInfo, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        CameraMuteCallbackInfo* callbackInfo = reinterpret_cast<CameraMuteCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnCameraMuteCallback(callbackInfo->info_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("CameraMuteListenerNapi::OnCameraMuteCallbackAsync failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void CameraMuteListenerNapi::OnCameraMuteCallback(const CameraMuteInfo &cameraMuteInfo) const
{
    napi_value result[ARGS_TWO];
    napi_value callback = nullptr;
    napi_value retVal;
    bool muteMode = cameraMuteInfo.muteMode;
    napi_get_reference_value(env_, callbackRef_, &callback);
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_boolean(env_, muteMode, &result[PARAM1]);
    napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
}

void CameraMuteListenerNapi::OnCameraMute(bool muteMode) const
{
    MEDIA_DEBUG_LOG("CameraMuteListenerNapi::OnCameraMute muteMode: %{public}d", muteMode);
    const CameraMuteInfo cameraMuteInfo = {
        .muteMode = muteMode
    };
    OnCameraMuteCallbackAsync(cameraMuteInfo);
}
} // namespace CameraStandard
} // namespace OHOS
