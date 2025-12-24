/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_INFO_CALLBACK_H
#define CAMERA_NAPI_INFO_CALLBACK_H

#include <cstddef>
#include <cstdint>
#include <memory>

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "listener_base.h"
#include "camera_log.h"
#include "native_info_callback.h"

namespace OHOS {
namespace CameraStandard {
template<typename InfoTp>
class NapiInfoCallback : public NativeInfoCallback<InfoTp>,
                         public ListenerBase,
                         public std::enable_shared_from_this<NapiInfoCallback<InfoTp>> {
public:
    NapiInfoCallback(napi_env env) : ListenerBase(env) {}
    ~NapiInfoCallback() = default;
    void OnInfoChanged(InfoTp info) override
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        // OnInfoChanged -> NapiSendAsyncEvent -> ToNapiFormat, only ToNapiFormat need to implement
        NapiSendAsyncEvent(info, env_);
    };

private:
    void NapiSendAsyncEvent(const InfoTp& info, napi_env env)
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        auto pCb = this->weak_from_this();
        auto task = [info, pCb]() {
            auto cb = pCb.lock();
            if (cb != nullptr) {
                cb->ToNapiFormat(info);
            }
        };
        if (napi_ok != napi_send_event(env, task, napi_eprio_immediate, "NapiInfoCallback::OnInfoChanged")) {
            MEDIA_ERR_LOG("failed to execute work");
        }
    }
    // need to implement
    void ToNapiFormat(const InfoTp& info) const;
};

} // namespace CameraStandard
} // namespace OHOS
#endif