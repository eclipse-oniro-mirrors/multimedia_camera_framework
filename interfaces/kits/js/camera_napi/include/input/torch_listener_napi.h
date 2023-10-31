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

#ifndef TORCH_LISTENER_NAPI_H_
#define TORCH_LISTENER_NAPI_H_

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "hilog/log.h"
#include "camera_napi_utils.h"

#include "input/camera_manager.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

namespace OHOS {
namespace CameraStandard {
class TorchListenerNapi : public TorchListener {
public:
    explicit TorchListenerNapi(napi_env env);
    virtual ~TorchListenerNapi();
    void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const override;
    void SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback);
    void RemoveAllCallbacks();
private:
    void OnTorchStatusChangeCallback(const TorchStatusInfo &torchStatusInfo) const;
    void OnTorchStatusChangeCallbackAsync(const TorchStatusInfo &torchStatusInfo) const;

    std::mutex mutex_;
    napi_env env_ = nullptr;
    mutable std::vector<std::shared_ptr<AutoRef>> torchCbList_;
};

struct TorchStatusChangeCallbackInfo {
    TorchStatusInfo info_;
    const TorchListenerNapi* listener_;
    TorchStatusChangeCallbackInfo(TorchStatusInfo info, const TorchListenerNapi* listener)
        : info_(info), listener_(listener) {}
    ~TorchStatusChangeCallbackInfo()
    {
        listener_ = nullptr;
    }
};

} // namespace CameraStandard
} // namespace OHOS
#endif /* TORCH_LISTENER_NAPI_H_ */