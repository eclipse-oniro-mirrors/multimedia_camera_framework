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

#ifndef LISTENER_BASE_H_
#define LISTENER_BASE_H_

#include "camera_napi_utils.h"
namespace OHOS {
namespace CameraStandard {
class ListenerBase {
public:
    explicit ListenerBase(napi_env env);
    virtual ~ListenerBase();

    void SaveCallbackReference(napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback);
    void RemoveAllCallbacks();

protected:
    std::mutex mutex_;
    napi_env env_ = nullptr;
    mutable std::vector<std::shared_ptr<AutoRef>> baseCbList_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* LISTENER_BASE_H_ */
