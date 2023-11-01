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

#ifndef CAMERA_MUTE_LISTENER_NAPI_H_
#define CAMERA_MUTE_LISTENER_NAPI_H_
#include "hilog/log.h"
#include "camera_napi_utils.h"

#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {
class CameraMuteListenerNapi : public CameraMuteListener {
public:
    explicit CameraMuteListenerNapi(napi_env env);
    virtual ~CameraMuteListenerNapi();
    void OnCameraMute(bool muteMode) const override;
    void SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback);
    void RemoveAllCallbacks();
private:
    void OnCameraMuteCallback(bool muteMode) const;
    void OnCameraMuteCallbackAsync(bool muteMode) const;

    std::mutex mutex_;
    napi_env env_ = nullptr;
    mutable std::vector<std::shared_ptr<AutoRef>> cameraMuteCbList_;
};

struct CameraMuteCallbackInfo {
    bool muteMode_;
    const CameraMuteListenerNapi* listener_;
    CameraMuteCallbackInfo(bool muteMode, const CameraMuteListenerNapi* listener)
        : muteMode_(muteMode), listener_(listener) {}
    ~CameraMuteCallbackInfo()
    {
        listener_ = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_MUTE_LISTENER_NAPI_H_ */