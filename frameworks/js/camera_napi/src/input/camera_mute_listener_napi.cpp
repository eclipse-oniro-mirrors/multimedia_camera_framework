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
#include "input/camera_mute_listener_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "CameraMuteListenerNapi"};
}
CameraMuteListenerNapi::CameraMuteListenerNapi(napi_env env, napi_ref ref): env_(env), callbackRef_(ref)
{}

CameraMuteListenerNapi::~CameraMuteListenerNapi()
{}

void CameraManagerCallbackNapi::OnCameraMute(bool muteMode) const
{
    mCallbackRef->OnCameraMute(muteMode);
}

} // namespace CameraStandard
} // namespace OHOS
