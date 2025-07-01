/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_SYS_OBJECT_TYPES_H
#define CAMERA_NAPI_SYS_OBJECT_TYPES_H

#include <any>
#include <cstdint>
#include <memory>

#include "camera_napi_object_types.h"
#include "camera_napi_object.h"
#include "js_native_api_types.h"
#include "session/video_session_for_sys.h"

namespace OHOS {
namespace CameraStandard {
class FocusTrackingInfo;
class CameraNapiFocusTrackingInfo : public CameraNapiObjectTypes {
public:
    explicit CameraNapiFocusTrackingInfo(FocusTrackingInfo& focusTrackingInfo) : focusTrackingInfo_(focusTrackingInfo)
    {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    FocusTrackingInfo& focusTrackingInfo_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_SYS_OBJECT_TYPES_H */
