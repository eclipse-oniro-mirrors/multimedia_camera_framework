/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef HCAMERA_SWITCH_SEESION_FUZZER_H
#define HCAMERA_SWITCH_SEESION_FUZZER_H

#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_util.h"
#include "camera_switch_session_callback_stub.h"
namespace OHOS::CameraStandard {
class MockCameraSwitchSessionCallback : public CameraSwitchSessionCallbackStub {
public:
    ErrCode OnCameraActive(const std::string& cameraId, bool isRegisterCameraSwitchCallback,
        const CaptureSessionInfo& sessionInfo) override
    {
        return 0;
    }

    ErrCode OnCameraUnactive(const std::string& cameraId) override
    {
        return 0;
    }

    ErrCode OnCameraSwitch(const std::string& oriCameraId, const std::string& destCameraId, bool status) override
    {
        return 0;
    }
};

} // namespace OHOS::CameraStandard
#endif // HCAMERA_SWITCH_SEESION_FUZZER_H