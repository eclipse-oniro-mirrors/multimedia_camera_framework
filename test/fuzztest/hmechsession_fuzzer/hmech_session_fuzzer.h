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

#ifndef HMECH_SEESION_FUZZER_H
#define HMECH_SEESION_FUZZER_H

#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_util.h"
#include "mech_session_callback_stub.h"
namespace OHOS::CameraStandard {
class MockMechSessionCallback : public MechSessionCallbackStub {
public:
    ErrCode OnFocusTrackingInfo(
        int32_t streamId, bool isNeedMirror, bool isNeedFlip, const std::shared_ptr<CameraMetadata>& results) override
    {
        return 0;
    }

    ErrCode OnCaptureSessionConfiged(const CaptureSessionInfo& captureSessionInfo) override
    {
        return 0;
    }

    ErrCode OnZoomInfoChange(int32_t sessionid, const ZoomInfo& zoomInfo) override
    {
        return 0;
    }

    ErrCode OnSessionStatusChange(int32_t sessionid, bool status) override
    {
        return 0;
    }
};

} // namespace OHOS::CameraStandard
#endif // HMECH_SEESION_FUZZER_H