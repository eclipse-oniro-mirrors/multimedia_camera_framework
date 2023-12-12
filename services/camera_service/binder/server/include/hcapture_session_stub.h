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

#ifndef OHOS_CAMERA_HCAPTURE_SESSION_STUB_H
#define OHOS_CAMERA_HCAPTURE_SESSION_STUB_H

#include "icapture_session.h"
#include "iremote_stub.h"
#include "istream_capture.h"
#include "istream_metadata.h"
#include "istream_repeat.h"
namespace OHOS {
namespace CameraStandard {
class HCaptureSessionStub : public IRemoteStub<ICaptureSession> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data,
                        MessageParcel &reply, MessageOption &option) override;

private:
    int HandleAddInput(MessageParcel &data);
    int HandleAddOutput(MessageParcel &data);
    int HandleRemoveInput(MessageParcel &data);
    int HandleRemoveOutput(MessageParcel &data);
    int HandleSaveRestoreParam(MessageParcel &data);
    int HandleSetCallback(MessageParcel &data);
    int HandleGetSesstionState(MessageParcel &reply);
    int HandleGetActiveColorSpace(MessageParcel &reply);
    int HandleSetColorSpace(MessageParcel &data);
    int HandleSetSmoothZoom(MessageParcel &data, MessageParcel &reply);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAPTURE_SESSION_STUB_H
