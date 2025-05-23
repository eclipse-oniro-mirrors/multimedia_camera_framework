/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_HCAMERA_DEVICE_STUB_H
#define OHOS_CAMERA_HCAMERA_DEVICE_STUB_H

#include "icamera_device_service.h"
#include "icamera_ipc_checker.h"
#include "iremote_stub.h"

namespace OHOS {
namespace CameraStandard {
class HCameraDeviceStub : public IRemoteStub<ICameraDeviceService>, public ICameraIpcChecker {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t HandleSetCallback(MessageParcel& data);
    int32_t HandleUpdateSetting(MessageParcel& data);
    int32_t HandleUsedAsPos(MessageParcel& data);
    int32_t HandleGetStatus(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetEnabledResults(MessageParcel& reply);
    int32_t HandleEnableResult(MessageParcel& data);
    int32_t HandleDisableResult(MessageParcel& data);
    int32_t HandleOpenSecureCameraResults(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOpenConcurrent(MessageParcel &data, MessageParcel &reply);
    int32_t HandleSetDeviceRetryTime(MessageParcel& data, MessageParcel& reply);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_DEVICE_STUB_H
