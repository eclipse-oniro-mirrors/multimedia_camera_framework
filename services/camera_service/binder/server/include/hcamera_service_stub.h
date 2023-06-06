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

#ifndef OHOS_CAMERA_HCAMERA_SERVICE_STUB_H
#define OHOS_CAMERA_HCAMERA_SERVICE_STUB_H

#include "camera_util.h"
#include "icamera_service.h"
#include "iremote_stub.h"
#include "input/camera_death_recipient.h"
#include "input/i_standard_camera_listener.h"

namespace OHOS {
namespace CameraStandard {
class HCameraServiceStub : public IRemoteStub<ICameraService> {
public:
    HCameraServiceStub();
    ~HCameraServiceStub();
    int OnRemoteRequest(uint32_t code, MessageParcel &data,
                        MessageParcel &reply, MessageOption &option) override;

private:
    int HandleGetCameras(MessageParcel &data, MessageParcel &reply);
    int HandleCreateCameraDevice(MessageParcel &data, MessageParcel &reply);
    int HandleSetCallback(MessageParcel &data, MessageParcel &reply);
    int HandleSetMuteCallback(MessageParcel &data, MessageParcel &reply);
    int HandleCreateCaptureSession(MessageParcel &data, MessageParcel &reply);
    int HandleCreatePhotoOutput(MessageParcel &data, MessageParcel &reply);
    int HandleCreatePreviewOutput(MessageParcel &data, MessageParcel &reply);
    int HandleCreateDeferredPreviewOutput(MessageParcel &data, MessageParcel &reply);
    int HandleCreateMetadataOutput(MessageParcel &data, MessageParcel &reply);
    int HandleCreateVideoOutput(MessageParcel &data, MessageParcel &reply);
    int HandleMuteCamera(MessageParcel &data, MessageParcel &reply);
    int HandleIsCameraMuted(MessageParcel &data, MessageParcel &reply);
    int DestroyStubForPid(pid_t pid);
    void ClientDied(pid_t pid);
    int SetListenerObject(const sptr<IRemoteObject> &object) override;
    int SetListenerObject(MessageParcel &data, MessageParcel &reply);
    int32_t CheckRequestCode(const uint32_t code, MessageParcel &data,
                                                 MessageParcel &reply, MessageOption &option);
    void RegisterMethod();
    virtual int32_t UnSetCallback(pid_t pid);
    virtual int32_t CloseCameraForDestory(pid_t pid);

    SafeMap<pid_t, sptr<CameraDeathRecipient>> deathRecipientMap_;
    SafeMap<pid_t, sptr<IStandardCameraListener>> cameraListenerMap_;

    typedef int (HCameraServiceStub::* HandleMethod)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, HandleMethod> methodFactory;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_SERVICE_STUB_H

