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

#ifndef HCAMERA_SERVICE_FUZZER_H
#define HCAMERA_SERVICE_FUZZER_H

#include "camera_service_callback_stub.h"
#include "camera_mute_service_callback_stub.h"
#include "torch_service_callback_stub.h"
#include "control_center_status_callback_stub.h"
#include "deferred_video_processing_session_callback_stub.h"
#include "deferred_photo_processing_session_callback_stub.h"
#include "fold_service_callback_stub.h"
#include "hcamera_broker_stub.h"

namespace OHOS::CameraStandard {
class MockCameraServiceCallback : public CameraServiceCallbackStub {
public:
    ErrCode OnCameraStatusChanged(const std::string& cameraId, int32_t status, const std::string& bundleName) override
    {
        return 0;
    }
    int32_t OnFlashlightStatusChanged(const std::string& cameraId, int32_t status) override
    {
        return 0;
    }
};

class MockCameraMuteServiceCallback : public CameraMuteServiceCallbackStub {
public:
    ErrCode OnCameraMute(bool muteMode) override
    {
        return 0;
    }
};

class MockTorchServiceCallback : public TorchServiceCallbackStub {
public:
    ErrCode OnTorchStatusChange(TorchStatus status) override
    {
        return 0;
    }
};

class MockControlCenterStatusCallbackStub : public ControlCenterStatusCallbackStub {
public:
    int32_t OnControlCenterStatusChanged(bool status)
    {
        return 0;
    }
};
using namespace DeferredProcessing;

class MockDeferredVideoProcessingSessionCallback : public DeferredVideoProcessingSessionCallbackStub {
public:
    ErrCode OnProcessVideoDone(const std::string& videoId) override
    {
        return 0;
    }

    ErrCode OnError(const std::string& videoId, ErrorCode errorCode) override
    {
        return 0;
    }

    ErrCode OnStateChanged(StatusCode status) override
    {
        return 0;
    }

    ErrCode OnProcessingProgress(const std::string& videoId, float progress) override
    {
        return 0;
    }
};

class MockDeferredPhotoProcessingSessionCallback : public DeferredPhotoProcessingSessionCallbackStub {
public:
    ErrCode OnProcessImageDone(const std::string& imageId, const sptr<IPCFileDescriptor>& ipcFd, int64_t bytes,
        uint32_t cloudImageEnhanceFlag) override
    {
        return 0;
    };

    ErrCode OnError(const std::string& imageId, ErrorCode errorCode) override
    {
        return 0;
    };

    ErrCode OnStateChanged(StatusCode status) override
    {
        return 0;
    };

    ErrCode OnDeliveryLowQualityImage(const std::string& imageId, const std::shared_ptr<PictureIntf>& picture) override
    {
        return 0;
    };

    ErrCode OnProcessImageDone(const std::string& imageId, const std::shared_ptr<PictureIntf>& picture,
        const DpsMetadata& dpsMetaData) override
    {
        return 0;
    };

    int32_t CallbackParcel(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        return 0;
    }
};

class MockFoldServiceCallback : public FoldServiceCallbackStub {
public:
    ErrCode OnFoldStatusChanged(FoldStatus status) override
    {
        return 0;
    }
};

class MockCameraBroker : public ICameraBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Anco.Service.Camera");

    int32_t NotifyCloseCamera(std::string cameraId)
    {
        return 0;
    };
    int32_t NotifyMuteCamera(bool muteMode)
    {
        return 0;
    };
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };
};

} // namespace OHOS::CameraStandard
#endif