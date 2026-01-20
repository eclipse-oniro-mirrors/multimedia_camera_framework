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

#ifndef CAMERA_SERVICE_PROXY_FUZZER_H
#define CAMERA_SERVICE_PROXY_FUZZER_H

#include "camera_service_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace CameraStandard {
class ITorchServiceCallbackFuzz : public ITorchServiceCallback {
public:
    int32_t OnTorchStatusChange(const TorchStatus status, const float level) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return 0;
    }
};

class IFoldServiceCallbackFuzz : public IFoldServiceCallback {
public:
    virtual int32_t OnFoldStatusChanged(const FoldStatus status)
    {
        return 0;
    }
    virtual sptr<IRemoteObject> AsObject()
    {
        return 0;
    }
};

class ICameraMuteServiceCallbackFuzz : public ICameraMuteServiceCallback {
public:
    int32_t OnCameraMute(bool muteMode) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return 0;
    }
};
class ICameraServiceCallbackFuzz : public ICameraServiceCallback {
public:
    int32_t OnCameraStatusChanged(const std::string& cameraId, int32_t status, const std::string& bundleName) override
    {
        return 0;
    }

    int32_t OnFlashlightStatusChanged(const std::string& cameraId, int32_t status) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return 0;
    }
};

class IControlCenterStatusCallbackFuzz : public IControlCenterStatusCallback {
public:
    int32_t OnControlCenterStatusChanged(bool status) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return 0;
    }
};

class CameraBrokerFuzz : public ICameraBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Anco.Service.Camera");

    int32_t NotifyCloseCamera(std::string cameraId) override
    {
        return 0;
    };
    int32_t NotifyMuteCamera(bool muteMode) override
    {
        return 0;
    };
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};


class IDeferredPhotoProcessingSessionCallbackFuzz : public IDeferredPhotoProcessingSessionCallback {
public:
    explicit IDeferredPhotoProcessingSessionCallbackFuzz() = default;
    virtual ~IDeferredPhotoProcessingSessionCallbackFuzz() = default;
    inline int32_t OnProcessImageDone(const std::string &imageId,
        const sptr<IPCFileDescriptor>& ipcFd, int64_t bytes, uint32_t cloudImageEnhanceFlag) override
    {
        return 0;
    }
    inline int32_t OnProcessImageDone(const std::string &imageId, const std::shared_ptr<PictureIntf>& picture,
        const DpsMetadata& metadata) override
    {
        return 0;
    }
    inline int32_t OnDeliveryLowQualityImage(const std::string &imageId,
        const std::shared_ptr<PictureIntf>& picture) override
    {
        return 0;
    }
    inline int32_t OnError(const std::string &imageId, DeferredProcessing::ErrorCode errorCode) override
    {
        return 0;
    }
    inline int32_t OnStateChanged(DeferredProcessing::StatusCode status) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            return nullptr;
        }
        sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
        if (object == nullptr) {
            return nullptr;
        }
        return object;
    }
};

class DeferredVideoProcessingSessionCallback : public DeferredProcessing::IDeferredVideoProcessingSessionCallback {
public:
    ErrCode OnProcessVideoDone(const std::string& videoId) override
    {
        return 0;
    }
    ErrCode OnError(const std::string& videoId, DeferredProcessing::ErrorCode errorCode) override
    {
        return 0;
    }
    ErrCode OnStateChanged(DeferredProcessing::StatusCode status) override
    {
        return 0;
    }
    ErrCode OnProcessingProgress(const std::string& videoId, float progress) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};

class CameraServiceProxyFuzz {
public:
    static std::shared_ptr<CameraServiceProxy> fuzz_;
    
    static void CameraServiceProxyTest1(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest2(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest3(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest4(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest5();
    static void CameraServiceProxyTest6(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest7(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest8(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest9(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest10(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest11(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest12(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest13(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest14(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest15(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest16(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest17(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest18(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest19();
    static void CameraServiceProxyTest20();
    static void CameraServiceProxyTest21(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest22(FuzzedDataProvider &fdp);
    static void CameraServiceProxyTest23();
    static void CameraServiceProxyTest24(FuzzedDataProvider &fdp);
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // CAMERA_DEVICE_SERVICE_PROXY_FUZZER_H