 /*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_MANAGER_FUZZER_H
#define CAMERA_MANAGER_FUZZER_H

#include "input/camera_manager.h"
#include "picture_interface.h"
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class CameraManagerFuzzer {
public:
static void CameraManagerFuzzTest1(FuzzedDataProvider& fdp);
static void CameraManagerFuzzTest2(FuzzedDataProvider& fdp);
static void CameraManagerFuzzTest3(FuzzedDataProvider& fdp);
};

class IDeferredPhotoProcSessionCallbackFuzz : public IDeferredPhotoProcSessionCallback {
public:
    void OnProcessImageDone(const std::string& imageId, const uint8_t* addr, const long bytes,
        uint32_t cloudImageEnhanceFlag) override {}
    void OnProcessImageDone(const std::string &imageId, std::shared_ptr<PictureIntf> picture,
        const DpsMetadata& metadata) override {}
    void OnDeliveryLowQualityImage(const std::string &imageId, std::shared_ptr<PictureIntf> picture) override {}
    void OnError(const std::string& imageId, const DpsErrorCode errorCode) override {}
    void OnStateChanged(const DpsStatusCode status) override {}
};

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

class IDeferredVideoProcSessionCallbackFuzz : public IDeferredVideoProcSessionCallback {
public:
    void OnProcessVideoDone(const std::string& videoId) override {}
    void OnError(const std::string& videoId, const DpsErrorCode errorCode) override {}
    void OnStateChanged(const DpsStatusCode status) override {}
};

class CameraManagerCallbackFuzz : public CameraManagerCallback {
public:
    void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const override {}
    void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const override {}
};

class CameraMuteListenerFuzz : public CameraMuteListener {
public:
    void OnCameraMute(bool muteMode) const override {}
};

class FoldListenerFuzz : public FoldListener {
public:
    void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const override {}
};

class TorchListenerFuzz : public TorchListener {
public:
    void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const override {}
};
} //CameraStandard
} //OHOS
#endif //CAMERA_MANAGER_FUZZER_H