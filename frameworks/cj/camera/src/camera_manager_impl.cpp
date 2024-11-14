/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_manager_impl.h"
#include <vector>
#include "camera_input_impl.h"
#include "camera_log.h"
#include "camera_utils.h"
#include "cj_lambda.h"

const int32_t SECURE_CAMERA = 12;

namespace OHOS {
namespace CameraStandard {
void CJCameraManagerCallback::OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const
{
    ExecuteCallback(cameraStatusInfo);
}

void CJCameraManagerCallback::OnFlashlightStatusChanged(const std::string &cameraID,
                                                        const FlashStatus flashStatus) const
{
    (void)cameraID;
    (void)flashStatus;
}

void CJFoldListener::OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const
{
    ExecuteCallback(foldStatusInfo);
}

void CJTorchListener::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    ExecuteCallback(torchStatusInfo);
}

CJCameraManager::CJCameraManager()
{
    cameraManager_ = CameraManager::GetInstance();
}

CJCameraManager::~CJCameraManager()
{
}

CArrCJCameraDevice CJCameraManager::GetSupportedCameras(int32_t *errCode)
{
    std::vector<sptr<CameraDevice>> supportedCameraDevices = cameraManager_->GetSupportedCameras();
    CArrCJCameraDevice result = {nullptr, 0};
    CJCameraDevice *supportedCameras =
        static_cast<CJCameraDevice *>(malloc(sizeof(CJCameraDevice) * supportedCameraDevices.size()));
    if (supportedCameras == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return result;
    }

    int i = 0;
    for (auto it = supportedCameraDevices.begin(); it != supportedCameraDevices.end(); ++it) {
        sptr<CameraDevice> cameraDevice = *it;
        char *cameraDeviceId = MallocCString(cameraDevice->GetID());
        if (cameraDeviceId == nullptr) {
            *errCode = CameraError::CAMERA_SERVICE_ERROR;
            for (int j = 0; j < i; j++) {
                free(supportedCameras[j].cameraId);
            }
            free(supportedCameras);
            return result;
        }

        supportedCameras[i].cameraId = cameraDeviceId;
        supportedCameras[i].cameraPosition = static_cast<int32_t>(cameraDevice->GetPosition());
        supportedCameras[i].cameraType = static_cast<int32_t>(cameraDevice->GetCameraType());
        supportedCameras[i].connectionType = static_cast<int32_t>(cameraDevice->GetConnectionType());
        supportedCameras[i].cameraOrientation = cameraDevice->GetCameraOrientation();
        i++;
    }

    result.size = supportedCameraDevices.size();
    result.head = supportedCameras;
    *errCode = CameraError::NO_ERROR;
    return result;
}

CArrI32 CJCameraManager::GetSupportedSceneModes(std::string cameraId, int32_t *errCode)
{
    sptr<CameraDevice> cameraInfo = cameraManager_->GetCameraDeviceFromId(cameraId);
    CArrI32 result = {nullptr, 0};
    if (cameraInfo == nullptr) {
        *errCode = CameraError::INVALID_PARAM;
        return result;
    }

    std::vector<SceneMode> modeObjList = cameraManager_->GetSupportedModes(cameraInfo);
    for (auto it = modeObjList.begin(); it != modeObjList.end(); it++) {
        if (*it == SCAN) {
            modeObjList.erase(it);
            break;
        }
    }
    if (modeObjList.empty()) {
        modeObjList.emplace_back(CAPTURE);
        modeObjList.emplace_back(VIDEO);
    }

    int64_t size = 0;
    for (size_t i = 0; i < modeObjList.size(); i++) {
        if (modeObjList[i] == CAPTURE || modeObjList[i] == VIDEO || modeObjList[i] == PROFESSIONAL_VIDEO) {
            size++;
        }
    }

    int32_t *sceneModes = static_cast<int32_t *>(malloc(sizeof(int32_t) * size));
    if (sceneModes == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return result;
    }

    size = 0;
    for (size_t i = 0; i < modeObjList.size(); i++) {
        if (modeObjList[i] == CAPTURE || modeObjList[i] == VIDEO || modeObjList[i] == PROFESSIONAL_VIDEO) {
            sceneModes[size] = modeObjList[i];
            size++;
        }
    }
    result.head = sceneModes;
    result.size = size;
    *errCode = CameraError::NO_ERROR;
    return result;
}

sptr<CameraOutputCapability> CJCameraManager::GetSupportedOutputCapability(sptr<CameraDevice> &camera, int32_t modeType)
{
    return cameraManager_->GetSupportedOutputCapability(camera, modeType);
}

bool CJCameraManager::IsCameraMuted()
{
    bool isMuted = CameraManager::GetInstance()->IsCameraMuted();
    return isMuted;
}

int64_t CJCameraManager::CreateCameraInputWithCameraDevice(sptr<CameraDevice> &camera, sptr<CameraInput> *pCameraInput)
{
    int retCode = cameraManager_->CreateCameraInput(camera, pCameraInput);
    return retCode;
}

int64_t CJCameraManager::CreateCameraInputWithCameraDeviceInfo(CameraPosition position, CameraType cameraType,
                                                               sptr<CameraInput> *pCameraInput)
{
    std::vector<sptr<CameraDevice>> cameraObjList = cameraManager_->GetSupportedCameras();
    sptr<CameraDevice> cameraInfo = nullptr;
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        sptr<CameraDevice> cameraDevice = cameraObjList[i];
        if (cameraDevice == nullptr) {
            continue;
        }
        if (cameraDevice->GetPosition() == position && cameraDevice->GetCameraType() == cameraType) {
            cameraInfo = cameraDevice;
            break;
        }
    }
    return CreateCameraInputWithCameraDevice(cameraInfo, pCameraInput);
}

sptr<CameraStandard::CaptureSession> CJCameraManager::CreateSession(int32_t mode)
{
    SceneMode sceneMode;
    if (mode == SECURE_CAMERA) {
        sceneMode = SceneMode::SECURE;
    } else {
        sceneMode = static_cast<SceneMode>(mode);
    }
    return CameraManager::GetInstance()->CreateCaptureSession(sceneMode);
}

bool CJCameraManager::IsTorchSupported()
{
    bool isTorchSupported = CameraManager::GetInstance()->IsTorchSupported();
    return isTorchSupported;
}

bool CJCameraManager::IsTorchModeSupported(int32_t modeType)
{
    TorchMode mode = TorchMode(modeType);
    bool isTorchModeSupported = CameraManager::GetInstance()->IsTorchModeSupported(mode);
    return isTorchModeSupported;
}

int32_t CJCameraManager::GetTorchMode()
{
    TorchMode torchMode = CameraManager::GetInstance()->GetTorchMode();
    return torchMode;
}

int32_t CJCameraManager::SetTorchMode(int32_t modeType)
{
    TorchMode mode = TorchMode(modeType);
    return CameraManager::GetInstance()->SetTorchMode(mode);
}

sptr<CameraDevice> CJCameraManager::GetCameraDeviceById(std::string cameraId)
{
    return cameraManager_->GetCameraDeviceFromId(cameraId);
}

void CJCameraManager::OnCameraStatusChanged(int64_t callbackId)
{
    if (cameraManagerCallback_ == nullptr) {
        cameraManagerCallback_ = std::make_shared<CJCameraManagerCallback>();
        cameraManager_->SetCallback(cameraManagerCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJCameraStatusInfo info)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const CameraStatusInfo &cameraStatusInfo) -> void {
        auto res = CameraStatusInfoToCJCameraStatusInfo(cameraStatusInfo);
        lambda(res);
        free(res.camera.cameraId);
    };
    auto callbackRef = std::make_shared<CallbackRef<const CameraStatusInfo &>>(callback, callbackId);
    cameraManagerCallback_->SaveCallbackRef(callbackRef);
}

void CJCameraManager::OffCameraStatusChanged(int64_t callbackId)
{
    if (cameraManagerCallback_ == nullptr) {
        return;
    }
    cameraManagerCallback_->RemoveCallbackRef(callbackId);
}

void CJCameraManager::OffAllCameraStatusChanged()
{
    if (cameraManagerCallback_ == nullptr) {
        return;
    }
    cameraManagerCallback_->RemoveAllCallbackRef();
}

void CJCameraManager::OnFoldStatusChanged(int64_t callbackId)
{
    if (foldListener_ == nullptr) {
        foldListener_ = std::make_shared<CJFoldListener>();
        cameraManager_->RegisterFoldListener(foldListener_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJFoldStatusInfo info)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const FoldStatusInfo &foldStatusInfo) -> void {
        auto res = FoldStatusInfoToCJFoldStatusInfo(foldStatusInfo);
        lambda(res);
        if (res.supportedCameras.head != nullptr) {
            for (int64_t i = 0; i < res.supportedCameras.size; i++) {
                free(res.supportedCameras.head[i].cameraId);
            }
            free(res.supportedCameras.head);
        }
    };
    auto callbackRef = std::make_shared<CallbackRef<const FoldStatusInfo &>>(callback, callbackId);
    foldListener_->SaveCallbackRef(callbackRef);
}

void CJCameraManager::OffFoldStatusChanged(int64_t callbackId)
{
    if (foldListener_ == nullptr) {
        return;
    }
    foldListener_->RemoveCallbackRef(callbackId);
}

void CJCameraManager::OffAllFoldStatusChanged()
{
    if (foldListener_ == nullptr) {
        return;
    }
    foldListener_->RemoveAllCallbackRef();
}

void CJCameraManager::OnTorchStatusChange(int64_t callbackId)
{
    if (torchListener_ == nullptr) {
        torchListener_ = std::make_shared<CJTorchListener>();
        cameraManager_->RegisterTorchListener(torchListener_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJTorchStatusInfo info)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const TorchStatusInfo &torchStatusInfo) -> void {
        lambda(TorchStatusInfoToCJTorchStatusInfo(torchStatusInfo));
    };
    auto callbackRef = std::make_shared<CallbackRef<const TorchStatusInfo &>>(callback, callbackId);
    torchListener_->SaveCallbackRef(callbackRef);
}

void CJCameraManager::OffTorchStatusChange(int64_t callbackId)
{
    if (torchListener_ == nullptr) {
        return;
    }
    torchListener_->RemoveCallbackRef(callbackId);
}

void CJCameraManager::OffAllTorchStatusChange()
{
    if (torchListener_ == nullptr) {
        return;
    }
    torchListener_->RemoveAllCallbackRef();
}

} // namespace CameraStandard
} // namespace OHOS