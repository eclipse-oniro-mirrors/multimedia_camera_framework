/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hcapture_session_wrapper.h"
#include "hshared_capture_session.h"
#include "hcamera_device_wrapper.h"
#include "hshared_camera_device.h"
#include "camera_log.h"
#include <cstdint>

namespace OHOS {
namespace CameraStandard {

HCaptureSessionWrapper::HCaptureSessionWrapper(
    int32_t opMode,
    pid_t ownerPid,
    bool isPrivilegeApp,
    const sptr<HCaptureSession>& session)
    : ownerPid_(ownerPid), opMode_(opMode), isPrivilegeApp_(isPrivilegeApp),
    isSharedMode_(isPrivilegeApp), session_(nullptr)
{
    MEDIA_INFO_LOG("HCaptureSessionWrapper::Constructor opMode: %{public}d, pid: %{public}d, isPrivilege: %{public}d",
        opMode_, ownerPid_, isPrivilegeApp_);

    if (session == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::Constructor session is null");
        return;
    }

    session_ = session;
    if (isSharedMode_) {
        auto* sharedSession = static_cast<HSharedCaptureSession*>(session_.GetRefPtr());
        if (sharedSession != nullptr) {
            sharedSession->AddRef(ownerPid_);
        }
        MEDIA_INFO_LOG("HCaptureSessionWrapper::Constructor using shared session");
    } else {
        MEDIA_INFO_LOG("HCaptureSessionWrapper::Constructor using independent session");
    }
}

HCaptureSessionWrapper::~HCaptureSessionWrapper()
{
    MEDIA_INFO_LOG("HCaptureSessionWrapper::Destructor pid: %{public}d", ownerPid_);
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::Release session is null");
        return;
    }

    if (isSharedMode_) {
        auto* sharedSession = static_cast<HSharedCaptureSession*>(session_.GetRefPtr());
        CHECK_RETURN_ELOG(sharedSession == nullptr, "HCaptureSessionWrapper::Release sharedSession is null");
        RemoveSavedOutputsFromSharedSession();
        sharedSession->ReleaseRef(ownerPid_);
        return;
    }

    session_->Release(CaptureSessionReleaseType::RELEASE_TYPE_OBJ_DIED);
}

sptr<HCaptureSession> HCaptureSessionWrapper::GetRealSession() const
{
    return session_;
}

pid_t HCaptureSessionWrapper::GetOwnerPid() const
{
    return ownerPid_;
}

std::string HCaptureSessionWrapper::GetCameraId() const
{
    auto session = GetRealSession();
    if (session == nullptr) {
        return "";
    }
    auto device = session->GetCameraDevice();
    if (device == nullptr) {
        return "";
    }
    return device->GetCameraId();
}

bool HCaptureSessionWrapper::IsSharedMode() const
{
    return isSharedMode_;
}

void HCaptureSessionWrapper::SetSharedSessionReadyCallback(SharedSessionReadyCallback callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    sharedSessionReadyCallback_ = callback;
}

void HCaptureSessionWrapper::SwitchShareSession(const sptr<HSharedCaptureSession>& sharedSession)
{
    MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession pid: %{public}d", ownerPid_);

    sptr<HCaptureSession> oldSession = session_;
    bool oldWasShared = isSharedMode_;

    session_ = sharedSession;
    isSharedMode_ = true;

    sharedSession->AddRef(ownerPid_);
    MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession added ref for pid: %{public}d", ownerPid_);

    if (!savedOutputs_.empty()) {
        RestoreOutputsToSharedSession();
    }

    if (!oldWasShared && oldSession != nullptr) {
        MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession releasing old independent session");
        oldSession->Release();
    }
    if (oldWasShared && oldSession != nullptr && oldSession.GetRefPtr() != sharedSession.GetRefPtr()) {
        HSharedCaptureSession* oldShared = static_cast<HSharedCaptureSession*>(oldSession.GetRefPtr());
        if (oldShared != nullptr) {
            oldShared->ReleaseRef(ownerPid_);
            MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession released ref on old shared session");
        }
    }

    MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession success");
}

int32_t HCaptureSessionWrapper::HandleSharedInput(const std::string& cameraId,
    SharedSessionReadyCallback& readyCallback, std::string& readyCameraId,
    sptr<HSharedCameraDevice>& readySharedDevice, sptr<HSharedCaptureSession>& readySharedSession)
{
    sptr<HSharedCameraDevice> sharedDevice = HSharedCameraDevice::GetSharedDevice(cameraId);
    CHECK_RETURN_RET_ELOG(sharedDevice == nullptr, CAMERA_INVALID_STATE,
        "HCaptureSessionWrapper::AddInput sharedDevice is null");

    sptr<HSharedCaptureSession> sharedSession = HSharedCaptureSession::GetExistingSession(cameraId);
    if (sharedSession == nullptr) {
        MEDIA_INFO_LOG("HCaptureSessionWrapper::AddInput registering shared session "
            "to map for cameraId: %{public}s", cameraId.c_str());
        HSharedCaptureSession* sharedSessPtr =
            static_cast<HSharedCaptureSession*>(session_.GetRefPtr());
        CHECK_RETURN_RET_ELOG(sharedSessPtr == nullptr, CAMERA_INVALID_STATE,
            "HCaptureSessionWrapper::AddInput sharedSessPtr is null");
        sharedSessPtr->RegisterToMap(cameraId);
        sharedSession = sptr<HSharedCaptureSession>(sharedSessPtr);
        readyCallback = sharedSessionReadyCallback_;
        readyCameraId = cameraId;
        readySharedDevice = sharedDevice;
        readySharedSession = sharedSession;
        int32_t rc = session_->AddInput(sharedDevice->GetRealDevice());
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::AddInput AddInput on shared session failed");
            return rc;
        }
    } else {
        MEDIA_INFO_LOG("HCaptureSessionWrapper::AddInput switching to existing "
            "shared session for pid: %{public}d", ownerPid_);
        SwitchShareSession(sharedSession);
    }
    CaptureSessionState currentState = CaptureSessionState::SESSION_INIT;
    sharedSession->GetSessionState(currentState);
    if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        int32_t rc = sharedSession->BeginConfig();
        MEDIA_INFO_LOG("HCaptureSessionWrapper::AddInput BeginConfig on "
            "shared session returned %{public}d", rc);
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::AddInput BeginConfig on shared session failed");
            return rc;
        }
    }
    return CAMERA_OK;
}

void HCaptureSessionWrapper::RestoreOutputsToSharedSession()
{
    MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession restoring %{public}zu outputs",
        savedOutputs_.size());

    HSharedCaptureSession* sharedSess = static_cast<HSharedCaptureSession*>(session_.GetRefPtr());
    if (sharedSess == nullptr) {
        return;
    }

    CaptureSessionState currentState = CaptureSessionState::SESSION_INIT;
    sharedSess->GetSessionState(currentState);
    MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession shared session state: %{public}d", currentState);

    if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        int32_t rc = sharedSess->BeginConfig();
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::SwitchShareSession BeginConfig failed, rc: %{public}d", rc);
            return;
        }
    }

    size_t restoredCount = 0;
    for (const auto& [streamType, remoteObj] : savedOutputs_) {
        int32_t rc = session_->AddOutput(streamType, remoteObj);
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::SwitchShareSession restore output type:%{public}d failed, "
                "rc: %{public}d", streamType, rc);
        } else {
            restoredCount++;
            MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession restored output type: %{public}d",
                streamType);
        }
    }
    MEDIA_INFO_LOG("HCaptureSessionWrapper::SwitchShareSession restored %{public}zu/%{public}zu outputs",
        restoredCount, savedOutputs_.size());
}

void HCaptureSessionWrapper::RemoveSavedOutputsFromSharedSession()
{
    if (session_ == nullptr || savedOutputs_.empty()) {
        return;
    }

    auto* sharedSession = static_cast<HSharedCaptureSession*>(session_.GetRefPtr());
    if (sharedSession == nullptr) {
        return;
    }

    CaptureSessionState currentState = CaptureSessionState::SESSION_INIT;
    sharedSession->GetSessionState(currentState);
    if (currentState != CaptureSessionState::SESSION_CONFIG_INPROGRESS) {
        int32_t rc = sharedSession->BeginConfig();
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveSavedOutputsFromSharedSession BeginConfig failed, "
                "rc:%{public}d", rc);
            return;
        }
    }

    size_t removedCount = 0;
    for (const auto& [streamType, remoteObj] : savedOutputs_) {
        int32_t rc = session_->RemoveOutput(streamType, remoteObj);
        if (rc != CAMERA_OK) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveSavedOutputsFromSharedSession remove output type:%{public}d "
                "failed, rc:%{public}d", streamType, rc);
            continue;
        }
        removedCount++;
    }

    int32_t rc = sharedSession->CommitConfig();
    if (rc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveSavedOutputsFromSharedSession CommitConfig failed, rc:%{public}d",
            rc);
        return;
    }
    int32_t startRc = sharedSession->Start();
    if (startRc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveSavedOutputsFromSharedSession Start failed, rc:%{public}d",
            startRc);
        return;
    }
    MEDIA_INFO_LOG("HCaptureSessionWrapper::RemoveSavedOutputsFromSharedSession removed %{public}zu outputs, "
        "CommitConfig returned %{public}d", removedCount, rc);
    savedOutputs_.clear();
}

int32_t HCaptureSessionWrapper::BeginConfig()
{
    if (session_ != nullptr) {
        return session_->BeginConfig();
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::BeginConfig session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::CommitConfig()
{
    if (session_ != nullptr) {
        return session_->CommitConfig();
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::CommitConfig session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::CanAddInput(const sptr<ICameraDeviceService>& cameraDevice, bool& result)
{
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::CanAddInput session is null");
        return CAMERA_INVALID_STATE;
    }
    HCameraDeviceWrapper* deviceWrapper = static_cast<HCameraDeviceWrapper*>(cameraDevice.GetRefPtr());
    if (deviceWrapper != nullptr) {
        sptr<HCameraDevice> realDevice = deviceWrapper->GetRealDevice();
        if (deviceWrapper->IsSharedMode()) {
            HSharedCameraDevice* sharedDevice = static_cast<HSharedCameraDevice*>(realDevice.GetRefPtr());
            CHECK_RETURN_RET_ELOG(sharedDevice == nullptr, CAMERA_INVALID_STATE,
                "HCaptureSessionWrapper::CanAddInput sharedDevice is null");
            realDevice = sharedDevice->GetRealDevice();
        }
        return session_->CanAddInput(realDevice, result);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::CanAddInput deviceWrapper is null");
    return CAMERA_INVALID_ARG;
}

int32_t HCaptureSessionWrapper::AddInput(const sptr<ICameraDeviceService>& cameraDevice)
{
    SharedSessionReadyCallback readyCallback = nullptr;
    std::string readyCameraId;
    sptr<HSharedCameraDevice> readySharedDevice = nullptr;
    sptr<HSharedCaptureSession> readySharedSession = nullptr;
    int32_t addInputRc = CAMERA_OK;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (session_ == nullptr) {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::AddInput session is null");
            return CAMERA_INVALID_STATE;
        }

        HCameraDeviceWrapper* deviceWrapper = static_cast<HCameraDeviceWrapper*>(cameraDevice.GetRefPtr());
        if (deviceWrapper != nullptr) {
            std::string cameraId = deviceWrapper->GetCameraId();
            if (deviceWrapper->IsSharedMode()) {
                addInputRc = HandleSharedInput(cameraId, readyCallback, readyCameraId,
                    readySharedDevice, readySharedSession);
            } else {
                addInputRc = session_->AddInput(deviceWrapper->GetRealDevice());
            }
        } else {
            MEDIA_ERR_LOG("HCaptureSessionWrapper::AddInput deviceWrapper is null");
            return CAMERA_INVALID_ARG;
        }
    }
    if (addInputRc == CAMERA_OK && readyCallback != nullptr && readySharedDevice != nullptr &&
        readySharedSession != nullptr) {
        readyCallback(readyCameraId, readySharedDevice, readySharedSession, ownerPid_);
    }
    return addInputRc;
}

int32_t HCaptureSessionWrapper::AddOutput(StreamType streamType, const sptr<IRemoteObject>& stream)
{
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::AddOutput session is null");
        return CAMERA_INVALID_STATE;
    }
    int32_t rc = session_->AddOutput(streamType, stream);
    if (rc == CAMERA_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(savedOutputs_.begin(), savedOutputs_.end(),
            [streamType, &stream](const auto& pair) {
                return pair.first == streamType && pair.second == stream;
            });
        if (it == savedOutputs_.end()) {
            savedOutputs_.emplace_back(streamType, stream);
        }
        MEDIA_INFO_LOG("HCaptureSessionWrapper::AddOutput saved, total: %{public}zu", savedOutputs_.size());
    }
    return rc;
}

int32_t HCaptureSessionWrapper::AddMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput, int32_t opMode)
{
    if (session_ != nullptr) {
        return session_->AddMultiStreamOutput(multiStreamOutput, opMode);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::AddMultiStreamOutput session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::RemoveMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput)
{
    if (session_ != nullptr) {
        return session_->RemoveMultiStreamOutput(multiStreamOutput);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveMultiStreamOutput session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::RemoveInput(const sptr<ICameraDeviceService>& cameraDevice)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveInput session is null");
        return CAMERA_INVALID_STATE;
    }

    HCameraDeviceWrapper* deviceWrapper = static_cast<HCameraDeviceWrapper*>(cameraDevice.GetRefPtr());
    if (deviceWrapper == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveInput deviceWrapper is null");
        return CAMERA_INVALID_ARG;
    }

    sptr<HCameraDevice> realDevice = deviceWrapper->GetRealDevice();
    if (deviceWrapper->IsSharedMode()) {
        HSharedCameraDevice* sharedDevice = static_cast<HSharedCameraDevice*>(realDevice.GetRefPtr());
        CHECK_RETURN_RET_ELOG(sharedDevice == nullptr, CAMERA_INVALID_STATE,
            "HCaptureSessionWrapper::RemoveInput sharedDevice is null");
        realDevice = sharedDevice->GetRealDevice();
    }
    CHECK_RETURN_RET_ELOG(realDevice == nullptr, CAMERA_INVALID_STATE,
        "HCaptureSessionWrapper::RemoveInput realDevice is null");
    return session_->RemoveInput(realDevice);
}

int32_t HCaptureSessionWrapper::RemoveOutput(StreamType streamType, const sptr<IRemoteObject>& stream)
{
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::RemoveOutput session is null");
        return CAMERA_INVALID_STATE;
    }
    int32_t rc = session_->RemoveOutput(streamType, stream);
    if (rc == CAMERA_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::remove_if(savedOutputs_.begin(), savedOutputs_.end(),
            [streamType, &stream](const auto& pair) {
                return pair.first == streamType && pair.second == stream;
            });
        savedOutputs_.erase(it, savedOutputs_.end());
        MEDIA_INFO_LOG("HCaptureSessionWrapper::RemoveOutput removed, remaining: %{public}zu", savedOutputs_.size());
    }
    return rc;
}

int32_t HCaptureSessionWrapper::Start()
{
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::Start session is null");
        return CAMERA_INVALID_STATE;
    }
    return session_->Start();
}

int32_t HCaptureSessionWrapper::Stop()
{
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::Stop session is null");
        return CAMERA_INVALID_STATE;
    }
    return session_->Stop();
}

int32_t HCaptureSessionWrapper::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionWrapper::Release session is null");
        return CAMERA_INVALID_STATE;
    }

    if (isSharedMode_) {
        auto* sharedSession = static_cast<HSharedCaptureSession*>(session_.GetRefPtr());
        CHECK_RETURN_RET_ELOG(sharedSession == nullptr, CAMERA_INVALID_STATE,
            "HCaptureSessionWrapper::Release sharedSession is null");
        RemoveSavedOutputsFromSharedSession();
        sharedSession->ReleaseRef(ownerPid_);
        return CAMERA_OK;
    }

    return session_->Release();
}

int32_t HCaptureSessionWrapper::SetCallback(const sptr<ICaptureSessionCallback>& callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ != nullptr) {
        return session_->SetCallback(callback);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::UnSetCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ != nullptr) {
        return session_->UnSetCallback();
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::UnSetCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetPressureCallback(const sptr<IPressureStatusCallback>& callback)
{
    if (session_ != nullptr) {
        return session_->SetPressureCallback(callback);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetPressureCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::UnSetPressureCallback()
{
    if (session_ != nullptr) {
        return session_->UnSetPressureCallback();
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::UnSetPressureCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetSessionState(CaptureSessionState& sessionState)
{
    if (session_ != nullptr) {
        return session_->GetSessionState(sessionState);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetSessionState session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetActiveColorSpace(int32_t& curColorSpace)
{
    if (session_ != nullptr) {
        return session_->GetActiveColorSpace(curColorSpace);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetActiveColorSpace session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetColorSpace(int32_t curColorSpace, bool isNeedUpdate)
{
    if (session_ != nullptr) {
        return session_->SetColorSpace(curColorSpace, isNeedUpdate);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetColorSpace session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetSmoothZoom(int32_t smoothZoomType, int32_t operationMode,
    float targetZoomRatio, float& duration)
{
    if (session_ != nullptr) {
        return session_->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetSmoothZoom session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetFeatureMode(int32_t featureMode)
{
    if (session_ != nullptr) {
        return session_->SetFeatureMode(featureMode);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetFeatureMode session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::EnableMovingPhoto(bool isEnable)
{
    if (session_ != nullptr) {
        return session_->EnableMovingPhoto(isEnable);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::EnableMovingPhoto session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
    if (session_ != nullptr) {
        return session_->EnableMovingPhotoMirror(isMirror, isConfig);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::EnableMovingPhotoMirror session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetPreviewRotation(const std::string& deviceClass)
{
    if (session_ != nullptr) {
        return session_->SetPreviewRotation(deviceClass);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetPreviewRotation session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetCommitConfigFlag(bool isNeedCommitting)
{
    if (session_ != nullptr) {
        return session_->SetCommitConfigFlag(isNeedCommitting);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetCommitConfigFlag session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetHasFitedRotation(bool isHasFitedRotation)
{
    if (session_ != nullptr) {
        return session_->SetHasFitedRotation(isHasFitedRotation);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetHasFitedRotation session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::CreateRecorder(const sptr<IRemoteObject>& stream, sptr<ICameraRecorder>& recorder)
{
    if (session_ != nullptr) {
        return session_->CreateRecorder(stream, recorder);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::CreateRecorder session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetVirtualApertureMetadata(std::vector<float>& virtualApertureMetadata)
{
    if (session_ != nullptr) {
        return session_->GetVirtualApertureMetadata(virtualApertureMetadata);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetVirtualApertureMetadata session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetVirtualApertureValue(float& value)
{
    if (session_ != nullptr) {
        return session_->GetVirtualApertureValue(value);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetVirtualApertureValue session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetVirtualApertureValue(float value, bool needPersist)
{
    if (session_ != nullptr) {
        return session_->SetVirtualApertureValue(value, needPersist);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetVirtualApertureValue session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetBeautyMetadata(std::vector<int32_t>& beautyApertureMetadata)
{
    if (session_ != nullptr) {
        return session_->GetBeautyMetadata(beautyApertureMetadata);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetBeautyMetadata session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetBeautyRange(std::vector<int32_t>& range, int32_t type)
{
    if (session_ != nullptr) {
        return session_->GetBeautyRange(range, type);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetBeautyRange session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetBeautyValue(int32_t type, int32_t& value)
{
    if (session_ != nullptr) {
        return session_->GetBeautyValue(type, value);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetBeautyValue session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetBeautyValue(int32_t type, int32_t value, bool needPersist)
{
    if (session_ != nullptr) {
        return session_->SetBeautyValue(type, value, needPersist);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetBeautyValue session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetColorEffectsMetadata(std::vector<int32_t>& colorEffectMetadata)
{
    if (session_ != nullptr) {
        return session_->GetColorEffectsMetadata(colorEffectMetadata);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetColorEffectsMetadata session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetColorEffect(int32_t& colourEffect)
{
    if (session_ != nullptr) {
        return session_->GetColorEffect(colourEffect);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetColorEffect session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetColorEffect(int32_t colourEffect)
{
    if (session_ != nullptr) {
        return session_->SetColorEffect(colourEffect);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetColorEffect session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::EnableKeyFrameReport(bool isKeyFrameReportEnabled)
{
    if (session_ != nullptr) {
        return session_->EnableKeyFrameReport(isKeyFrameReportEnabled);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::EnableKeyFrameReport session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetXtStyleStatus(bool status)
{
    if (session_ != nullptr) {
        return session_->SetXtStyleStatus(status);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetXtStyleStatus session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetCameraSwitchRequestCallback(const sptr<ICameraSwitchSessionCallback>& callback)
{
    if (session_ != nullptr) {
        return session_->SetCameraSwitchRequestCallback(callback);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetCameraSwitchRequestCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::UnSetCameraSwitchRequestCallback()
{
    if (session_ != nullptr) {
        return session_->UnSetCameraSwitchRequestCallback();
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::UnSetCameraSwitchRequestCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetCompositionStream(sptr<IRemoteObject>& compositionStreamRemote)
{
    if (session_ != nullptr) {
        return session_->GetCompositionStream(compositionStreamRemote);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetCompositionStream session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetSensorRotationOnce(int32_t& sensorRotation)
{
    if (session_ != nullptr) {
        return session_->GetSensorRotationOnce(sensorRotation);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetSensorRotationOnce session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::IsAutoFramingSupported(bool& support)
{
    if (session_ != nullptr) {
        return session_->IsAutoFramingSupported(support);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::IsAutoFramingSupported session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::GetAutoFramingStatus(bool& status)
{
    if (session_ != nullptr) {
        return session_->GetAutoFramingStatus(status);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::GetAutoFramingStatus session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::EnableAutoFraming(bool enable, bool needPersist)
{
    if (session_ != nullptr) {
        return session_->EnableAutoFraming(enable, needPersist);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::EnableAutoFraming session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::SetControlCenterEffectStatusCallback(
    const sptr<IControlCenterEffectStatusCallback>& callback)
{
    if (session_ != nullptr) {
        return session_->SetControlCenterEffectStatusCallback(callback);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::SetControlCenterEffectStatusCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::UnSetControlCenterEffectStatusCallback()
{
    if (session_ != nullptr) {
        return session_->UnSetControlCenterEffectStatusCallback();
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::UnSetControlCenterEffectStatusCallback session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::CallbackEnter([[maybe_unused]] uint32_t code)
{
    if (session_ != nullptr) {
        return session_->CallbackEnter(code);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::CallbackEnter session is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCaptureSessionWrapper::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    if (session_ != nullptr) {
        return session_->CallbackExit(code, result);
    }
    MEDIA_ERR_LOG("HCaptureSessionWrapper::CallbackExit session is null");
    return CAMERA_INVALID_STATE;
}

} // namespace CameraStandard
} // namespace OHOS
