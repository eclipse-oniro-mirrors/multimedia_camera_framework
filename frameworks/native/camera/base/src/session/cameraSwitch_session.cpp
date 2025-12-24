/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
 
#include "session/cameraSwitch_session.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"
#include "camera_manager.h"

namespace OHOS {

namespace CameraStandard {

int32_t CameraSwitchCallbackImpl::OnCameraActive(
    const std::string &cameraId, bool isRegisterCameraSwitchCallback, const CaptureSessionInfo &sessionInfo)
{
    MEDIA_INFO_LOG(
        "HCameraService::OnCameraActive cameraId is: %{public}s,isRegisterCameraSwitchCallback is:%{public}d",
        cameraId.c_str(), isRegisterCameraSwitchCallback);
    int32_t ret = CAMERA_OK;
    auto switchSession = cameraSwitchSession_.promote();
    CHECK_RETURN_RET(!switchSession, ret);
    auto saSwitchCallback = switchSession->GetCameraSwitchCallback();
    if (saSwitchCallback) {
        saSwitchCallback->OnCameraActive(cameraId, isRegisterCameraSwitchCallback, sessionInfo);
    }
    return ret;
}

int32_t CameraSwitchCallbackImpl::OnCameraUnactive(const std::string &cameraId)
{
    MEDIA_INFO_LOG("CameraSwitchCallbackImpl::OnCameraUnactive cameraId is: %{public}s", cameraId.c_str());
    int32_t ret = CAMERA_OK;
    auto switchSession = cameraSwitchSession_.promote();
    CHECK_RETURN_RET(!switchSession, ret);
    auto saSwitchCallback = switchSession->GetCameraSwitchCallback();
    if (saSwitchCallback) {
        saSwitchCallback->OnCameraUnactive(cameraId);
    }
    return CAMERA_OK;
}

int32_t CameraSwitchCallbackImpl::OnCameraSwitch(
    const std::string &oriCameraId, const std::string &destCameraId, bool status)
{
    MEDIA_INFO_LOG(
        "CameraSwitchCallbackImpl::OnCameraSwitch oriCameraId is: %{public}s,destCameraId is:%{public}s, is:%{public}d",
        oriCameraId.c_str(), destCameraId.c_str(), status);
    int32_t ret = CAMERA_OK;
    auto switchSession = cameraSwitchSession_.promote();
    CHECK_RETURN_RET(!switchSession, ret);
    auto saSwitchCallback = switchSession->GetCameraSwitchCallback();
    if (saSwitchCallback) {
        saSwitchCallback->OnCameraSwitch(oriCameraId, destCameraId, status);
    }
    return CAMERA_OK;
}

CameraSwitchSession::CameraSwitchSession(sptr<ICameraSwitchSession> session) : remoteSwitchSession_(session)
{
    MEDIA_INFO_LOG("CameraSwitchSession::CameraSwitchSession is enter");
    sptr<IRemoteObject> object = remoteSwitchSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_ELOG(deathRecipient_ == nullptr, "failed to new CameraDeathRecipient.");
    auto thisPtr = wptr<CameraSwitchSession>(this);
    deathRecipient_->SetNotifyCb([thisPtr](pid_t pid) {
        auto ptr = thisPtr.promote();
        CHECK_RETURN(ptr == nullptr);
        ptr->CameraServerSwitchDied(pid);
    });
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_ELOG(!result, "failed to add deathRecipient");
}

sptr<ICameraSwitchSession> CameraSwitchSession::GetRemoteSwitchSession()
{
    std::lock_guard<std::mutex> lock(remoteCameraSwitchSessionMutex_);
    return remoteSwitchSession_;
}

void CameraSwitchSession::SetRemoteSwitchSession(sptr<ICameraSwitchSession> remoteSession)
{
    std::lock_guard<std::mutex> lock(remoteCameraSwitchSessionMutex_);
    remoteSwitchSession_ = remoteSession;
}

CameraSwitchSession::~CameraSwitchSession()
{
    MEDIA_INFO_LOG("CameraSwitchSession::~CameraSwitchSession enter");
    RemoveSwitchDeathRecipient();
}

void CameraSwitchSession::SetCallback(std::shared_ptr<CameraSwitchCallback> callback)
{
    MEDIA_INFO_LOG("CameraSwitchSession::SetCallback enter");
    std::lock_guard<std::mutex> lock(callbackCameraSwitchMutex_);
    auto remoteSession = GetRemoteSwitchSession();
    CHECK_RETURN_ELOG(remoteSession == nullptr, "CameraSwitchSession::SetCallback CameraSwitchSession is null");
    sptr<ICameraSwitchSessionCallback> remoteCallback = new (std::nothrow) CameraSwitchCallbackImpl(this);
    CHECK_RETURN_ELOG(
        remoteCallback == nullptr, "CameraSwitchSession::SetCallback failed to new CameraSwitchCallbackImpl!");
    remoteSession->SetCallback(remoteCallback);
    appSwitchCallback_ = callback;
}

int32_t CameraSwitchSession::SwitchCamera(const std::string &oriCameraId, const std::string &destCameraId)
{
    MEDIA_INFO_LOG("CameraSwitchSession::SwitchCamera enter, oriCameraId=%{public}s,destCameraId=%{public}s",
        oriCameraId.c_str(), destCameraId.c_str());
    auto remoteSession = GetRemoteSwitchSession();
    CHECK_RETURN_RET_ELOG(remoteSession == nullptr,
        CameraErrorCode::INVALID_ARGUMENT, "CameraSwitchSession::SwitchCamera CameraSwitchSession is nullptr");
    sptr<ICameraDeviceService> deviceService = nullptr;
    int32_t retCode = CameraErrorCode::SUCCESS;
    retCode = CameraManager::GetInstance()->CreateCameraDevice(destCameraId, &deviceService);
    SwitchSetService(deviceService);
    retCode = remoteSession->SwitchCamera(oriCameraId, destCameraId);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "Failed to SwitchCamera!, %{public}d", retCode);
    return retCode;
}

int32_t CameraSwitchSession::SwitchSetService(const sptr<ICameraDeviceService>& cameraDevice){
    MEDIA_DEBUG_LOG("CameraSwitchSession::SwitchSetService enter");
    auto remoteSession = GetRemoteSwitchSession();
    CHECK_RETURN_RET_ELOG(remoteSession == nullptr,
        CameraErrorCode::INVALID_ARGUMENT, "CameraSwitchSession::SwitchSetService CameraSwitchSession is nullptr");
    int32_t retCode = remoteSession->SwitchSetService(cameraDevice);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "Failed to SwitchSetService!");
    return retCode;
}

void CameraSwitchSession::RemoveSwitchDeathRecipient()
{
    MEDIA_DEBUG_LOG("CameraSwitchSession::RemoveSwitchDeathRecipient enter");
    auto remoteSession = GetRemoteSwitchSession();
    if (remoteSession != nullptr) {
        auto asObject = remoteSession->AsObject();
        if (asObject) {
            (void)asObject->RemoveDeathRecipient(deathRecipient_);
        }
        SetRemoteSwitchSession(nullptr);
    }
    deathRecipient_ = nullptr;
}

std::shared_ptr<CameraSwitchCallback> CameraSwitchSession::GetCameraSwitchCallback()
{
    std::lock_guard<std::mutex> lock(callbackCameraSwitchMutex_);
    return appSwitchCallback_;
}
void CameraSwitchSession::CameraServerSwitchDied(pid_t pid)
{
    MEDIA_ERR_LOG("CameraSwitchSession::CameraServerSwitchDied has died, pid:%{public}d!", pid);
    RemoveSwitchDeathRecipient();
}
}  // namespace CameraStandard
}  // namespace OHOS
