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

#include "hcamera_switch_session.h"

#include "camera_log.h"
#include "camera_util.h"
#include "hcamera_session_manager.h"
#include "hcapture_session.h"
#include "camera_error_code.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {

HCameraSwitchSession::HCameraSwitchSession()
{
    MEDIA_INFO_LOG("HCameraSwitchSession::HCameraSwitchSession enter");
}

HCameraSwitchSession::~HCameraSwitchSession()
{
    MEDIA_INFO_LOG("HCameraSwitchSession::~HCameraSwitchSession enter");
}

int32_t HCameraSwitchSession::OnCameraActive(
    const std::string &cameraId, bool isRegisterCameraSwitchCallback, const CaptureSessionInfo &sessionInfo)
{
    MEDIA_INFO_LOG(
        "HCameraSwitchSession::OnCameraActive cameraId is: %{public}s,isRegisterCameraSwitchCallback is:%{public}d",
        cameraId.c_str(),
        isRegisterCameraSwitchCallback);
    std::lock_guard<std::mutex> lock(switchCallbackLock_);
    for (auto& switchCallback : setSwitchCallbackList_) {
        switchCallback->OnCameraActive(cameraId, isRegisterCameraSwitchCallback, sessionInfo);
    }
    return CAMERA_OK;
}

int32_t HCameraSwitchSession::OnCameraUnactive(const std::string &cameraId)
{
    MEDIA_INFO_LOG("HCameraService::OnCameraUnactive cameraId is: %{public}s", cameraId.c_str());
    std::lock_guard<std::mutex> lock(switchCallbackLock_);
    for (auto& switchCallback : setSwitchCallbackList_) {
        switchCallback->OnCameraUnactive(cameraId);
    }
    return CAMERA_OK;
}

int32_t HCameraSwitchSession::OnCameraSwitch(
    const std::string &oriCameraId, const std::string &destCameraId, bool status)
{
    MEDIA_INFO_LOG(
        "HCameraService::OnCameraSwitch oriCameraId is: %{public}s,destCameraId is:%{public}s, is:%{public}d",
        oriCameraId.c_str(),
        destCameraId.c_str(),
        status);
    std::lock_guard<std::mutex> lock(switchCallbackLock_);
    for (auto& switchCallback : setSwitchCallbackList_) {
        switchCallback->OnCameraSwitch(oriCameraId, destCameraId, status);
    }
    return CAMERA_OK;
}

int32_t HCameraSwitchSession::SetCallback(const sptr<ICameraSwitchSessionCallback> &callback)
{
    MEDIA_INFO_LOG("HCameraSwitchSession::SetCallback enter pid is:%{public}d", IPCSkeleton::GetCallingPid());
    std::lock_guard<std::mutex> lock(switchCallbackLock_);
    if (callback) {
        setSwitchCallbackList_.push_back(callback);
    }
    return CAMERA_OK;
}

int32_t HCameraSwitchSession::SwitchCamera(const std::string &oriCameraId, const std::string &destCameraId)
{
    MEDIA_INFO_LOG("HCameraSwitchSession::SwitchCamera enter, oriCameraId=%{public}s,destCameraId=%{public}s",
        oriCameraId.c_str(), destCameraId.c_str());
    std::lock_guard<std::mutex> lock(switchEnableLock_);
    captureSession_ = GetAppCameraSwitchSession();
    if (captureSession_ != nullptr) {
        sptr<ICameraSwitchSessionCallback> icameraAppSwitchSessionCallback_ =
            captureSession_->GetAppCameraSwitchCallback();
        if (icameraAppSwitchSessionCallback_ != nullptr) {
            MEDIA_INFO_LOG("HCameraSwitchSession::notify app switchCamera");
            icameraAppSwitchSessionCallback_->OnCameraUnactive(destCameraId);
            bool isSwitchSuccess = true;
            OnCameraSwitch(oriCameraId, destCameraId, isSwitchSuccess);
            return CAMERA_OK;
        }
    }
    MEDIA_INFO_LOG("HCameraSwitchSession::system forced switch");
    notRegisterCaptureSession_ = GetNotRegistCameraSwitchSession();
    CHECK_RETURN_RET_ELOG(notRegisterCaptureSession_ == nullptr,
        CAMERA_INVALID_ARG, "HCameraSwitchSession::notRegisterCaptureSession_ is nullptr.");
    sptr<HCameraDevice> cameraDevice_ = notRegisterCaptureSession_->GetCameraSwirchDevice();
    CHECK_RETURN_RET_ELOG(
        cameraDevice_ == nullptr, CAMERA_INVALID_ARG, "HCameraSwitchSession::GetCameraSwirchDevice is failed.");
    int32_t retCode = CameraErrorCode::SUCCESS;
    int32_t sensorOrientation = cameraDevice_->GetSensorOrientation();
    MEDIA_INFO_LOG("SwitchCamera::GetSensorOrientation sensorOrientation is, %{public}d", sensorOrientation);
    retCode = notRegisterCaptureSession_->Stop();
    MEDIA_INFO_LOG("SwitchCamera::Stop failed!, %{public}d", retCode);
    retCode = notRegisterCaptureSession_->BeginConfig();
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "SwitchCamera::BeginConfig failed!, %{public}d", retCode);
    retCode = notRegisterCaptureSession_->RemoveInput(cameraDevice_);
    retCode = cameraDevice_->Close();
    MEDIA_INFO_LOG("SwitchCamera::Close failed!, %{public}d", retCode);
    cameraDevice_->UpdateCameraSwitchCameraId(destCameraId);
    retCode = cameraDevice_->Open();
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "SwitchCamera::Open failed!, %{public}d", retCode);
    retCode = notRegisterCaptureSession_->AddInput(cameraDevice_);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "SwitchCamera::Open failed!, %{public}d", retCode);
    retCode = SwitchCameraUpdateSetting(cameraDevice_, sensorOrientation);
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, retCode, "SwitchCamera::SwitchCameraUpdateSetting failed!, %{public}d", retCode);
    MEDIA_INFO_LOG("HCameraSwitchSession::SwitchCamera enter, CommitConfig(),sessionId=%{public}d",
        notRegisterCaptureSession_->GetSessionId());
    retCode = notRegisterCaptureSession_->CommitConfig();
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "SwitchCamera::CommitConfig failed!, %{public}d", retCode);
    retCode = notRegisterCaptureSession_->Start();
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "SwitchCamera::Start failed!, %{public}d", retCode);
    OnCameraSwitch(oriCameraId, destCameraId, true);
    return CAMERA_OK;
}

int32_t HCameraSwitchSession::SwitchCameraUpdateSetting(
    sptr<HCameraDevice> cameraDevice_, int32_t sensorOrientation)
{
    MEDIA_INFO_LOG("HCameraSwitchSession::SwitchCameraUpdateSetting enter");
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSwitchMetadata =
    std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    camera_metadata_item_t item;
    bool status = false;
    int32_t ret;
    int32_t value = OHOS_CAMERA_SWITCH_ON;
    MEDIA_INFO_LOG("HCameraSwitchSession::SwitchCameraUpdateSetting sensorOrientation,%{public}d", sensorOrientation);
    ret = OHOS::Camera::FindCameraMetadataItem(cameraSwitchMetadata->get(), OHOS_CONTROL_REQUEST_CAMERA_SWITCH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraSwitchMetadata->addEntry(OHOS_CONTROL_REQUEST_CAMERA_SWITCH, &value, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraSwitchMetadata->updateEntry(OHOS_CONTROL_REQUEST_CAMERA_SWITCH, &value, 1);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(cameraSwitchMetadata->get(), OHOS_CONTROL_CAMERA_SWITCH_INFOS, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraSwitchMetadata->addEntry(OHOS_CONTROL_CAMERA_SWITCH_INFOS, &sensorOrientation, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraSwitchMetadata->updateEntry(OHOS_CONTROL_CAMERA_SWITCH_INFOS, &sensorOrientation, 1);
    }
    ret = cameraDevice_->UpdateSetting(cameraSwitchMetadata);
    CHECK_PRINT_ELOG(!status || ret != CameraErrorCode::SUCCESS, "SwitchCamera::UpdateSetting failed.");
    return CAMERA_OK;
}

int32_t HCameraSwitchSession::SwitchSetService(const sptr<ICameraDeviceService> &cameraDevice)
{
    MEDIA_INFO_LOG("HCameraSwitchSession::SwitchSetService enter");
    switchSetService_ = static_cast<HCameraDevice *>(cameraDevice.GetRefPtr());
    return CAMERA_OK;
}

sptr<HCaptureSession> HCameraSwitchSession::GetAppCameraSwitchSession()
{
    MEDIA_INFO_LOG("HCameraSwitchSession::GetAppCameraSwitchSession enter");
    auto &sessionManager = HCameraSessionManager::GetInstance();
    auto totalSession = sessionManager.GetTotalSession();
    for (auto &session : totalSession) {
        MEDIA_INFO_LOG(
            "HCameraSwitchSession::GetAppCameraSwitchSession  GetSessionId:%{public}d", session->GetSessionId());
        bool isFindSession = session->GetSessionId() == session->GetAppCameraSwitchSessionId();
        CHECK_RETURN_RET(isFindSession, session);
    }
    MEDIA_INFO_LOG("HCameraSwitchSession::GetAppCameraSwitchSession is null");
    return nullptr;
}
int32_t HCameraSwitchSession::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_INFO_LOG("HCameraSwitchSession::CallbackEnter enter");
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    return CAMERA_OK;
}
int32_t HCameraSwitchSession::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("HCameraSwitchSession::CallbackExit leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

sptr<HCaptureSession> HCameraSwitchSession::GetNotRegistCameraSwitchSession()
{
    MEDIA_INFO_LOG("HCameraSwitchSession::GetNotRegistCameraSwitchSession enter");
    auto &sessionManager = HCameraSessionManager::GetInstance();
    auto totalSession = sessionManager.GetTotalSession();
    for (auto &session : totalSession) {
        MEDIA_INFO_LOG(
            "HCameraSwitchSession::GetNotRegistCameraSwitchSession  GetSessionId:%{public}d", session->GetSessionId());
        bool isFindSession = session->GetSessionId() == session->GetNotRegisterCameraSwitchSessionId();
        CHECK_RETURN_RET(isFindSession, session);
    }
    MEDIA_INFO_LOG("HCameraSwitchSession::GetNotRegistCameraSwitchSession is null");
    return nullptr;
}
}  // namespace CameraStandard
}  // namespace OHOS