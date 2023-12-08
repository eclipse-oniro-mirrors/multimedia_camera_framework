/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "hcamera_service.h"

#include <securec.h>
#include <unordered_set>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_util.h"
#include "display_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "hcamera_device_manager.h"

namespace OHOS {
namespace CameraStandard {
REGISTER_SYSTEM_ABILITY_BY_ID(HCameraService, CAMERA_SERVICE_ID, true)
constexpr int32_t SENSOR_SUCCESS = 0;
constexpr int32_t POSTURE_INTERVAL = 1000000;
constexpr uint8_t POSITION_FOLD_INNER = 3;
static sptr<HCameraService> mCameraService;

HCameraService::HCameraService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), cameraHostManager_(nullptr), streamOperatorCallback_(nullptr),
      muteMode_(false)
{}

HCameraService::~HCameraService() {}

void HCameraService::OnStart()
{
    if (cameraHostManager_ == nullptr) {
        cameraHostManager_ = new (nothrow) HCameraHostManager(this);
        CHECK_AND_RETURN_LOG(
            cameraHostManager_ != nullptr, "HCameraService OnStart failed to create HCameraHostManager obj");
    }
    if (cameraHostManager_->Init() != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService OnStart failed to init camera host manager.");
    }
    bool res = Publish(this);
    if (res) {
        MEDIA_INFO_LOG("HCameraService OnStart res=%{public}d", res);
    }
    RegisterSensorCallback();
}

void HCameraService::OnDump()
{
    MEDIA_INFO_LOG("HCameraService::OnDump called");
}

void HCameraService::OnStop()
{
    MEDIA_INFO_LOG("HCameraService::OnStop called");

    if (cameraHostManager_) {
        cameraHostManager_->DeInit();
        delete cameraHostManager_;
        cameraHostManager_ = nullptr;
    }
    if (streamOperatorCallback_) {
        streamOperatorCallback_ = nullptr;
    }
    UnRegisterSensorCallback();
}

int32_t HCameraService::GetCameras(
    vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    CAMERA_SYNC_TRACE;
    isFoldable = isFoldableInit ? isFoldable : OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    isFoldableInit = true;
    int32_t ret = cameraHostManager_->GetCameras(cameraIds);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::GetCameras failed");
        return ret;
    }
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    vector<shared_ptr<CameraMetaInfo>> cameraInfos;
    for (auto id : cameraIds) {
        ret = cameraHostManager_->GetCameraAbility(id, cameraAbility);
        if (ret != CAMERA_OK || cameraAbility == nullptr) {
            MEDIA_ERR_LOG("HCameraService::GetCameraAbility failed");
            return ret;
        }
        camera_metadata_item_t item;
        common_metadata_header_t* metadata = cameraAbility->get();
        int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_POSITION, &item);
        uint8_t cameraPosition = (ret == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_POSITION_OTHER;
        ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &item);
        uint8_t foldType = (ret == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_FOLDSCREEN_OTHER;
        if (isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT && foldType == OHOS_CAMERA_FOLDSCREEN_OTHER) {
            continue;
        }
        if (isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT && foldType == OHOS_CAMERA_FOLDSCREEN_INNER) {
            cameraPosition = POSITION_FOLD_INNER;
        }
        ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_TYPE, &item);
        camera_type_enum_t cameraType = (ret == CAM_META_SUCCESS) ?
            static_cast<camera_type_enum_t>(item.data.u8[0]) : OHOS_CAMERA_TYPE_UNSPECIFIED;
        ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
        camera_connection_type_t connectionType = (ret == CAM_META_SUCCESS) ?
            static_cast<camera_connection_type_t>(item.data.u8[0]) : OHOS_CAMERA_CONNECTION_TYPE_BUILTIN;
        ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
        bool isMirrorSupported = (ret == CAM_META_SUCCESS) ?
            ((item.data.u8[0] == 1) || (item.data.u8[0] == 0)) : false;
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CameraManager GetCameras camera ID:%s, Camera position:%d,"
                                            " Camera Type:%d, Connection Type:%d, Mirror support:%d",
            id.c_str(), cameraPosition, cameraType, connectionType, isMirrorSupported));
        cameraInfos.emplace_back(make_shared<CameraMetaInfo>(id, cameraPosition, connectionType, cameraAbility));
    }
    vector<shared_ptr<CameraMetaInfo>> choosedCameras = ChooseDeFaultCameras(cameraInfos);
    cameraIds.clear();
    cameraAbilityList.clear();
    for (const auto& camera: choosedCameras) {
        cameraIds.emplace_back(camera->cameraId);
        cameraAbilityList.emplace_back(camera->cameraAbility);
    }
    return ret;
}

vector<shared_ptr<CameraMetaInfo>> HCameraService::ChooseDeFaultCameras(vector<shared_ptr<CameraMetaInfo>> cameraInfos)
{
    vector<shared_ptr<CameraMetaInfo>> choosedCameras;
    for (auto& camera : cameraInfos) {
        if (any_of(choosedCameras.begin(), choosedCameras.end(),
            [camera](const auto& defaultCamera) {
                return (camera->connectionType != OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN &&
                    defaultCamera->position == camera->position &&
                    defaultCamera->connectionType == camera->connectionType);
            })
        ) {
            MEDIA_INFO_LOG("ChooseDeFaultCameras alreadly has default camera");
        } else {
            choosedCameras.emplace_back(camera);
        }
    }
    return choosedCameras;
}

int32_t HCameraService::CreateCameraDevice(string cameraId, sptr<ICameraDeviceService>& device)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();

    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    if (ret != CAMERA_OK) {
        return ret;
    }
    // if callerToken is invalid, will not call IsAllowedUsingPermission
    if (IsValidTokenId(callerToken) &&
        !Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken, permissionName)) {
        MEDIA_ERR_LOG("HCameraService::CreateCameraDevice is not allowed!");
        return CAMERA_ALLOC_ERROR;
    }

    lock_guard<mutex> lock(mapOperatorsLock_);
    sptr<HCameraDevice> cameraDevice = new (nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    CHECK_AND_RETURN_RET_LOG(cameraDevice != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateCameraDevice HCameraDevice allocation failed");

    // when create camera device, update mute setting truely.
    if (IsCameraMuteSupported(cameraId)) {
        if (UpdateMuteSetting(cameraDevice, muteMode_) != CAMERA_OK) {
            MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
        }
    } else {
        MEDIA_ERR_LOG("HCameraService::CreateCameraDevice MuteCamera not Supported");
    }
    cameraDevice->SetDeviceOperatorsCallback(this);
    device = cameraDevice;
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CameraManager_CreateCameraInput CameraId:%s", cameraId.c_str()));
    return CAMERA_OK;
}

int32_t HCameraService::CreateCaptureSession(sptr<ICaptureSession>& session, int32_t opMode)
{
    CAMERA_SYNC_TRACE;
    lock_guard<mutex> lock(mutex_);
    sptr<HCaptureSession> captureSession;
    if (streamOperatorCallback_ == nullptr) {
        streamOperatorCallback_ = new (nothrow) StreamOperatorCallback();
        CHECK_AND_RETURN_RET_LOG(streamOperatorCallback_ != nullptr, CAMERA_ALLOC_ERROR,
            "HCameraService::CreateCaptureSession streamOperatorCallback_ allocation failed");
    }

    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    captureSession =
        new (nothrow) HCaptureSession(cameraHostManager_, streamOperatorCallback_, callerToken, opMode);
    CHECK_AND_RETURN_RET_LOG(captureSession != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateCaptureSession HCaptureSession allocation failed");
    captureSession->SetDeviceOperatorsCallback(this);
    session = captureSession;
    return CAMERA_OK;
}

int32_t HCameraService::CreatePhotoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
    int32_t height, sptr<IStreamCapture>& photoOutput)
{
    CAMERA_SYNC_TRACE;
    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraService::CreatePhotoOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    sptr<HStreamCapture> streamCapture = new (nothrow) HStreamCapture(producer, format, width, height);
    CHECK_AND_RETURN_RET_LOG(streamCapture != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreatePhotoOutput HStreamCapture allocation failed");
    POWERMGR_SYSEVENT_CAMERA_CONFIG(PHOTO, producer->GetDefaultWidth(), producer->GetDefaultHeight());
    photoOutput = streamCapture;
    return CAMERA_OK;
}

int32_t HCameraService::CreateDeferredPreviewOutput(
    int32_t format, int32_t width, int32_t height, sptr<IStreamRepeat>& previewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamRepeat> streamDeferredPreview;

    if ((width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraService::CreateDeferredPreviewOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    streamDeferredPreview = new (nothrow) HStreamRepeat(nullptr, format, width, height, RepeatStreamType::PREVIEW);
    CHECK_AND_RETURN_RET_LOG(streamDeferredPreview != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateDeferredPreviewOutput HStreamRepeat allocation failed");
    previewOutput = streamDeferredPreview;
    return CAMERA_OK;
}

int32_t HCameraService::CreatePreviewOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
    int32_t height, sptr<IStreamRepeat>& previewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamRepeat> streamRepeatPreview;

    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraService::CreatePreviewOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    streamRepeatPreview = new (nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);
    CHECK_AND_RETURN_RET_LOG(streamRepeatPreview != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreatePreviewOutput HStreamRepeat allocation failed");
    POWERMGR_SYSEVENT_CAMERA_CONFIG(PREVIEW, width, height);
    previewOutput = streamRepeatPreview;
    return CAMERA_OK;
}

int32_t HCameraService::CreateMetadataOutput(
    const sptr<OHOS::IBufferProducer>& producer, int32_t format, sptr<IStreamMetadata>& metadataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamMetadata> streamMetadata;

    if (producer == nullptr) {
        MEDIA_ERR_LOG("HCameraService::CreateMetadataOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    streamMetadata = new (nothrow) HStreamMetadata(producer, format);
    CHECK_AND_RETURN_RET_LOG(streamMetadata != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateMetadataOutput HStreamMetadata allocation failed");

    POWERMGR_SYSEVENT_CAMERA_CONFIG(METADATA, producer->GetDefaultWidth(), producer->GetDefaultHeight());
    metadataOutput = streamMetadata;
    return CAMERA_OK;
}

int32_t HCameraService::CreateVideoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
    int32_t height, sptr<IStreamRepeat>& videoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamRepeat> streamRepeatVideo;

    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraService::CreateVideoOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    streamRepeatVideo = new (nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::VIDEO);
    CHECK_AND_RETURN_RET_LOG(streamRepeatVideo != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateVideoOutput HStreamRepeat allocation failed");

    POWERMGR_SYSEVENT_CAMERA_CONFIG(VIDEO, producer->GetDefaultWidth(), producer->GetDefaultHeight());
    videoOutput = streamRepeatVideo;
    return CAMERA_OK;
}

void HCameraService::OnCameraStatus(const string& cameraId, CameraStatus status)
{
    lock_guard<mutex> lock(cbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnCameraStatus "
                   "callbacks.size = %{public}zu, cameraId = %{public}s, status = %{public}d, pid = %{public}d",
        cameraServiceCallbacks_.size(), cameraId.c_str(), status, IPCSkeleton::GetCallingPid());
    for (auto it : cameraServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnCameraStatus cameraServiceCallback is null, pid = %{public}d",
                IPCSkeleton::GetCallingPid());
            continue;
        } else {
            it.second->OnCameraStatusChanged(cameraId, status);
        }
        CAMERA_SYSEVENT_BEHAVIOR(
            CreateMsg("OnCameraStatusChanged! for cameraId:%s, current Camera Status:%d", cameraId.c_str(), status));
    }
}

void HCameraService::OnFlashlightStatus(const string& cameraId, FlashStatus status)
{
    lock_guard<mutex> lock(cbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnFlashlightStatus "
                   "callbacks.size = %{public}zu, cameraId = %{public}s, status = %{public}d, pid = %{public}d",
        cameraServiceCallbacks_.size(), cameraId.c_str(), status, IPCSkeleton::GetCallingPid());
    for (auto it : cameraServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnCameraStatus cameraServiceCallback is null, pid = %{public}d",
                IPCSkeleton::GetCallingPid());
            continue;
        } else {
            it.second->OnFlashlightStatusChanged(cameraId, status);
        }
    }
}

void HCameraService::OnTorchStatus(TorchStatus status)
{
    lock_guard<mutex> lock(torchCbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnTorchtStatus "
                   "callbacks.size = %{public}zu,  status = %{public}d, pid = %{public}d",
        torchServiceCallbacks_.size(), status, IPCSkeleton::GetCallingPid());
    for (auto it : torchServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnTorchtStatus torchServiceCallback is null, pid = %{public}d",
                IPCSkeleton::GetCallingPid());
            continue;
        } else {
            it.second->OnTorchStatusChange(status);
        }
    }
}

int32_t HCameraService::SetCallback(sptr<ICameraServiceCallback>& callback)
{
    lock_guard<mutex> lock(cbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetCallback pid = %{public}d", pid);
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraService::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    auto callbackItem = cameraServiceCallbacks_.find(pid);
    if (callbackItem != cameraServiceCallbacks_.end()) {
        callbackItem->second = nullptr;
        (void)cameraServiceCallbacks_.erase(callbackItem);
    }
    cameraServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::CloseCameraForDestory(pid_t pid)
{
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    sptr<HCameraDevice> deviceNeedClose = deviceManager->GetCameraByPid(pid);
    if (deviceNeedClose != nullptr) {
        deviceNeedClose->CloseDevice();
    }
    return CAMERA_OK;
}

int32_t HCameraService::UnSetMuteCallback(pid_t pid)
{
    lock_guard<mutex> lock(muteCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback pid = %{public}d, size = %{public}zu", pid,
        cameraMuteServiceCallbacks_.size());
    if (!cameraMuteServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::UnSetMuteCallback cameraMuteServiceCallbacks_ is not empty, reset it");
        auto it = cameraMuteServiceCallbacks_.find(pid);
        if ((it != cameraMuteServiceCallbacks_.end()) && (it->second)) {
            it->second = nullptr;
            cameraMuteServiceCallbacks_.erase(it);
        }
    }

    MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback after erase pid = %{public}d, size = %{public}zu", pid,
        cameraMuteServiceCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::UnSetCallback(pid_t pid)
{
    lock_guard<mutex> lock(cbMutex_);
    MEDIA_INFO_LOG(
        "HCameraService::UnSetCallback pid = %{public}d, size = %{public}zu", pid, cameraServiceCallbacks_.size());
    if (!cameraServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::SetStatusCallback statusSvcCallbacks_ is not empty, reset it");
        auto it = cameraServiceCallbacks_.find(pid);
        if ((it != cameraServiceCallbacks_.end()) && (it->second != nullptr)) {
            it->second = nullptr;
            cameraServiceCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetCallback after erase pid = %{public}d, size = %{public}zu", pid,
        cameraServiceCallbacks_.size());
    int32_t ret = CAMERA_OK;
    ret = UnSetMuteCallback(pid);
    UnSetTorchCallback(pid);
    return ret;
}

int32_t HCameraService::SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    lock_guard<mutex> lock(muteCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraService::SetMuteCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    cameraMuteServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::SetTorchCallback(sptr<ITorchServiceCallback>& callback)
{
    lock_guard<mutex> lock(torchCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraService::SetTorchCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    torchServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::UnSetTorchCallback(pid_t pid)
{
    lock_guard<mutex> lock(torchCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback pid = %{public}d, size = %{public}zu", pid,
        torchServiceCallbacks_.size());
    if (!torchServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::UnSetTorchCallback torchServiceCallbacks_ is not empty, reset it");
        auto it = torchServiceCallbacks_.find(pid);
        if ((it != torchServiceCallbacks_.end()) && (it->second)) {
            it->second = nullptr;
            torchServiceCallbacks_.erase(it);
        }
    }

    MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback after erase pid = %{public}d, size = %{public}zu", pid,
        torchServiceCallbacks_.size());
    return CAMERA_OK;
}

bool HCameraService::IsCameraMuteSupported(string cameraId)
{
    bool isMuteSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::IsCameraMuted GetCameraAbility failed");
        return false;
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_MUTE_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            MEDIA_INFO_LOG("OHOS_ABILITY_MUTE_MODES %{public}d th is %{public}d", i, item.data.u8[i]);
            if (item.data.u8[i] == OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK) {
                isMuteSupported = true;
                break;
            }
        }
    } else {
        isMuteSupported = false;
        MEDIA_ERR_LOG("HCameraService::IsCameraMuted not find MUTE ability");
    }
    MEDIA_DEBUG_LOG("HCameraService::IsCameraMuted supported: %{public}d", isMuteSupported);
    return isMuteSupported;
}

int32_t HCameraService::UpdateMuteSetting(sptr<HCameraDevice> cameraDevice, bool muteMode)
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    bool status = false;
    int32_t ret;
    int32_t count = 1;
    uint8_t mode = muteMode ? OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK : OHOS_CAMERA_MUTE_MODE_OFF;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("UpdateMuteSetting muteMode: %{public}d", muteMode);

    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_MUTE_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    }
    ret = cameraDevice->UpdateSetting(changedMetadata);
    if (!status || ret != CAMERA_OK) {
        MEDIA_ERR_LOG("UpdateMuteSetting muteMode Failed");
        return CAMERA_UNKNOWN_ERROR;
    }
    return CAMERA_OK;
}

int32_t HCameraService::MuteCamera(bool muteMode)
{
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = CheckPermission(OHOS_PERMISSION_MANAGE_CAMERA_CONFIG, callerToken);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CheckPermission is failed!");
        return ret;
    }

    bool oldMuteMode = muteMode_;
    if (muteMode == oldMuteMode) {
        return CAMERA_OK;
    } else {
        muteMode_ = muteMode;
    }
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    pid_t activeClient = deviceManager->GetActiveClient();
    if (activeClient == -1) {
        lock_guard<mutex> lock(muteCbMutex_);
        if (!cameraMuteServiceCallbacks_.empty()) {
            for (auto cb : cameraMuteServiceCallbacks_) {
                cb.second->OnCameraMute(muteMode);
                CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraMute! current Camera muteMode:%d", muteMode));
            }
        }
        return CAMERA_OK;
    }
    sptr<HCameraDevice> activeDevice = deviceManager->GetCameraByPid(activeClient);
    if (activeDevice != nullptr) {
        string cameraId = activeDevice->GetCameraId();
        if (!IsCameraMuteSupported(cameraId)) {
            MEDIA_ERR_LOG("Not Supported Mute,cameraId: %{public}s", cameraId.c_str());
            return CAMERA_UNSUPPORTED;
        }
        if (activeDevice != nullptr) {
            ret = UpdateMuteSetting(activeDevice, muteMode);
        }
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
            muteMode_ = oldMuteMode;
        }
    }
    lock_guard<mutex> lock(muteCbMutex_);
    if (!cameraMuteServiceCallbacks_.empty() && ret == CAMERA_OK) {
        for (auto cb : cameraMuteServiceCallbacks_) {
            if (cb.second) {
                cb.second->OnCameraMute(muteMode);
            }
            CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraMute! current Camera muteMode:%d", muteMode));
        }
    }
    return ret;
}

int32_t HCameraService::PrelaunchCamera()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera");
    if (preCameraId_.empty()) {
        vector<string> cameraIds_;
        cameraHostManager_->GetCameras(cameraIds_);
        if (cameraIds_.empty()) {
            return CAMERA_OK;
        }
        preCameraId_ = cameraIds_.front();
    }
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera preCameraId_ is: %{public}s", preCameraId_.c_str());
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("Camera Prelaunch CameraId:%s", preCameraId_.c_str()));
    int32_t ret = cameraHostManager_->Prelaunch(preCameraId_);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::Prelaunch failed");
    }
    return ret;
}

int32_t HCameraService::SetPrelaunchConfig(string cameraId)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::SetPrelaunchConfig failed permission is: %{public}s", permissionName.c_str());
        return ret;
    }

    MEDIA_INFO_LOG("HCameraService::SetPrelaunchConfig");
    vector<string> cameraIds_;
    cameraHostManager_->GetCameras(cameraIds_);
    if ((find(cameraIds_.begin(), cameraIds_.end(), cameraId) != cameraIds_.end()) && IsPrelaunchSupported(cameraId)) {
        preCameraId_ = cameraId;
    } else {
        MEDIA_ERR_LOG("HCameraService::SetPrelaunchConfig illegal");
        ret = CAMERA_INVALID_ARG;
    }
    return ret;
}

int32_t HCameraService::SetTorchLevel(float level)
{
    int32_t ret = cameraHostManager_->SetTorchLevel(level);
    if (ret != CAMERA_OK) {
        MEDIA_DEBUG_LOG("Failed to SetTorchLevel");
    }
    return ret;
}

bool HCameraService::IsPrelaunchSupported(string cameraId)
{
    bool isPrelaunchSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::IsCameraMuted GetCameraAbility failed");
        return isPrelaunchSupported;
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    if (ret == 0) {
        MEDIA_INFO_LOG(
            "CameraManager::IsPrelaunchSupported() OHOS_ABILITY_PRELAUNCH_AVAILABLE is %{public}d", item.data.u8[0]);
        isPrelaunchSupported = (item.data.u8[0] == 1);
    } else {
        MEDIA_ERR_LOG("Failed to get OHOS_ABILITY_PRELAUNCH_AVAILABLE ret = %{public}d", ret);
    }
    return isPrelaunchSupported;
}

int32_t HCameraService::IsCameraMuted(bool& muteMode)
{
    muteMode = muteMode_;
    MEDIA_DEBUG_LOG("HCameraService::IsCameraMuted success. isMuted: %{public}d", muteMode);
    return CAMERA_OK;
}

void HCameraService::CameraSummary(vector<string> cameraIds, string& dumpString)
{
    dumpString += "# Number of Cameras:[" + to_string(cameraIds.size()) + "]:\n";
    dumpString += "# Number of Active Cameras:[" + to_string(1) + "]:\n";
    HCaptureSession::CameraSessionSummary(dumpString);
}

void HCameraService::CameraDumpAbility(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Camera Ability List: \n";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_POSITION, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraPos.find(item.data.u8[0]);
        if (iter != g_cameraPos.end()) {
            dumpString += "        Camera Position:["
                + iter->second
                + "]:    ";
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraType.find(item.data.u8[0]);
        if (iter != g_cameraType.end()) {
            dumpString += "Camera Type:["
                + iter->second
                + "]:    ";
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraConType.find(item.data.u8[0]);
        if (iter != g_cameraConType.end()) {
            dumpString += "Camera Connection Type:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpStreaminfo(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    constexpr uint32_t unitLen = 3;
    uint32_t widthOffset = 1;
    uint32_t heightOffset = 2;
    dumpString += "        ### Camera Available stream configuration List: \n";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry,
                                               OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    if (ret == CAM_META_SUCCESS) {
        dumpString += "            Number Stream Info: "
            + to_string(item.count/unitLen) + "\n";
        for (uint32_t index = 0; index < item.count; index += unitLen) {
            map<int, string>::const_iterator iter =
                g_cameraFormat.find(item.data.i32[index]);
            if (iter != g_cameraFormat.end()) {
                dumpString += "            Format:["
                        + iter->second
                        + "]:    ";
                dumpString += "Size:[Width:"
                        + to_string(item.data.i32[index + widthOffset])
                        + " Height:"
                        + to_string(item.data.i32[index + heightOffset])
                        + "]:\n";
            }
        }
    }
}

void HCameraService::CameraDumpZoom(common_metadata_header_t* metadataEntry, string& dumpString)
{
    dumpString += "    ## Zoom Related Info: \n";
    camera_metadata_item_t item;
    int ret;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    uint32_t zoomRangeCount = 2;
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_CAP, &item);
    if ((ret == CAM_META_SUCCESS) && (item.count == zoomRangeCount)) {
        dumpString += "        Available Zoom Capability:["
            + to_string(item.data.i32[minIndex]) + "  "
            + to_string(item.data.i32[maxIndex])
            + "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    if ((ret == CAM_META_SUCCESS) && (item.count == zoomRangeCount)) {
        dumpString += "        Available scene Zoom Capability:["
            + to_string(item.data.i32[minIndex]) + "  "
            + to_string(item.data.i32[maxIndex])
            + "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    if ((ret == CAM_META_SUCCESS) && (item.count == zoomRangeCount)) {
        dumpString += "        Available Zoom Ratio Range:["
            + to_string(item.data.f[minIndex])
            + to_string(item.data.f[maxIndex])
            + "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret == CAM_META_SUCCESS) {
        dumpString += "        Set Zoom Ratio:["
            + to_string(item.data.f[0])
            + "]:\n";
    }
}

void HCameraService::CameraDumpFlash(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Flash Related Info: \n";
    dumpString += "        Available Flash Modes:[";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FLASH_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraFlashMode.find(item.data.u8[i]);
            if (iter != g_cameraFlashMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraFlashMode.find(item.data.u8[0]);
        if (iter != g_cameraFlashMode.end()) {
            dumpString += "        Set Flash Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpAF(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## AF Related Info: \n";
    dumpString += "        Available Focus Modes:[";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraFocusMode.find(item.data.u8[i]);
            if (iter != g_cameraFocusMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraFocusMode.find(item.data.u8[0]);
        if (iter != g_cameraFocusMode.end()) {
            dumpString += "        Set Focus Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpAE(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## AE Related Info: \n";
    dumpString += "        Available Exposure Modes:[";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraExposureMode.find(item.data.u8[i]);
            if (iter != g_cameraExposureMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraExposureMode.find(item.data.u8[0]);
        if (iter != g_cameraExposureMode.end()) {
            dumpString += "        Set exposure Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpSensorInfo(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Sensor Info Info: \n";
    int32_t leftIndex = 0;
    int32_t topIndex = 1;
    int32_t rightIndex = 2;
    int32_t bottomIndex = 3;
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &item);
    if (ret == CAM_META_SUCCESS) {
        dumpString += "        Array:["
            + to_string(item.data.i32[leftIndex]) + " "
            + to_string(item.data.i32[topIndex]) + " "
            + to_string(item.data.i32[rightIndex]) + " "
            + to_string(item.data.i32[bottomIndex])
            + "]:\n";
    }
}

void HCameraService::CameraDumpVideoStabilization(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Video Stabilization Related Info: \n";
    dumpString += "        Available Video Stabilization Modes:[";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraVideoStabilizationMode.find(item.data.u8[i]);
            if (iter != g_cameraVideoStabilizationMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraVideoStabilizationMode.find(item.data.u8[0]);
        if (iter != g_cameraVideoStabilizationMode.end()) {
            dumpString += "        Set Stabilization Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpVideoFrameRateRange(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    const int32_t FRAME_RATE_RANGE_STEP = 2;
    int ret;
    dumpString += "    ## Video FrameRateRange Related Info: \n";
    dumpString += "        Available FrameRateRange :\n";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FPS_RANGES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < (item.count - 1); i += FRAME_RATE_RANGE_STEP) {
            dumpString += "            [ " + to_string(item.data.i32[i]) + ", " +
                          to_string(item.data.i32[i+1]) + " ]\n";
        }
        dumpString += "\n";
    }
}

void HCameraService::CameraDumpPrelaunch(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Camera Prelaunch Related Info: \n";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraPrelaunchAvailable.find(item.data.u8[0]);
        if (iter != g_cameraPrelaunchAvailable.end()) {
            dumpString += "        Available Prelaunch Info:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpThumbnail(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Camera Thumbnail Related Info: \n";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraQuickThumbnailAvailable.find(item.data.u8[0]);
        if (iter != g_cameraQuickThumbnailAvailable.end()) {
            dumpString += "        Available Thumbnail Info:["
                + iter->second
                + "]:\n";
        }
    }
}

int32_t HCameraService::Dump(int fd, const vector<u16string>& args)
{
    unordered_set<u16string> argSets;
    u16string arg1(u"summary");
    u16string arg2(u"ability");
    u16string arg3(u"clientwiseinfo");
    for (decltype(args.size()) index = 0; index < args.size(); ++index) {
        argSets.insert(args[index]);
    }
    string dumpString;
    vector<string> cameraIds;
    vector<shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t capIdx = 0;
    shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    int ret;

    ret = GetCameras(cameraIds, cameraAbilityList);
    if ((ret != CAMERA_OK) || cameraIds.empty() || (cameraAbilityList.empty())) {
        return CAMERA_INVALID_STATE;
    }
    if (args.size() == 0 || argSets.count(arg1) != 0) {
        dumpString += "-------- Summary -------\n";
        CameraSummary(cameraIds, dumpString);
    }
    if (args.size() == 0 || argSets.count(arg2) != 0) {
        dumpString += "-------- CameraDevice -------\n";
        for (auto& it : cameraIds) {
            metadata = cameraAbilityList[capIdx++];
            common_metadata_header_t* metadataEntry = metadata->get();
            dumpString += "# Camera ID:[" + it + "]: \n";
            CameraDumpAbility(metadataEntry, dumpString);
            CameraDumpStreaminfo(metadataEntry, dumpString);
            CameraDumpZoom(metadataEntry, dumpString);
            CameraDumpFlash(metadataEntry, dumpString);
            CameraDumpAF(metadataEntry, dumpString);
            CameraDumpAE(metadataEntry, dumpString);
            CameraDumpSensorInfo(metadataEntry, dumpString);
            CameraDumpVideoStabilization(metadataEntry, dumpString);
            CameraDumpVideoFrameRateRange(metadataEntry, dumpString);
            CameraDumpPrelaunch(metadataEntry, dumpString);
            CameraDumpThumbnail(metadataEntry, dumpString);
        }
    }
    if (args.size() == 0 || argSets.count(arg3) != 0) {
        dumpString += "-------- Clientwise Info -------\n";
        HCaptureSession::dumpSessions(dumpString);
    }

    if (dumpString.size() == 0) {
        MEDIA_ERR_LOG("Dump string empty!");
        return CAMERA_INVALID_STATE;
    }

    (void)write(fd, dumpString.c_str(), dumpString.size());
    return CAMERA_OK;
}
void HCameraService::RegisterSensorCallback()
{
    mCameraService = this;
    MEDIA_INFO_LOG("HCameraService::RegisterSensorCallback start");
    user.callback = DropDetectionDataCallbackImpl;
    int32_t subscribeRet = SubscribeSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, subscribeRet: %{public}d", subscribeRet);
    int32_t setBatchRet = SetBatch(SENSOR_TYPE_ID_DROP_DETECTION, &user, POSTURE_INTERVAL, POSTURE_INTERVAL);
    MEDIA_INFO_LOG("RegisterSensorCallback, setBatchRet: %{public}d", setBatchRet);
    int32_t activateRet = ActivateSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, activateRet: %{public}d", activateRet);
    if (subscribeRet != SENSOR_SUCCESS || setBatchRet != SENSOR_SUCCESS || activateRet != SENSOR_SUCCESS) {
        MEDIA_INFO_LOG("RegisterSensorCallback failed.");
    }
}

void HCameraService::UnRegisterSensorCallback()
{
    int32_t deactivateRet = DeactivateSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    int32_t unsubscribeRet = UnsubscribeSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    if (deactivateRet == SENSOR_SUCCESS && unsubscribeRet == SENSOR_SUCCESS) {
        MEDIA_INFO_LOG("HCameraService.UnRegisterSensorCallback success.");
    }
}

void HCameraService::DropDetectionDataCallbackImpl(SensorEvent *event)
{
    if (event == nullptr) {
        MEDIA_INFO_LOG("SensorEvent is nullptr.");
        return;
    }
    if (event[0].data == nullptr) {
        MEDIA_INFO_LOG("SensorEvent[0].data is nullptr.");
        return;
    }
    if (event[0].dataLen < sizeof(DropDetectionData)) {
        MEDIA_INFO_LOG("less than drop detection data size, event.dataLen:%{public}u", event[0].dataLen);
        return;
    }
    DropDetectionData *dropDetectionData = reinterpret_cast<DropDetectionData *>(event[0].data);
    if (dropDetectionData == nullptr) {
        MEDIA_INFO_LOG("dropDetectionData is nullptr");
        return;
    }
    MEDIA_DEBUG_LOG("sensorId:%{public}d, version:%{public}d, dataLen:%{public}u, status:%{public}f",
        event[0].sensorTypeId, event[0].version, event[0].dataLen, dropDetectionData->status);

    if (mCameraService != nullptr && mCameraService->cameraHostManager_) {
        mCameraService->cameraHostManager_->NotifyDeviceStateChangeInfo(DeviceType::FALLING_TYPE,
            FallingState::FALLING_STATE);
    }
}
} // namespace CameraStandard
} // namespace OHOS
