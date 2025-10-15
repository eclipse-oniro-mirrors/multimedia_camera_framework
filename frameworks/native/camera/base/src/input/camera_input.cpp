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

#include "input/camera_input.h"

#include <cinttypes>
#include <cstdint>
#include <mutex>
#include <securec.h>
#include <parameters.h>
#include "camera_device.h"
#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "icamera_util.h"
#include "metadata_utils.h"
#include "metadata_common_utils.h"
#include "timer/camera_deferred_timer.h"
#include "timer/time_broker.h"
#include "display_manager.h"
#include "camera_counting_timer.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_3::OperationMode;
int32_t CameraDeviceServiceCallback::OnError(const int32_t errorType, const int32_t errorMsg)
{
    std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
    auto camInputSptr = camInput_.promote();
    MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnError() is called!, errorType: %{public}d, errorMsg: %{public}d",
                  errorType, errorMsg);
    if (camInputSptr != nullptr && camInputSptr->GetErrorCallback() != nullptr) {
        int32_t serviceErrorType = ServiceToCameraError(errorType);
        camInputSptr->GetErrorCallback()->OnError(serviceErrorType, errorMsg);
    } else {
        MEDIA_INFO_LOG("CameraDeviceServiceCallback::ErrorCallback not set!, Discarding callback");
    }
    return CAMERA_OK;
}

int32_t CameraDeviceServiceCallback::OnResult(const uint64_t timestamp,
                                              const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    CHECK_RETURN_RET_ELOG(result == nullptr, CAMERA_INVALID_ARG, "OnResult get null meta from server");
    std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
    auto camInputSptr = camInput_.promote();
    CHECK_RETURN_RET_ELOG(camInputSptr == nullptr, CAMERA_OK,
        "CameraDeviceServiceCallback::OnResult() camInput_ is null!");
    auto cameraObject = camInputSptr->GetCameraDeviceInfo();
    if (cameraObject == nullptr) {
        MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnResult() camInput_->GetCameraDeviceInfo() is null!");
    } else {
        MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::OnResult()"
                        "is called!, cameraId: %{public}s, timestamp: %{public}"
                        PRIu64, cameraObject->GetID().c_str(), timestamp);
    }
    CHECK_EXECUTE(camInputSptr->GetResultCallback() != nullptr,
        camInputSptr->GetResultCallback()->OnResult(timestamp, result));

    auto pfnOcclusionDetectCallback = camInputSptr->GetOcclusionDetectCallback();
    if (pfnOcclusionDetectCallback != nullptr) {
        camera_metadata_item itemOcclusion;
        int32_t retOcclusion = OHOS::Camera::FindCameraMetadataItem(result->get(),
            OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &itemOcclusion);
        bool foundOcclusion = (retOcclusion == CAM_META_SUCCESS && itemOcclusion.count != 0);
        uint8_t occlusion = foundOcclusion ? static_cast<uint8_t>(itemOcclusion.data.i32[0]) : 0;

        camera_metadata_item itemLensDirty;
        int32_t retLensDirty = OHOS::Camera::FindCameraMetadataItem(result->get(),
            OHOS_STATUS_CAMERA_LENS_DIRTY_DETECTION, &itemLensDirty);
        bool foundLensDirty = (retLensDirty == CAM_META_SUCCESS && itemLensDirty.count != 0);
        uint8_t lensDirty = foundLensDirty ? itemLensDirty.data.u8[0] : 0;

        if (foundOcclusion || foundLensDirty) {
            MEDIA_DEBUG_LOG("occlusion found:%{public}d val:%{public}u; lensDirty found:%{public}d val:%{public}u",
                foundOcclusion, occlusion, foundLensDirty, lensDirty);
            pfnOcclusionDetectCallback->OnCameraOcclusionDetected(occlusion, lensDirty);
        }
    }

    camInputSptr->ProcessCallbackUpdates(timestamp, result);
    return CAMERA_OK;
}

CameraInput::CameraInput(sptr<ICameraDeviceService> &deviceObj,
                         sptr<CameraDevice> &cameraObj) : deviceObj_(deviceObj), cameraObj_(cameraObj)
{
    MEDIA_INFO_LOG("CameraInput::CameraInput Contructor!");
    InitCameraInput();
}

void CameraInput::GetMetadataFromService(sptr<CameraDevice> &device,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& metaData)
{
    CHECK_RETURN_ELOG(device == nullptr, "CameraInput::GetMetadataFromService device is nullptr");
    auto cameraId = device->GetID();
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "CameraInput::GetMetadataFromService serviceProxy is null");
    serviceProxy->GetCameraAbility(cameraId, metaData);
    CHECK_RETURN_ELOG(metaData == nullptr,
        "CameraInput::GetMetadataFromService GetDeviceMetadata failed");
    device->AddMetadata(metaData);
}
void CameraInput::InitCameraInput()
{
    auto cameraObj = GetCameraDeviceInfo();
    auto deviceObj = GetCameraDevice();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaData;
    if (cameraObj) {
        MEDIA_INFO_LOG("CameraInput::InitCameraInput Contructor Camera: %{public}s", cameraObj->GetID().c_str());
        GetMetadataFromService(cameraObj, metaData);
    }
    CameraDeviceSvcCallback_ = new(std::nothrow) CameraDeviceServiceCallback(this);
    CHECK_RETURN_ELOG(CameraDeviceSvcCallback_ == nullptr, "Failed to new CameraDeviceSvcCallback_!");
    CHECK_RETURN_ELOG(!deviceObj, "CameraInput::InitCameraInput() deviceObj is nullptr");
    deviceObj->SetCallback(CameraDeviceSvcCallback_);
    sptr<IRemoteObject> object = deviceObj->AsObject();
    CHECK_RETURN(object == nullptr);
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_ELOG(deathRecipient_ == nullptr, "failed to new CameraDeathRecipient.");
    auto thisPtr = wptr<CameraInput>(this);
    deathRecipient_->SetNotifyCb([thisPtr](pid_t pid) {
        auto ptr = thisPtr.promote();
        CHECK_EXECUTE(ptr != nullptr, ptr->CameraServerDied(pid));
    });
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_ELOG(!result, "CameraInput::InitCameraInput failed to add deathRecipient");

    InitDynamicOrientation(deviceObj, metaData);

    CameraCountingTimer::GetInstance().IncreaseUserCount();
}

bool CameraInput::InitDynamicOrientation(sptr<ICameraDeviceService> deviceObj,
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaData)
{
    CHECK_RETURN_RET_ELOG(deviceObj == nullptr, false, "CameraInput::InitDynamicOrientation deviceObj is nullptr");
    CHECK_RETURN_RET_ELOG(metaData == nullptr, false, "CameraInput::InitDynamicOrientation failed get metaData");

    camera_metadata_item item;
    int32_t retCode = OHOS::Camera::FindCameraMetadataItem(metaData->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_EXECUTE(retCode == CAM_META_SUCCESS && item.count,
        staticOrientation_ = static_cast<uint32_t>(item.data.i32[0]));

    CHECK_RETURN_RET_ELOG(system::GetParameter("const.system.sensor_correction_enable", "0") != "1", false,
        "CameraInput::InitDynamicOrientation variable orientation is closed");

    retCode = OHOS::Camera::FindCameraMetadataItem(metaData->get(),
        OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &item);
    CHECK_EXECUTE(retCode == CAM_META_SUCCESS, isVariable_ = item.count > 0 && item.data.u8[0]);
    CHECK_RETURN_RET_ILOG(!isVariable_, false, "CameraInput::InitDynamicOrientation do not support dynamic camera");

    retCode = OHOS::Camera::FindCameraMetadataItem(metaData->get(), OHOS_FOLD_STATE_SENSOR_ORIENTATION_MAP, &item);
    CHECK_RETURN_RET_ELOG(retCode != CAM_META_SUCCESS, false,
        "InitDynamicOrientation OHOS_FOLD_STATE_SENSOR_ORIENTATION_MAP FindCameraMetadataItem Error");
    uint32_t count = item.count;
    CHECK_RETURN_RET_ELOG(count % STEP_TWO, false, "InitDynamicOrientation FindCameraMetadataItem Count Error");
    for (uint32_t index = 0; index < count / STEP_TWO; index++) {
        uint32_t innerFoldState = static_cast<uint32_t>(item.data.i32[STEP_TWO * index]);
        uint32_t innerOrientation = static_cast<uint32_t>(item.data.i32[STEP_TWO * index + STEP_ONE]);
        foldStateSensorOrientationMap_[innerFoldState] = innerOrientation;
        MEDIA_INFO_LOG("CameraInput::InitDynamicOrientation foldStatus: %{public}d, orientation:%{public}d",
            innerFoldState, innerOrientation);
    }
    CHECK_EXECUTE(foldStateSensorOrientationMap_.empty(), isVariable_ = false);
    CHECK_RETURN_RET_ELOG(!isVariable_, false, "InitDynamicOrientation foldStateSensorOrientationMap is empty");

    bool isNaturalDirectionCorrect = false;
    deviceObj->GetNaturalDirectionCorrect(isNaturalDirectionCorrect);
    CHECK_EXECUTE(isNaturalDirectionCorrect, isVariable_ = false);
    CHECK_RETURN_RET_ELOG(!isVariable_, false, "InitDynamicOrientation isNaturalDirectionCorrect: %{public}d",
        isNaturalDirectionCorrect);

    int32_t isNeedDynamicMeta = 0;
    deviceObj->GetIsNeedDynamicMeta(isNeedDynamicMeta);
    CHECK_RETURN_RET_ELOG(isNeedDynamicMeta == 0, false,
        "CameraInput::InitDynamicOrientation do not need dynamic orientation");
    SetUsePhysicalCameraOrientation(true);
    MEDIA_INFO_LOG("CameraInput::InitDynamicOrientation need dynamic orientation");
    return true;
}

void CameraInput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    {
        std::lock_guard<std::mutex> errLock(errorCallbackMutex_);
        if (errorCallback_ != nullptr) {
            MEDIA_DEBUG_LOG("appCallback not nullptr");
            int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
            int32_t serviceErrorMsg = 0;
            MEDIA_DEBUG_LOG("serviceErrorType:%{public}d!, serviceErrorMsg:%{public}d!", serviceErrorType,
                            serviceErrorMsg);
            errorCallback_->OnError(serviceErrorType, serviceErrorMsg);
        }
    }
    std::lock_guard<std::mutex> interfaceLock(interfaceMutex_);
    InputRemoveDeathRecipient();
}

void CameraInput::InputRemoveDeathRecipient()
{
    auto deviceObj = GetCameraDevice();
    if (deviceObj != nullptr) {
        (void)deviceObj->AsObject()->RemoveDeathRecipient(deathRecipient_);
        SetCameraDevice(nullptr);
    }
    deathRecipient_ = nullptr;
}

CameraInput::~CameraInput()
{
    MEDIA_INFO_LOG("CameraInput::CameraInput Destructor!");
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        deviceObj->UnSetCallback();
    }
    UnregisterTime();
    CameraCountingTimer::GetInstance().DecreaseUserCount();
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    if (cameraObj_) {
        MEDIA_INFO_LOG("CameraInput::CameraInput Destructor Camera: %{public}s", cameraObj_->GetID().c_str());
    }
    InputRemoveDeathRecipient();
}

int CameraInput::Open()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    RecoveryOldDevice();
    UnregisterTime();
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Open");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        retCode = deviceObj->Open();
        CHECK_PRINT_ELOG(retCode != CAMERA_OK, "Failed to open Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Open() deviceObj is nullptr");
    }
    return ServiceToCameraError(retCode);
}

const std::unordered_map<CameraPosition, camera_position_enum_t> fwToMetaCameraPosition_ = {
    {CAMERA_POSITION_FRONT, OHOS_CAMERA_POSITION_FRONT},
    {CAMERA_POSITION_BACK, OHOS_CAMERA_POSITION_BACK},
    {CAMERA_POSITION_UNSPECIFIED, OHOS_CAMERA_POSITION_OTHER}
};

int32_t CameraInput::CameraDevicePhysicOpen(sptr<ICameraDeviceService> cameraDevicePhysic,
    int32_t cameraConcurrentType)
{
    MEDIA_INFO_LOG("CameraInput::cameraDevicePhysicOpen enter.");
    if (cameraDevicePhysic) {
        int32_t retCode = cameraDevicePhysic->Open(cameraConcurrentType);
        CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
            "Failed to open Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Open()with CameraConcurrentType deviceObj is nullptr");
    }
    return CAMERA_OK;
}

int CameraInput::Open(int32_t cameraConcurrentType)
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_INFO_LOG("Enter Into CameraInput::Open with CameraConcurrentType"
        " CameraConcurrentType = %{public}d", cameraConcurrentType);
    auto deviceObj = GetCameraDevice();
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObject == nullptr,
        CAMERA_DEVICE_ERROR, "CameraInput::GetCameraId cameraObject is null");
    // LCOV_EXCL_START
    CameraPosition cameraPosition = cameraObject->GetPosition();
    auto cameraServiceOnly = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(cameraServiceOnly == nullptr,
        CAMERA_UNKNOWN_ERROR, "GetMetadata Failed to get cameraProxy");

    string idOfThis;
    auto iter = fwToMetaCameraPosition_.find(cameraPosition);
    CHECK_RETURN_RET_ELOG(iter == fwToMetaCameraPosition_.end(), CAMERA_UNKNOWN_ERROR,
        "CameraInput::Open can not find cameraPosition in fwToMetaCameraPosition_");

    cameraServiceOnly->GetIdforCameraConcurrentType(iter->second, idOfThis);

    if (cameraObject->isConcurrentDeviceType() == false) {
        CameraManager::GetInstance()->SaveOldCameraId(idOfThis, cameraObject->GetID());
        std::shared_ptr<OHOS::Camera::CameraMetadata> metaData;
        auto devid = cameraObject->GetID();
        cameraServiceOnly->GetCameraAbility(devid, metaData);
        CameraManager::GetInstance()->SaveOldMeta(cameraObject->GetID(), metaData);
    }

    sptr<ICameraDeviceService> cameraDevicePhysic = nullptr;
    CameraManager::GetInstance()->CreateCameraDevice(idOfThis, &cameraDevicePhysic);
    SetCameraDevice(cameraDevicePhysic);

    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t retCode = cameraServiceOnly->GetConcurrentCameraAbility(idOfThis, cameraAbility);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "CameraInput::Open camera id: %{public}s get concurrent camera ability failed", idOfThis.c_str());

    sptr<CameraDevice> cameraObjnow = new (std::nothrow) CameraDevice(idOfThis, cameraAbility);
    CHECK_RETURN_RET_ELOG(cameraObjnow == nullptr, CAMERA_UNKNOWN_ERROR, "CameraInput::Open cameraObjnow is null");
    if (cameraConcurrentType == 0) {
        cameraObjnow->isConcurrentLimted_ = 1;
        auto itr = CameraManager::GetInstance()->cameraConLimCapMap_.find(cameraObjnow->GetID());
        CHECK_RETURN_RET_ELOG(itr == CameraManager::GetInstance()->cameraConLimCapMap_.end(), CAMERA_DEVICE_ERROR,
            "CameraInput::Open can not find CameraDevice in ConcurrentCameraMap");
        cameraObjnow->limtedCapabilitySave_ = itr->second;
    }
    std::lock_guard<std::mutex> lock2(deviceObjMutex_);
    cameraObj_ = cameraObjnow;
    cameraObj_->SetConcurrentDeviceType(true);
    CameraManager::GetInstance()->SetProfile(cameraObj_, cameraAbility);

    retCode = CameraDevicePhysicOpen(cameraDevicePhysic, cameraConcurrentType);
    return ServiceToCameraError(retCode);
    // LCOV_EXCL_STOP
}

int CameraInput::Open(bool isEnableSecureCamera, uint64_t* secureSeqId)
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::OpenSecureCamera");
    RecoveryOldDevice();
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    bool isSupportSecCamera = false;
    auto cameraObject = GetCameraDeviceInfo();
    if (isEnableSecureCamera && cameraObject) {
        // LCOV_EXCL_START
        std::vector<SceneMode> supportedModes = cameraObject->GetSupportedModes();
        CHECK_RETURN_RET_ELOG(supportedModes.empty(), retCode, "CameraInput::GetSupportedModes Failed");
        for (uint32_t i = 0; i < supportedModes.size(); i++) {
            if (supportedModes[i] == SECURE) {
                isSupportSecCamera = true;
            }
        }
        // LCOV_EXCL_STOP
    }

    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        retCode = isSupportSecCamera ? (deviceObj->OpenSecureCamera(*secureSeqId)) : (deviceObj->Open());
        CHECK_PRINT_ELOG(retCode != CAMERA_OK,
            "Failed to open Camera Input, retCode: %{public}d, isSupportSecCamera is %{public}d",
                retCode, isSupportSecCamera);
    } else {
        MEDIA_ERR_LOG("CameraInput::OpenSecureCamera() deviceObj is nullptr");
    }
    MEDIA_INFO_LOG("Enter Into CameraInput::OpenSecureCamera secureSeqId = %{public}" PRIu64, *secureSeqId);
    return ServiceToCameraError(retCode);
}

int CameraInput::Close()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    UnregisterTime();
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Close");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        deviceObj->UnSetCallback();
        retCode = deviceObj->Close();
        CHECK_PRINT_ELOG(retCode != CAMERA_OK, "Failed to close Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Close() deviceObj is nullptr");
    }
    SetCameraDeviceInfo(nullptr);
    InputRemoveDeathRecipient();
    CameraDeviceSvcCallback_ = nullptr;
    return ServiceToCameraError(retCode);
}

int CameraInput::closeDelayed(int32_t delayTime)
{
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_INFO_LOG("Enter Into CameraInput::closeDelayed");
    auto cameraObject = GetCameraDeviceInfo();
    auto deviceObj = GetCameraDevice();
    // LCOV_EXCL_START
    if (delayTime > 0 && deviceObj) {
        std::shared_ptr<Camera::CameraMetadata> metadata = std::make_shared<Camera::CameraMetadata>(1, 1);
        uint32_t count = 1;
        metadata->addEntry(OHOS_CONTROL_CAMERA_CLOSE_AFTER_SECONDS, &delayTime, count);
        deviceObj->UpdateSetting(metadata);
    }
    if (deviceObj) {
        deviceObj->UnSetCallback();
        MEDIA_INFO_LOG("CameraInput::closeDelayed() deviceObj is true");
        retCode = deviceObj->closeDelayed();
        CHECK_PRINT_ELOG(retCode != CAMERA_OK, "Failed to close closeDelayed Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::closeDelayed() deviceObj is nullptr");
    }
    // LCOV_EXCL_STOP
    auto thiswptr = wptr<CameraInput>(this);
    const int delayTaskTime = delayTime * 1000;
    UnregisterTime();
    uint32_t timeIdFirst = CameraCountingTimer::GetInstance().Register(
        [thiswptr] {
            auto input = thiswptr.promote();
            if (input) {
                MEDIA_INFO_LOG("Enter Into CameraInput::closeDelayed obj->close");
                input->Close();
            }
        },
        delayTaskTime, true);

    timeQueue_.push(timeIdFirst);
    return ServiceToCameraError(retCode);
}

void CameraInput::UnregisterTime()
{
    MEDIA_INFO_LOG("Enter Into CameraInput::UnregisterTime");
    while (!timeQueue_.empty()) {
        uint32_t timeIdFirst = timeQueue_.front();
        timeQueue_.pop();
        CameraCountingTimer::GetInstance().Unregister(timeIdFirst);
    }
}

int CameraInput::Release()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Release");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        deviceObj->UnSetCallback();
        retCode = deviceObj->Release();
        CHECK_PRINT_ELOG(retCode != CAMERA_OK, "Failed to release Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Release() deviceObj is nullptr");
    }
    SetCameraDeviceInfo(nullptr);
    InputRemoveDeathRecipient();
    CameraDeviceSvcCallback_ = nullptr;
    return ServiceToCameraError(retCode);
}

void CameraInput::SetErrorCallback(std::shared_ptr<ErrorCallback> errorCallback)
{
    CHECK_PRINT_ELOG(errorCallback == nullptr, "SetErrorCallback: Unregistering error callback");
    std::lock_guard<std::mutex> lock(errorCallbackMutex_);
    errorCallback_ = errorCallback;
    return;
}

void CameraInput::SetResultCallback(std::shared_ptr<ResultCallback> resultCallback)
{
    CHECK_PRINT_ELOG(resultCallback == nullptr, "SetResultCallback: Unregistering error resultCallback");
    MEDIA_DEBUG_LOG("CameraInput::setresult callback");
    std::lock_guard<std::mutex> lock(resultCallbackMutex_);
    resultCallback_ = resultCallback;
    return;
}
void CameraInput::SetCameraDeviceInfo(sptr<CameraDevice> cameraObj)
{
    MEDIA_DEBUG_LOG("CameraInput::SetCameraDeviceInfo");
    std::lock_guard<std::mutex> lock(cameraDeviceInfoMutex_);
    cameraObj_ = cameraObj;
    return;
}

std::map<CameraPosition, camera_position_enum> createPositionMapping()
{
    std::map<CameraPosition, camera_position_enum> enumMapping;
    enumMapping[CameraPosition::CAMERA_POSITION_UNSPECIFIED] = camera_position_enum::OHOS_CAMERA_POSITION_OTHER;
    enumMapping[CameraPosition::CAMERA_POSITION_BACK] = camera_position_enum::OHOS_CAMERA_POSITION_BACK;
    enumMapping[CameraPosition::CAMERA_POSITION_FRONT] = camera_position_enum::OHOS_CAMERA_POSITION_FRONT;
    return enumMapping;
}

void CameraInput::SetInputUsedAsPosition(CameraPosition usedAsPosition)
{
    MEDIA_INFO_LOG("CameraInput::SetInputUsedAsPosition params: %{public}u", usedAsPosition);
    std::lock_guard<std::mutex> lock(cameraDeviceInfoMutex_);
    uint8_t translatePos = OHOS_CAMERA_POSITION_OTHER;
    if (positionMapping.empty()) {
        positionMapping = createPositionMapping();
    }
    translatePos = positionMapping[usedAsPosition];

    auto metadata = std::make_shared<Camera::CameraMetadata>(1, 1);
    MEDIA_INFO_LOG("CameraInput::SetInputUsedAsPosition fr: %{public}u, to: %{public}u", usedAsPosition, translatePos);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(metadata, OHOS_CONTROL_CAMERA_USED_AS_POSITION, &translatePos, 1),
        "CameraInput::SetInputUsedAsPosition Failed to set metadata");
    auto deviceObj = GetCameraDevice();
    CHECK_RETURN_ELOG(deviceObj == nullptr, "deviceObj is nullptr");
    // LCOV_EXCL_START
    deviceObj->SetUsedAsPosition(translatePos);
    deviceObj->UpdateSetting(metadata);
    CHECK_RETURN_ELOG(cameraObj_ == nullptr, "cameraObj_ is nullptr");
    cameraObj_->SetCameraDeviceUsedAsPosition(usedAsPosition);
    // LCOV_EXCL_STOP
}


void CameraInput::ControlAuxiliary(AuxiliaryType type, AuxiliaryStatus status)
{
    MEDIA_INFO_LOG("CameraInput::ControlAuxiliary type: %{public}u, status:%{public}u", type, status);
    // LCOV_EXCL_START
    if (type == AuxiliaryType::CONTRACTLENS && status == AuxiliaryStatus::AUXILIARY_ON) {
        uint8_t value = 1;
        uint32_t count = 1;
        constexpr int32_t DEFAULT_ITEMS = 1;
        constexpr int32_t DEFAULT_DATA_LENGTH = 1;
        auto metadata = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
        CHECK_RETURN_ELOG(!AddOrUpdateMetadata(metadata, OHOS_CONTROL_EJECT_RETRY, &value, count),
            "CameraInput::ControlAuxiliary Failed to set metadata");
        auto deviceObj = GetCameraDevice();
        CHECK_RETURN_ELOG(deviceObj == nullptr, "deviceObj is nullptr");
        deviceObj->UpdateSetting(metadata);
        deviceObj->SetDeviceRetryTime();
    }
    // LCOV_EXCL_STOP
}


void CameraInput::SetOcclusionDetectCallback(
    std::shared_ptr<CameraOcclusionDetectCallback> cameraOcclusionDetectCallback)
{
    CHECK_PRINT_ELOG(cameraOcclusionDetectCallback == nullptr,
        "SetOcclusionDetectCallback: SetOcclusionDetectCallback error cameraOcclusionDetectCallback");
    MEDIA_DEBUG_LOG("CameraInput::SetOcclusionDetectCallback callback");
    std::lock_guard<std::mutex> lock(occlusionCallbackMutex_);
    cameraOcclusionDetectCallback_ = cameraOcclusionDetectCallback;
    return;
}

std::string CameraInput::GetCameraId()
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObject == nullptr, "", "CameraInput::GetCameraId cameraObject is null");
    return cameraObject->GetID();
}

sptr<ICameraDeviceService> CameraInput::GetCameraDevice()
{
    std::lock_guard<std::mutex> lock(deviceObjMutex_);
    return deviceObj_;
}

void CameraInput::SetCameraDevice(sptr<ICameraDeviceService> deviceObj)
{
    std::lock_guard<std::mutex> lock(deviceObjMutex_);
    deviceObj_ = deviceObj;
    return;
}

std::shared_ptr<ErrorCallback> CameraInput::GetErrorCallback()
{
    std::lock_guard<std::mutex> lock(errorCallbackMutex_);
    return errorCallback_;
}

std::shared_ptr<ResultCallback> CameraInput::GetResultCallback()
{
    std::lock_guard<std::mutex> lock(resultCallbackMutex_);
    MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::GetResultCallback");
    return resultCallback_;
}

std::shared_ptr<CameraOcclusionDetectCallback> CameraInput::GetOcclusionDetectCallback()
{
    std::lock_guard<std::mutex> lock(occlusionCallbackMutex_);
    return cameraOcclusionDetectCallback_;
}

sptr<CameraDevice> CameraInput::GetCameraDeviceInfo()
{
    std::lock_guard<std::mutex> lock(cameraDeviceInfoMutex_);
    return cameraObj_;
}

void CameraInput::ProcessCallbackUpdates(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto metadataResultProcessor = GetMetadataResultProcessor();
    CHECK_RETURN(metadataResultProcessor == nullptr);
    metadataResultProcessor->ProcessCallbacks(timestamp, result);
}

int32_t CameraInput::UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET(changedMetadata == nullptr, CAMERA_INVALID_ARG);
    CHECK_RETURN_RET_ELOG(!OHOS::Camera::GetCameraMetadataItemCount(changedMetadata->get()), CAMERA_OK,
        "CameraInput::UpdateSetting No configuration to update");

    std::lock_guard<std::mutex> lock(interfaceMutex_);
    auto deviceObj = GetCameraDevice();
    CHECK_RETURN_RET_ELOG(!deviceObj, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CameraInput::UpdateSetting() deviceObj is nullptr");
    int32_t ret = deviceObj->UpdateSetting(changedMetadata);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "CameraInput::UpdateSetting Failed to update settings");

    auto cameraObject = GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObject == nullptr, CAMERA_INVALID_ARG,
        "CameraInput::UpdateSetting cameraObject is null");

    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObject->GetCachedMetadata();
    bool mergeResult = MergeMetadata(changedMetadata, baseMetadata);
    CHECK_RETURN_RET_ELOG(!mergeResult, CAMERA_INVALID_ARG,
        "CameraInput::UpdateSetting() baseMetadata or itemEntry is nullptr");
    return CAMERA_OK;
}

bool CameraInput::MergeMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata,
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata)
{
    CHECK_RETURN_RET(srcMetadata == nullptr || dstMetadata == nullptr, false);
    auto srcHeader = srcMetadata->get();
    CHECK_RETURN_RET(srcHeader == nullptr, false);
    auto dstHeader = dstMetadata->get();
    CHECK_RETURN_RET(dstHeader == nullptr, false);

    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t srcItem;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &srcItem);
        CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, false,
            "Failed to get metadata item at index: %{public}d", index);
        bool status = false;
        uint32_t currentIndex;
        ret = OHOS::Camera::FindCameraMetadataItemIndex(dstMetadata->get(), srcItem.item, &currentIndex);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = dstMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        } else if (ret == CAM_META_SUCCESS) {
            status = dstMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        }
        CHECK_RETURN_RET_ELOG(!status, false, "Failed to update metadata item: %{public}d", srcItem.item);
    }
    return true;
}

std::string CameraInput::GetCameraSettings()
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObject == nullptr, nullptr, "GetCameraSettings cameraObject is null");
    return OHOS::Camera::MetadataUtils::EncodeToString(cameraObject->GetCachedMetadata());
}

int32_t CameraInput::SetCameraSettings(std::string setting)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = OHOS::Camera::MetadataUtils::DecodeFromString(setting);
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CAMERA_INVALID_ARG,
        "CameraInput::SetCameraSettings Failed to decode metadata setting from string");
    return UpdateSetting(metadata);
}

std::shared_ptr<camera_metadata_item_t> CameraInput::GetMetaSetting(uint32_t metaTag)
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObject == nullptr, nullptr,
        "CameraInput::GetMetaSetting cameraObj has release!");
    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObject->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(baseMetadata == nullptr, nullptr,
        "CameraInput::GetMetaSetting Failed to find baseMetadata");
    std::shared_ptr<camera_metadata_item_t> item = MetadataCommonUtils::GetCapabilityEntry(baseMetadata, metaTag);
    CHECK_RETURN_RET_ELOG(item == nullptr || item->count == 0, nullptr,
        "CameraInput::GetMetaSetting  Failed to find meta item: metaTag = %{public}u", metaTag);
    return item;
}

int32_t CameraInput::GetCameraAllVendorTags(std::vector<vendorTag_t> &infos) __attribute__((no_sanitize("cfi")))
{
    infos.clear();
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags called!");
    int32_t ret = OHOS::Camera::GetAllVendorTags(infos);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CAMERA_UNKNOWN_ERROR,
        "CameraInput::GetCameraAllVendorTags failed! because of hdi error, ret = %{public}d", ret);
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags success! vendors size = %{public}zu!", infos.size());
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags end!");
    return CAMERA_OK;
}

void CameraInput::SwitchCameraDevice(sptr<ICameraDeviceService> &deviceObj, sptr<CameraDevice> &cameraObj)
{
    SetCameraDeviceInfo(cameraObj);
    SetCameraDevice(deviceObj);
    InitCameraInput();
}

void CameraInput::RecoveryOldDevice()
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_RETURN_ELOG(cameraObject == nullptr, "GetCameraSettings cameraObject is null");
    if (cameraObject->isConcurrentLimted_ == 1) {
        std::string virtualcameraID = CameraManager::GetInstance()->GetOldCameraIdfromReal(cameraObject->GetID());
        if (virtualcameraID == "") {
            MEDIA_ERR_LOG("CameraInput::SetOldDevice can not GetOldCameraId,now id = %{public}s",
                cameraObject->GetID().c_str());
            virtualcameraID = cameraObject->GetID();
        } else {
            cameraObject->SetCameraId(virtualcameraID);
        }
        std::shared_ptr<OHOS::Camera::CameraMetadata> result_meta = nullptr;
        result_meta = CameraManager::GetInstance()->GetOldMeta(virtualcameraID);
        sptr<CameraDevice> cameraObjnow = new (std::nothrow) CameraDevice(virtualcameraID, result_meta);
        CHECK_RETURN_ELOG(cameraObjnow == nullptr, "RecoveryOldDevice cameraObjnow is nullptr");
        if (result_meta == nullptr) {
            MEDIA_ERR_LOG("CameraInput::SetOldDevice can not GetOldMeta");
            return;
        } else {
            SetCameraDeviceInfo(cameraObjnow);
            CameraManager::GetInstance()->SetOldMetatoInput(cameraObjnow, result_meta);
        }
        cameraObjnow->isConcurrentLimted_ = 0;
    }
}

int CameraInput::IsPhysicalCameraOrientationVariable(bool* isVariable)
{
    CHECK_RETURN_RET_ELOG(isVariable == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CameraInput::IsPhysicalCameraOrientationVariable isVariable is nullptr");
    *isVariable = isVariable_;
    MEDIA_INFO_LOG("CameraInput::IsPhysicalCameraOrientationVariable isVariable: %{public}d", *isVariable);
    return ServiceToCameraError(CAMERA_OK);
}

int CameraInput::GetPhysicalCameraOrientation(uint32_t* orientation)
{
    CHECK_RETURN_RET_ELOG(orientation == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CameraInput::GetPhysicalCameraOrientation orientation is nullptr");
    *orientation = staticOrientation_;
    if (isVariable_) {
        uint32_t curFoldStatus;
        OHOS::Rosen::FoldDisplayMode displayMode = OHOS::Rosen::DisplayManager::GetInstance().GetFoldDisplayMode();
        if (displayMode == OHOS::Rosen::FoldDisplayMode::GLOBAL_FULL) {
            curFoldStatus = static_cast<uint32_t>(OHOS::Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_EXPAND);
        } else {
            curFoldStatus = static_cast<uint32_t>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus());
        }
        auto itr = foldStateSensorOrientationMap_.find(curFoldStatus);
        CHECK_RETURN_RET_ELOG(itr == foldStateSensorOrientationMap_.end(),
            ServiceToCameraError(CAMERA_OK), "GetPhysicalCameraOrientation Get Orientation From Map Error");
        *orientation = itr->second;
    }
    return ServiceToCameraError(CAMERA_OK);
}

int CameraInput::SetUsePhysicalCameraOrientation(bool isUsed)
{
    MEDIA_INFO_LOG("CameraInput::UsePhysicalCameraOrientation isUsed: %{public}d", isUsed);
    if (!isVariable_) {
        MEDIA_ERR_LOG("CameraInput::SetUsePhysicalCameraOrientation isVariable is false");
        return ServiceToCameraError(CAMERA_OPERATION_NOT_ALLOWED);
    }
    auto cameraObj = GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG),
        "SetUsePhysicalCameraOrientation cameraObj is nullptr");
    cameraObj->SetUsePhysicalCameraOrientation(isUsed);
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        int32_t retCode = deviceObj->SetUsePhysicalCameraOrientation(isUsed);
        CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
            "SetUsePhysicalCameraOrientation is failed");
    }
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG),
        "SetUsePhysicalCameraOrientation serviceProxy is null");
    serviceProxy->SetUsePhysicalCameraOrientation(isUsed);
    return ServiceToCameraError(CAMERA_OK);
}
} // namespace CameraStandard
} // namespace OHOS
