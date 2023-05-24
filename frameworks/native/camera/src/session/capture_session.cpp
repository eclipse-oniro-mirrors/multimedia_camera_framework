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

#include "session/capture_session.h"
#include "camera_util.h"
#include "hcapture_session_callback_stub.h"
#include "input/camera_input.h"
#include "camera_log.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"

namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr int32_t DEFAULT_ITEMS = 10;
    constexpr int32_t DEFAULT_DATA_LENGTH = 100;
}

const std::unordered_map<camera_focus_state_t, FocusCallback::FocusState> CaptureSession::metaToFwFocusState_ = {
    {OHOS_CAMERA_FOCUS_STATE_SCAN, FocusCallback::SCAN},
    {OHOS_CAMERA_FOCUS_STATE_FOCUSED, FocusCallback::FOCUSED},
    {OHOS_CAMERA_FOCUS_STATE_UNFOCUSED, FocusCallback::UNFOCUSED}
};

const std::unordered_map<camera_exposure_state_t,
        ExposureCallback::ExposureState> CaptureSession::metaToFwExposureState_ = {
    {OHOS_CAMERA_EXPOSURE_STATE_SCAN, ExposureCallback::SCAN},
    {OHOS_CAMERA_EXPOSURE_STATE_CONVERGED, ExposureCallback::CONVERGED}
};

const std::unordered_map<camera_exposure_mode_enum_t, ExposureMode> CaptureSession::metaToFwExposureMode_ = {
    {OHOS_CAMERA_EXPOSURE_MODE_LOCKED, EXPOSURE_MODE_LOCKED},
    {OHOS_CAMERA_EXPOSURE_MODE_AUTO, EXPOSURE_MODE_AUTO},
    {OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO, EXPOSURE_MODE_CONTINUOUS_AUTO}
};

const std::unordered_map<ExposureMode, camera_exposure_mode_enum_t> CaptureSession::fwToMetaExposureMode_ = {
    {EXPOSURE_MODE_LOCKED, OHOS_CAMERA_EXPOSURE_MODE_LOCKED},
    {EXPOSURE_MODE_AUTO, OHOS_CAMERA_EXPOSURE_MODE_AUTO},
    {EXPOSURE_MODE_CONTINUOUS_AUTO, OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO}
};

const std::unordered_map<camera_focus_mode_enum_t, FocusMode> CaptureSession::metaToFwFocusMode_ = {
    {OHOS_CAMERA_FOCUS_MODE_MANUAL, FOCUS_MODE_MANUAL},
    {OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO, FOCUS_MODE_CONTINUOUS_AUTO},
    {OHOS_CAMERA_FOCUS_MODE_AUTO, FOCUS_MODE_AUTO},
    {OHOS_CAMERA_FOCUS_MODE_LOCKED, FOCUS_MODE_LOCKED}
};

const std::unordered_map<FocusMode, camera_focus_mode_enum_t> CaptureSession::fwToMetaFocusMode_ = {
    {FOCUS_MODE_MANUAL, OHOS_CAMERA_FOCUS_MODE_MANUAL},
    {FOCUS_MODE_CONTINUOUS_AUTO, OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO},
    {FOCUS_MODE_AUTO, OHOS_CAMERA_FOCUS_MODE_AUTO},
    {FOCUS_MODE_LOCKED, OHOS_CAMERA_FOCUS_MODE_LOCKED}
};

const std::unordered_map<camera_flash_mode_enum_t, FlashMode> CaptureSession::metaToFwFlashMode_ = {
    {OHOS_CAMERA_FLASH_MODE_CLOSE, FLASH_MODE_CLOSE},
    {OHOS_CAMERA_FLASH_MODE_OPEN, FLASH_MODE_OPEN},
    {OHOS_CAMERA_FLASH_MODE_AUTO, FLASH_MODE_AUTO},
    {OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN, FLASH_MODE_ALWAYS_OPEN}
};

const std::unordered_map<FlashMode, camera_flash_mode_enum_t> CaptureSession::fwToMetaFlashMode_ = {
    {FLASH_MODE_CLOSE, OHOS_CAMERA_FLASH_MODE_CLOSE},
    {FLASH_MODE_OPEN, OHOS_CAMERA_FLASH_MODE_OPEN},
    {FLASH_MODE_AUTO, OHOS_CAMERA_FLASH_MODE_AUTO},
    {FLASH_MODE_ALWAYS_OPEN, OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN}
};

const std::unordered_map<CameraVideoStabilizationMode,
VideoStabilizationMode> CaptureSession::metaToFwVideoStabModes_ = {
    {OHOS_CAMERA_VIDEO_STABILIZATION_OFF, OFF},
    {OHOS_CAMERA_VIDEO_STABILIZATION_LOW, LOW},
    {OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE, MIDDLE},
    {OHOS_CAMERA_VIDEO_STABILIZATION_HIGH, HIGH},
    {OHOS_CAMERA_VIDEO_STABILIZATION_AUTO, AUTO}
};

const std::unordered_map<VideoStabilizationMode,
CameraVideoStabilizationMode> CaptureSession::fwToMetaVideoStabModes_ = {
    {OFF, OHOS_CAMERA_VIDEO_STABILIZATION_OFF},
    {LOW, OHOS_CAMERA_VIDEO_STABILIZATION_LOW},
    {MIDDLE, OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE},
    {HIGH, OHOS_CAMERA_VIDEO_STABILIZATION_HIGH},
    {AUTO, OHOS_CAMERA_VIDEO_STABILIZATION_AUTO}
};

class CaptureSessionCallback : public HCaptureSessionCallbackStub {
public:
    CaptureSession* captureSession_ = nullptr;
    CaptureSessionCallback() : captureSession_(nullptr) {
    }

    explicit CaptureSessionCallback(CaptureSession* captureSession) : captureSession_(captureSession) {
    }

    ~CaptureSessionCallback()
    {
        captureSession_ = nullptr;
    }

    int32_t OnError(int32_t errorCode) override
    {
        MEDIA_INFO_LOG("CaptureSessionCallback::OnError() is called!, errorCode: %{public}d",
                       errorCode);
        if (captureSession_ != nullptr && captureSession_->GetApplicationCallback() != nullptr) {
            captureSession_->GetApplicationCallback()->OnError(errorCode);
        } else {
            MEDIA_INFO_LOG("CaptureSessionCallback::ApplicationCallback not set!, Discarding callback");
        }
        return CameraErrorCode::SUCCESS;
    }
};

CaptureSession::CaptureSession(sptr<ICaptureSession> &captureSession)
{
    captureSession_ = captureSession;
    inputDevice_ = nullptr;
}

CaptureSession::~CaptureSession()
{
    inputDevice_ = nullptr;
    captureSession_ = nullptr;
    changedMetadata_ = nullptr;
    appCallback_ = nullptr;
    captureSessionCallback_ = nullptr;
    exposureCallback_ = nullptr;
    focusCallback_ = nullptr;
}

int32_t CaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    if (IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::BeginConfig Session is locked");
        return CameraErrorCode::SESSION_CONFIG_LOCKED;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->BeginConfig();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to BeginConfig!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::BeginConfig() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::CommitConfig()
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::CommitConfig operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->CommitConfig();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to CommitConfig!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::CommitConfig() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::CanAddInput(sptr<CaptureInput> &input)
{
    // todo: get Profile passed to createOutput and compare with OutputCapability
    // if present in capability return ok.
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::AddInput(sptr<CaptureInput> &input)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::AddInput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (input == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddInput input is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    input->SetSession(this);
    inputDevice_ = input;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->AddInput(((sptr<CameraInput> &)input)->GetCameraDevice());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to AddInput!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::AddInput() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    // todo: get Profile passed to createOutput and compare with OutputCapability
    // if present in capability return ok.
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::AddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::AddOutput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (output == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddOutput output is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    output->SetSession(this);
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
        SetFrameRateRange(static_cast<VideoOutput *>(output.GetRefPtr())->GetFrameRateRange());
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->AddOutput(output->GetStreamType(), output->GetStream());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to AddOutput!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::AddOutput() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::RemoveInput(sptr<CaptureInput> &input)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (input == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput input is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    if (inputDevice_ != nullptr) {
        inputDevice_ = nullptr;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->RemoveInput(((sptr<CameraInput> &)input)->GetCameraDevice());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to RemoveInput!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::RemoveOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (output == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput output is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    output->SetSession(nullptr);
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->RemoveOutput(output->GetStreamType(), output->GetStream());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to RemoveOutput!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Start()
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::Start Session not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->Start();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to Start capture session!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::Start() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Stop()
{
    CAMERA_SYNC_TRACE;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->Stop();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to Stop capture session!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::Stop() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Release()
{
    CAMERA_SYNC_TRACE;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->Release(0);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to Release capture session!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::Release() captureSession_ is nullptr");
    }
    inputDevice_ = nullptr;
    captureSession_ = nullptr;
    captureSessionCallback_ = nullptr;
    changedMetadata_ = nullptr;
    appCallback_ = nullptr;
    exposureCallback_ = nullptr;
    focusCallback_ = nullptr;
    return ServiceToCameraError(errCode);
}

void CaptureSession::SetCallback(std::shared_ptr<SessionCallback> callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetCallback: Unregistering application callback!");
    }
    int32_t errorCode = CAMERA_OK;

    appCallback_ = callback;
    if (appCallback_ != nullptr && captureSession_ != nullptr) {
        if (captureSessionCallback_ == nullptr) {
            captureSessionCallback_ = new(std::nothrow) CaptureSessionCallback(this);
        }
        if (captureSession_) {
            errorCode = captureSession_->SetCallback(captureSessionCallback_);
            if (errorCode != CAMERA_OK) {
                MEDIA_ERR_LOG("CaptureSession::SetCallback: Failed to register callback, errorCode: %{public}d",
                    errorCode);
                captureSessionCallback_ = nullptr;
                appCallback_ = nullptr;
            }
        } else {
            MEDIA_ERR_LOG("CaptureSession::SetCallback() captureSession_ is nullptr");
        }
    }
    return;
}

std::shared_ptr<SessionCallback> CaptureSession::GetApplicationCallback()
{
    return appCallback_;
}

int32_t CaptureSession::UpdateSetting(std::shared_ptr<Camera::CameraMetadata> changedMetadata)
{
    CAMERA_SYNC_TRACE;
    if (!Camera::GetCameraMetadataItemCount(changedMetadata->get())) {
        MEDIA_INFO_LOG("CaptureSession::UpdateSetting No configuration to update");
        return CameraErrorCode::SUCCESS;
    }

    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed Session Not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !((sptr<CameraInput> &)inputDevice_)->GetCameraDevice()) {
        MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed inputDevice_ is nullptr");
        return CameraErrorCode::SUCCESS;
    }
    int32_t ret = ((sptr<CameraInput> &)inputDevice_)->GetCameraDevice()->UpdateSetting(changedMetadata);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed to update settings, errCode = %{public}d", ret);
        return ServiceToCameraError(ret);
    }

    uint32_t count = changedMetadata->get()->item_count;
    uint8_t* data = Camera::GetMetadataData(changedMetadata->get());
    camera_metadata_item_entry_t* itemEntry = Camera::GetMetadataItems(changedMetadata->get());
    std::shared_ptr<Camera::CameraMetadata> baseMetadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    for (uint32_t i = 0; i < count; i++, itemEntry++) {
        bool status = false;
        camera_metadata_item_t item;
        size_t length = Camera::CalculateCameraMetadataItemDataSize(itemEntry->data_type, itemEntry->count);
        ret = Camera::FindCameraMetadataItem(baseMetadata->get(), itemEntry->item, &item);
        if (ret == CAM_META_SUCCESS) {
            status = baseMetadata->updateEntry(itemEntry->item,
                                               (length == 0) ? itemEntry->data.value : (data + itemEntry->data.offset),
                                               itemEntry->count);
        } else if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = baseMetadata->addEntry(itemEntry->item,
                                            (length == 0) ? itemEntry->data.value : (data + itemEntry->data.offset),
                                            itemEntry->count);
        }
        if (!status) {
            MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed to add/update metadata item: %{public}d",
                          itemEntry->item);
        }
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::LockForControl()
{
    changeMetaMutex_.lock();
    MEDIA_DEBUG_LOG("CaptureSession::LockForControl Called");
    changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
}

int32_t CaptureSession::UnlockForControl()
{
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::UnlockForControl Need to call LockForControl() before UnlockForControl()");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    MEDIA_DEBUG_LOG("CaptureSession::UnlockForControl Called");
    UpdateSetting(changedMetadata_);
    changedMetadata_ = nullptr;
    changeMetaMutex_.unlock();
    return CameraErrorCode::SUCCESS;
}

VideoStabilizationMode CaptureSession::GetActiveVideoStabilizationMode()
{
    sptr<CameraDevice> cameraObj_;
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return OFF;
    }
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaToFwVideoStabModes_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != metaToFwVideoStabModes_.end()) {
            return itr->second;
        }
    }
    return OFF;
}

int32_t CaptureSession::GetActiveVideoStabilizationMode(VideoStabilizationMode &mode)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    mode = OFF;
    bool isSupported = false;
    sptr<CameraDevice> cameraObj_;
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaToFwVideoStabModes_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != metaToFwVideoStabModes_.end()) {
            mode = itr->second;
            isSupported = true;
        }
    }
    if (!isSupported || ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode Failed with return code %{public}d", ret);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetVideoStabilizationMode(VideoStabilizationMode stabilizationMode)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetVideoStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto itr = fwToMetaVideoStabModes_.find(stabilizationMode);
    if ((itr == fwToMetaVideoStabModes_.end()) || !IsVideoStabilizationModeSupported(stabilizationMode)) {
        MEDIA_ERR_LOG("CaptureSession::SetVideoStabilizationMode Mode: %{public}d not supported", stabilizationMode);
        stabilizationMode = OFF;
    }

    uint32_t count = 1;
    uint8_t stabilizationMode_ = stabilizationMode;

    this->LockForControl();
    MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode StabilizationMode : %{public}d", stabilizationMode_);
    if (!(this->changedMetadata_->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &stabilizationMode_, count))) {
        MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    }

    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode)
{
    std::vector<VideoStabilizationMode> stabilizationModes = GetSupportedStabilizationMode();
    if (std::find(stabilizationModes.begin(), stabilizationModes.end(), stabilizationMode)
       != stabilizationModes.end()) {
        return true;
    }
    return false;
}

int32_t CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsVideoStabilizationModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<VideoStabilizationMode> stabilizationModes = GetSupportedStabilizationMode();
    if (std::find(stabilizationModes.begin(), stabilizationModes.end(), stabilizationMode)
       != stabilizationModes.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

std::vector<VideoStabilizationMode> CaptureSession::GetSupportedStabilizationMode()
{
    std::vector<VideoStabilizationMode> stabilizationModes;

    sptr<CameraDevice> cameraObj_;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode Session is not Commited");
        return stabilizationModes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode camera device is null");
        return stabilizationModes;
    }
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupporteStabilizationModes Failed with return code %{public}d", ret);
        return stabilizationModes;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwVideoStabModes_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[i]));
        if (itr != metaToFwVideoStabModes_.end()) {
            stabilizationModes.emplace_back(itr->second);
        }
    }
    return stabilizationModes;
}

int32_t CaptureSession::GetSupportedStabilizationMode(std::vector<VideoStabilizationMode> &stabilizationModes)
{
    sptr<CameraDevice> cameraObj_;
    stabilizationModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupporteStabilizationModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwVideoStabModes_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[i]));
        if (itr != metaToFwVideoStabModes_.end()) {
            stabilizationModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsExposureModeSupported(ExposureMode exposureMode)
{
    std::vector<ExposureMode> vecSupportedExposureModeList;
    vecSupportedExposureModeList = this->GetSupportedExposureModes();
    if (find(vecSupportedExposureModeList.begin(), vecSupportedExposureModeList.end(),
        exposureMode) != vecSupportedExposureModeList.end()) {
        return true;
    }

    return false;
}

int32_t CaptureSession::IsExposureModeSupported(ExposureMode exposureMode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsExposureModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<ExposureMode> vecSupportedExposureModeList;
    vecSupportedExposureModeList = this->GetSupportedExposureModes();
    if (find(vecSupportedExposureModeList.begin(), vecSupportedExposureModeList.end(),
        exposureMode) != vecSupportedExposureModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

std::vector<ExposureMode> CaptureSession::GetSupportedExposureModes()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes camera device is null");
        return {};
    }
    std::vector<ExposureMode> supportedExposureModes;
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Failed with return code %{public}d", ret);
        return supportedExposureModes;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwExposureMode_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[i]));
        if (itr != metaToFwExposureMode_.end()) {
            supportedExposureModes.emplace_back(itr->second);
        }
    }
    return supportedExposureModes;
}

int32_t CaptureSession::GetSupportedExposureModes(std::vector<ExposureMode> &supportedExposureModes)
{
    supportedExposureModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwExposureMode_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[i]));
        if (itr != metaToFwExposureMode_.end()) {
            supportedExposureModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetExposureMode(ExposureMode exposureMode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Need to call LockForControl() "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t exposure = fwToMetaExposureMode_.at(EXPOSURE_MODE_LOCKED);
    auto itr = fwToMetaExposureMode_.find(exposureMode);
    if (itr == fwToMetaExposureMode_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        exposure = itr->second;
    }

    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &exposure, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EXPOSURE_MODE, &exposure, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Failed to set exposure mode");
    }

    return CameraErrorCode::SUCCESS;
}

ExposureMode CaptureSession::GetExposureMode()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Session is not Commited");
        return EXPOSURE_MODE_UNSUPPORTED;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode camera device is null");
        return EXPOSURE_MODE_UNSUPPORTED;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
        return EXPOSURE_MODE_UNSUPPORTED;
    }
    auto itr = metaToFwExposureMode_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[0]));
    if (itr != metaToFwExposureMode_.end()) {
        return itr->second;
    }

    return EXPOSURE_MODE_UNSUPPORTED;
}

int32_t CaptureSession::GetExposureMode(ExposureMode &exposureMode)
{
    exposureMode = EXPOSURE_MODE_UNSUPPORTED;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaToFwExposureMode_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[0]));
    if (itr != metaToFwExposureMode_.end()) {
        exposureMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}


int32_t CaptureSession::SetMeteringPoint(Point exposurePoint)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetMeteringPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetExposurePoint Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    Point exposureVerifyPoint = VerifyFocusCorrectness(exposurePoint);
    Point unifyExposurePoint = CoordinateTransform(exposureVerifyPoint);
    bool status = false;
    float exposureArea[2] = {unifyExposurePoint.x, unifyExposurePoint.y};
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AE_REGIONS, exposureArea,
            sizeof(exposureArea) / sizeof(exposureArea[0]));
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AE_REGIONS, exposureArea,
            sizeof(exposureArea) / sizeof(exposureArea[0]));
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetExposurePoint Failed to set exposure Area");
    }
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::GetMeteringPoint()
{
    Point exposurePoint = {0, 0};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint Session is not Commited");
        return exposurePoint;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint camera device is null");
        return exposurePoint;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposurePoint Failed with return code %{public}d", ret);
        return exposurePoint;
    }
    exposurePoint.x = item.data.f[0];
    exposurePoint.y = item.data.f[1];
    Point unifyExposurePoint = CoordinateTransform(exposurePoint);
    return unifyExposurePoint;
}

int32_t CaptureSession::GetMeteringPoint(Point &exposurePoint)
{
    exposurePoint.x = 0;
    exposurePoint.y = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposurePoint Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    exposurePoint.x = item.data.f[0];
    exposurePoint.y = item.data.f[1];
    exposurePoint = CoordinateTransform(exposurePoint);
    return CameraErrorCode::SUCCESS;
}

std::vector<int32_t> CaptureSession::GetExposureBiasRange()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange camera device is null");
        return {};
    }
    return inputDevice_->GetCameraDeviceInfo()->GetExposureBiasRange();
}

int32_t CaptureSession::GetExposureBiasRange(std::vector<int32_t> &exposureBiasRange)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    exposureBiasRange = inputDevice_->GetCameraDeviceInfo()->GetExposureBiasRange();
    return CameraErrorCode::SUCCESS;
}


int32_t CaptureSession::SetExposureBias(int32_t exposureValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t ret;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue exposure compensation: %{public}d", exposureValue);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::vector<int32_t> biasRange = inputDevice_->GetCameraDeviceInfo()->GetExposureBiasRange();
    if (biasRange.empty()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Bias range is empty");
        return CameraErrorCode::SUCCESS;
    }
    if (exposureValue < biasRange[minIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue bias value:"
                        "%{public}d is lesser than minimum bias: %{public}d", exposureValue, biasRange[minIndex]);
        exposureValue = biasRange[minIndex];
    } else if (exposureValue > biasRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue bias value: "
                        "%{public}d is greater than maximum bias: %{public}d", exposureValue, biasRange[maxIndex]);
        exposureValue = biasRange[maxIndex];
    }
    if (exposureValue == 0) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Invalid exposure compensation value");
        return CameraErrorCode::SUCCESS;
    }
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureValue, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureValue, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Failed to set exposure compensation");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetExposureValue()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Session is not Commited");
        return 0;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue camera device is null");
        return 0;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return 0;
    }
    return static_cast<int32_t>(item.data.i32[0]);
}

int32_t CaptureSession::GetExposureValue(int32_t &exposureValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    exposureValue = static_cast<int32_t>(item.data.i32[0]);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetExposureCallback(std::shared_ptr<ExposureCallback> exposureCallback)
{
    exposureCallback_ = exposureCallback;
}

void CaptureSession::ProcessAutoExposureUpdates(const std::shared_ptr<Camera::CameraMetadata> &result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();

    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("exposure mode: %{public}d", item.data.u8[0]);
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_EXPOSURE_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_INFO_LOG("Exposure state: %{public}d", item.data.u8[0]);
        if (exposureCallback_ != nullptr) {
            auto itr = metaToFwExposureState_.find(static_cast<camera_exposure_state_t>(item.data.u8[0]));
            if (itr != metaToFwExposureState_.end()) {
                exposureCallback_->OnExposureState(itr->second);
            }
        }
    }
}

std::vector<FocusMode> CaptureSession::GetSupportedFocusModes()
{
    std::vector<FocusMode> supportedFocusModes = {};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return supportedFocusModes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes camera device is null");
        return supportedFocusModes;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
        return supportedFocusModes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwFocusMode_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        if (itr != metaToFwFocusMode_.end()) {
            supportedFocusModes.emplace_back(itr->second);
        }
    }
    return supportedFocusModes;
}

int32_t CaptureSession::GetSupportedFocusModes(std::vector<FocusMode> &supportedFocusModes)
{
    supportedFocusModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwFocusMode_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        if (itr != metaToFwFocusMode_.end()) {
            supportedFocusModes.emplace_back(itr->second);
            return CameraErrorCode::SUCCESS;
        }
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetFocusCallback(std::shared_ptr<FocusCallback> focusCallback)
{
    focusCallback_ = focusCallback;
    return;
}

bool CaptureSession::IsFocusModeSupported(FocusMode focusMode)
{
    std::vector<FocusMode> vecSupportedFocusModeList;
    vecSupportedFocusModeList = this->GetSupportedFocusModes();
    if (find(vecSupportedFocusModeList.begin(), vecSupportedFocusModeList.end(),
        focusMode) != vecSupportedFocusModeList.end()) {
        return true;
    }

    return false;
}

int32_t CaptureSession::IsFocusModeSupported(FocusMode focusMode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<FocusMode> vecSupportedFocusModeList;
    vecSupportedFocusModeList = this->GetSupportedFocusModes();
    if (find(vecSupportedFocusModeList.begin(), vecSupportedFocusModeList.end(),
        focusMode) != vecSupportedFocusModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::StartFocus(FocusMode focusMode)
{
    bool status = false;
    int32_t ret;
    static int32_t triggerId = 0;
    uint32_t count = 1;
    uint8_t trigger = OHOS_CAMERA_AF_TRIGGER_START;
    camera_metadata_item_t item;

    if (focusMode == FOCUS_MODE_MANUAL) {
        return CameraErrorCode::SUCCESS;
    }

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AF_TRIGGER, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AF_TRIGGER, &trigger, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AF_TRIGGER, &trigger, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::StartFocus Failed to set trigger");
        return CameraErrorCode::SUCCESS;
    }

    triggerId++;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AF_TRIGGER_ID, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AF_TRIGGER_ID, &triggerId, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AF_TRIGGER_ID, &triggerId, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Failed to set trigger Id");
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusMode(FocusMode focusMode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = fwToMetaFocusMode_.find(focusMode);
    if (itr == fwToMetaFocusMode_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        focus = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("CaptureSession::SetFocusMode Focus mode: %{public}d", focusMode);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_MODE, &focus, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FOCUS_MODE, &focus, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Failed to set focus mode");
    }
    return CameraErrorCode::SUCCESS;
}

FocusMode CaptureSession::GetFocusMode()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Session is not Commited");
        return FOCUS_MODE_MANUAL;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode camera device is null");
        return FOCUS_MODE_MANUAL;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Failed with return code %{public}d", ret);
        return FOCUS_MODE_MANUAL;
    }
    auto itr = metaToFwFocusMode_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != metaToFwFocusMode_.end()) {
        return itr->second;
    }
    return FOCUS_MODE_MANUAL;
}

int32_t CaptureSession::GetFocusMode(FocusMode &focusMode)
{
    focusMode = FOCUS_MODE_MANUAL;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaToFwFocusMode_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != metaToFwFocusMode_.end()) {
        focusMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusPoint(Point focusPoint)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusPoint Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    Point focusVerifyPoint = VerifyFocusCorrectness(focusPoint);
    Point unifyFocusPoint = CoordinateTransform(focusVerifyPoint);
    bool status = false;
    float FocusArea[2] = {unifyFocusPoint.x, unifyFocusPoint.y};
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AF_REGIONS, FocusArea,
            sizeof(FocusArea) / sizeof(FocusArea[0]));
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AF_REGIONS, FocusArea,
            sizeof(FocusArea) / sizeof(FocusArea[0]));
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusPoint Failed to set Focus Area");
    }
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::CoordinateTransform(Point point)
{
    MEDIA_DEBUG_LOG("CaptureSession::CoordinateTransform begin x: %{public}f, y: %{public}f", point.x, point.y);
    Point unifyPoint = point;
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::CoordinateTransform cameraInput is nullptr");
        return unifyPoint;
    }
    if (inputDevice_->GetCameraDeviceInfo()->GetPosition() == CAMERA_POSITION_FRONT) {
        unifyPoint.x = 1 - unifyPoint.x; // flip horizontally
    }
    MEDIA_DEBUG_LOG("CaptureSession::CoordinateTransform end x: %{public}f, y: %{public}f",
                    unifyPoint.x, unifyPoint.y);
    return unifyPoint;
}

Point CaptureSession::VerifyFocusCorrectness(Point point)
{
    MEDIA_DEBUG_LOG("CaptureSession::VerifyFocusCorrectness begin x: %{public}f, y: %{public}f", point.x, point.y);
    float minPoint = 0.0000001;
    float maxPoint = 1;
    Point VerifyPoint = point;
    if (VerifyPoint.x >= -minPoint && VerifyPoint.x <= minPoint) {
        VerifyPoint.x = minPoint;
    } else if (VerifyPoint.x > maxPoint) {
        VerifyPoint.x = maxPoint;
    }
    if (VerifyPoint.y >= -minPoint && VerifyPoint.y <= minPoint) {
        VerifyPoint.y = minPoint;
    } else if (VerifyPoint.y > maxPoint) {
        VerifyPoint.y = maxPoint;
    }
    MEDIA_DEBUG_LOG("CaptureSession::VerifyFocusCorrectness end x: %{public}f, y: %{public}f",
                    VerifyPoint.x, VerifyPoint.y);
    return VerifyPoint;
}

Point CaptureSession::GetFocusPoint()
{
    Point focusPoint = {0, 0};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Session is not Commited");
        return focusPoint;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint camera device is null");
        return focusPoint;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Failed with return code %{public}d", ret);
        return focusPoint;
    }
    focusPoint.x = item.data.f[0];
    focusPoint.y = item.data.f[1];
    Point unifyFocusPoint = CoordinateTransform(focusPoint);
    return unifyFocusPoint;
}

int32_t CaptureSession::GetFocusPoint(Point &focusPoint)
{
    focusPoint.x = 0;
    focusPoint.y = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    focusPoint.x = item.data.f[0];
    focusPoint.y = item.data.f[1];
    focusPoint = CoordinateTransform(focusPoint);
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetFocalLength()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Session is not Commited");
        return 0;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength camera device is null");
        return 0;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCAL_LENGTH, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Failed with return code %{public}d", ret);
        return 0;
    }
    return static_cast<float>(item.data.f[0]);
}

int32_t CaptureSession::GetFocalLength(float &focalLength)
{
    focalLength = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCAL_LENGTH, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    focalLength = static_cast<float>(item.data.f[0]);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessAutoFocusUpdates(const std::shared_ptr<Camera::CameraMetadata> &result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    }
    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_INFO_LOG("Focus state: %{public}d", item.data.u8[0]);
        if (focusCallback_ != nullptr) {
            auto itr = metaToFwFocusState_.find(static_cast<camera_focus_state_t>(item.data.u8[0]));
            if (itr != metaToFwFocusState_.end()) {
                focusCallback_->OnFocusState(itr->second);
            }
        }
    }
}

std::vector<FlashMode> CaptureSession::GetSupportedFlashModes()
{
    std::vector<FlashMode> supportedFlashModes = {};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Session is not Commited");
        return supportedFlashModes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes camera device is null");
        return supportedFlashModes;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
        return supportedFlashModes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwFlashMode_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[i]));
        if (itr != metaToFwFlashMode_.end()) {
            supportedFlashModes.emplace_back(itr->second);
        }
    }
    return supportedFlashModes;
}

int32_t CaptureSession::GetSupportedFlashModes(std::vector<FlashMode> &supportedFlashModes)
{
    supportedFlashModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaToFwFlashMode_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[i]));
        if (itr != metaToFwFlashMode_.end()) {
            supportedFlashModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

FlashMode CaptureSession::GetFlashMode()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Session is not Commited");
        return FLASH_MODE_CLOSE;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode camera device is null");
        return FLASH_MODE_CLOSE;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Failed with return code %{public}d", ret);
        return FLASH_MODE_CLOSE;
    }
    auto itr = metaToFwFlashMode_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaToFwFlashMode_.end()) {
        return itr->second;
    }

    return FLASH_MODE_CLOSE;
}

int32_t CaptureSession::GetFlashMode(FlashMode &flashMode)
{
    flashMode = FLASH_MODE_CLOSE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaToFwFlashMode_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaToFwFlashMode_.end()) {
        flashMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }

    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFlashMode(FlashMode flashMode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t flash = fwToMetaFlashMode_.at(FLASH_MODE_CLOSE);
    auto itr = fwToMetaFlashMode_.find(flashMode);
    if (itr == fwToMetaFlashMode_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        flash = itr->second;
    }

    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FLASH_MODE, &flash, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FLASH_MODE, &flash, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Failed to set flash mode");
        return CameraErrorCode::SUCCESS;
    }

    if (flashMode == FLASH_MODE_CLOSE) {
        POWERMGR_SYSEVENT_FLASH_OFF();
    } else {
        POWERMGR_SYSEVENT_FLASH_ON();
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsFlashModeSupported(FlashMode flashMode)
{
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (find(vecSupportedFlashModeList.begin(), vecSupportedFlashModeList.end(), flashMode) !=
        vecSupportedFlashModeList.end()) {
        return true;
    }

    return false;
}

int32_t CaptureSession::IsFlashModeSupported(FlashMode flashMode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsFlashModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (find(vecSupportedFlashModeList.begin(), vecSupportedFlashModeList.end(), flashMode) !=
        vecSupportedFlashModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::HasFlash()
{
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (vecSupportedFlashModeList.empty()) {
        return false;
    }
    return true;
}

int32_t CaptureSession::HasFlash(bool &hasFlash)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::HasFlash Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (vecSupportedFlashModeList.empty()) {
        hasFlash = false;
        return CameraErrorCode::SUCCESS;
    }
    hasFlash = true;
    return CameraErrorCode::SUCCESS;
}

std::vector<float> CaptureSession::GetZoomRatioRange()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange camera device is null");
        return {};
    }
    return inputDevice_->GetCameraDeviceInfo()->GetZoomRatioRange();
}

int32_t CaptureSession::GetZoomRatioRange(std::vector<float> &zoomRatioRange)
{
    zoomRatioRange.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    zoomRatioRange = inputDevice_->GetCameraDeviceInfo()->GetZoomRatioRange();
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetZoomRatio()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Session is not Commited");
        return 0;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio camera device is null");
        return 0;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Failed with return code %{public}d", ret);
        return 0;
    }
    return static_cast<float>(item.data.f[0]);
}

int32_t CaptureSession::GetZoomRatio(float &zoomRatio)
{
    zoomRatio = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    zoomRatio = static_cast<float>(item.data.f[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetCropRegion(float zoomRatio)
{
    bool status = false;
    int32_t leftIndex = 0;
    int32_t topIndex = 1;
    int32_t rightIndex = 2;
    int32_t bottomIndex = 3;
    int32_t factor = 2;
    const uint32_t arrayCount = 4;
    int32_t cropRegion[arrayCount] = {};
    camera_metadata_item_t item;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetCropRegion Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (zoomRatio == 0 || !inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetCropRegion Invalid zoom ratio or camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    int32_t ret = Camera::FindCameraMetadataItem(
        inputDevice_->GetCameraDeviceInfo()->GetMetadata()->get(), OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::SetCropRegion Failed get sensor active array, return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    if (item.count != arrayCount) {
        MEDIA_ERR_LOG("CaptureSession::SetCropRegion Invalid sensor active array size count: %{public}u", item.count);
        return CameraErrorCode::SUCCESS;
    }
    MEDIA_DEBUG_LOG("CaptureSession::SetCropRegion Sensor active array left: %{public}d, top: %{public}d, "
                    "right: %{public}d, bottom: %{public}d", item.data.i32[leftIndex], item.data.i32[topIndex],
                    item.data.i32[rightIndex], item.data.i32[bottomIndex]);
    int32_t sensorRight = item.data.i32[rightIndex];
    int32_t sensorBottom = item.data.i32[bottomIndex];
    cropRegion[leftIndex] = (sensorRight - (sensorRight / zoomRatio)) / factor;
    cropRegion[topIndex] = (sensorBottom - (sensorBottom / zoomRatio)) / factor;
    cropRegion[rightIndex] = cropRegion[leftIndex] + (sensorRight / zoomRatio);
    cropRegion[bottomIndex] = cropRegion[topIndex] + (sensorBottom / zoomRatio);
    MEDIA_DEBUG_LOG("CaptureSession::SetCropRegion Crop region left: %{public}d, top: %{public}d, "
                    "right: %{public}d, bottom: %{public}d", cropRegion[leftIndex], cropRegion[topIndex],
                    cropRegion[rightIndex], cropRegion[bottomIndex]);
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_ZOOM_CROP_REGION, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_ZOOM_CROP_REGION, cropRegion, arrayCount);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_ZOOM_CROP_REGION, cropRegion, arrayCount);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetCropRegion Failed to set zoom crop region");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetZoomRatio(float zoomRatio)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }

    bool status = false;
    int32_t ret;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f", zoomRatio);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::vector<float> zoomRange = inputDevice_->GetCameraDeviceInfo()->GetZoomRatioRange();
    if (zoomRange.empty()) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Zoom range is empty");
        return CameraErrorCode::SUCCESS;
    }
    if (zoomRatio < zoomRange[minIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f is lesser than minimum zoom: %{public}f",
                        zoomRatio, zoomRange[minIndex]);
        zoomRatio = zoomRange[minIndex];
    } else if (zoomRatio > zoomRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f is greater than maximum zoom: %{public}f",
                        zoomRatio, zoomRange[maxIndex]);
        zoomRatio = zoomRange[maxIndex];
    }

    if (zoomRatio == 0) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Invalid zoom ratio");
        return CameraErrorCode::SUCCESS;
    }

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Failed to set zoom mode");
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetCaptureMetadataObjectTypes(std::set<camera_face_detect_mode_t> metadataObjectTypes)
{
    if (inputDevice_ == nullptr) {
        MEDIA_ERR_LOG("SetCaptureMetadataObjectTypes: inputDevice is null");
        return;
    }
    uint32_t count = 0;
    uint8_t objectTypes[metadataObjectTypes.size()];
    for (const auto &type : metadataObjectTypes) {
        objectTypes[count++] = type;
    }
    this->LockForControl();
    if (!this->changedMetadata_->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, objectTypes, count)) {
        MEDIA_ERR_LOG("SetCaptureMetadataObjectTypes: Failed to add detect object types to changed metadata");
    }
    this->UnlockForControl();
}

void CaptureSession::SetFrameRateRange(const std::vector<int32_t>& frameRateRange)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("UpdateConfigSetting: inputDevice is null");
        return;
    }

    std::vector<int32_t> videoFrameRateRange = frameRateRange;
    this->LockForControl();
    if (!this->changedMetadata_->addEntry(OHOS_CONTROL_FPS_RANGES,
        videoFrameRateRange.data(), videoFrameRateRange.size())) {
        MEDIA_ERR_LOG("Failed to SetFrameRateRange");
    }
    this->UnlockForControl();
}

bool CaptureSession::IsSessionConfiged()
{
    bool isSessionConfiged = false;
    if (captureSession_) {
        CaptureSessionState currentState;
        captureSession_->GetSessionState(currentState);
        isSessionConfiged = (currentState == CaptureSessionState::SESSION_CONFIG_INPROGRESS);
    }
    return isSessionConfiged;
}

bool CaptureSession::IsSessionCommited()
{
    bool isCommitConfig = false;
    if (captureSession_) {
        CaptureSessionState currentState;
        captureSession_->GetSessionState(currentState);
        isCommitConfig = (currentState == CaptureSessionState::SESSION_CONFIG_COMMITTED);
    }
    return isCommitConfig;
}
} // CameraStandard
} // OHOS
