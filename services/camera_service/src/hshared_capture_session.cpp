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

#include "hshared_capture_session.h"
#include "camera_log.h"
#include "hstream_capture.h"
#include "hstream_depth_data.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"

namespace OHOS {
namespace CameraStandard {

std::map<std::string, sptr<HSharedCaptureSession>> HSharedCaptureSession::sharedSessionMap_;
std::mutex HSharedCaptureSession::sharedSessionMutex_;

CamServiceError HSharedCaptureSession::NewInstance(const uint32_t callerToken, int32_t opMode,
    sptr<HSharedCaptureSession>& outSession)
{
    sptr<HCaptureSession> realSession = new (std::nothrow) HCaptureSession(callerToken, opMode);
    if (realSession == nullptr) {
        MEDIA_ERR_LOG("HSharedCaptureSession::NewInstance real session allocation failed");
        return CAMERA_ALLOC_ERROR;
    }

    sptr<HSharedCaptureSession> newSession = new (std::nothrow) HSharedCaptureSession(callerToken, opMode, realSession);
    if (newSession == nullptr) {
        MEDIA_ERR_LOG("HSharedCaptureSession::NewInstance allocation failed");
        return CAMERA_ALLOC_ERROR;
    }

    outSession = newSession;
    MEDIA_INFO_LOG("HSharedCaptureSession::NewInstance created new session");
    return CAMERA_OK;
}

sptr<HSharedCaptureSession> HSharedCaptureSession::GetExistingSession(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(sharedSessionMutex_);
    auto it = sharedSessionMap_.find(cameraId);
    if (it != sharedSessionMap_.end()) {
        return it->second;
    }
    return nullptr;
}

void HSharedCaptureSession::RegisterToMap(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(sharedSessionMutex_);
    cameraId_ = cameraId;
    sharedSessionMap_[cameraId] = this;
    MEDIA_INFO_LOG("HSharedCaptureSession::RegisterToMap cameraId: %{public}s", cameraId.c_str());
}

void HSharedCaptureSession::UnregisterFromMap()
{
    std::lock_guard<std::mutex> lock(sharedSessionMutex_);
    if (!cameraId_.empty()) {
        sharedSessionMap_.erase(cameraId_);
        MEDIA_INFO_LOG("HSharedCaptureSession::UnregisterFromMap cameraId: %{public}s", cameraId_.c_str());
        cameraId_.clear();
    }
}

HSharedCaptureSession::HSharedCaptureSession(const uint32_t callerToken, int32_t opMode,
    const sptr<HCaptureSession>& realSession)
    : HCaptureSession(callerToken, opMode), realSession_(realSession)
{
    MEDIA_INFO_LOG("HSharedCaptureSession::Constructor opMode: %{public}d", opMode);
}

HSharedCaptureSession::~HSharedCaptureSession()
{
    MEDIA_INFO_LOG("HSharedCaptureSession::Destructor");
    UnregisterFromMap();
}

void HSharedCaptureSession::AddRef(pid_t pid)
{
    std::lock_guard<std::mutex> lock(refMutex_);
    refCount_[pid]++;
    MEDIA_INFO_LOG("HSharedCaptureSession::AddRef pid: %{public}d, count: %{public}u", pid, refCount_[pid]);
}

void HSharedCaptureSession::ReleaseRef(pid_t pid)
{
    bool shouldRelease = false;
    {
        std::lock_guard<std::mutex> lock(refMutex_);
        auto it = refCount_.find(pid);
        if (it != refCount_.end()) {
            if (it->second > 1) {
                it->second--;
                MEDIA_INFO_LOG("HSharedCaptureSession::ReleaseRef pid: %{public}d, count: %{public}u", pid, it->second);
                return;
            }
            refCount_.erase(it);
        }
        shouldRelease = refCount_.empty();
        MEDIA_INFO_LOG("HSharedCaptureSession::ReleaseRef pid: %{public}d, shouldRelease: %{public}d", pid,
            shouldRelease);
    }

    if (!shouldRelease) {
        return;
    }

    MEDIA_INFO_LOG("HSharedCaptureSession::ReleaseRef all clients released");
    Release();
}

HDI::Camera::V1_0::StreamSupportType HSharedCaptureSession::NeedReconfigure()
{
    if (realSession_ == nullptr) {
        return HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED;
    }
    int32_t rc = CAMERA_OK;
    auto device = realSession_->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(device == nullptr, HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED,
        "NeedReconfigure camera device is null");

    auto hStreamOperatorSptr = realSession_->GetStreamOperator();
    CHECK_RETURN_RET_ELOG(hStreamOperatorSptr == nullptr, HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED,
        "NeedReconfigure get stream operator fail");

    hStreamOperatorSptr->GetStreamOperator();
    auto hdiStreamOperator = hStreamOperatorSptr->GetHDIStreamOperator();
    CHECK_RETURN_RET_ELOG(hdiStreamOperator == nullptr, HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED,
        "NeedReconfigure get HDI stream operator fail");

    std::vector<uint8_t> modeSettings;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(device->CloneCachedSettings(), modeSettings);
    std::vector<StreamInfo_V1_5> allStreamInfos;
    rc = realSession_->GetCurrentStreamInfos(allStreamInfos);
    CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED,
        "NeedReconfigure get streamInfo err:%{public}d", rc);

    std::vector<HDI::Camera::V1_0::StreamInfo> allStreamInfosV1_0;
    for (const auto& info : allStreamInfos) {
        allStreamInfosV1_0.emplace_back(info.v1_0);
    }

    HDI::Camera::V1_0::StreamSupportType supportType;
    uint32_t major = 0;
    uint32_t minor = 0;
    hdiStreamOperator->GetVersion(major, minor);
    if (GetVersionId(major, minor) >= HDI_VERSION_ID_1_5) {
        sptr<HDI::Camera::V1_5::IStreamOperator> streamOperatorV1_5 =
            HDI::Camera::V1_5::IStreamOperator::CastFrom(hdiStreamOperator);
        if (streamOperatorV1_5 == nullptr) {
            MEDIA_WARNING_LOG("NeedReconfigure cast to V1_5 failed, fallback to raw pointer");
            streamOperatorV1_5 = static_cast<HDI::Camera::V1_5::IStreamOperator*>(hdiStreamOperator.GetRefPtr());
        }
        CHECK_RETURN_RET_ELOG(streamOperatorV1_5 == nullptr, HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED,
            "NeedReconfigure get V1_5 stream operator fail");

        rc = streamOperatorV1_5->IsStreamsSupported(static_cast<HDI::Camera::V1_0::OperationMode>(opMode_),
            modeSettings, allStreamInfosV1_0, supportType);
        CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED,
            "NeedReconfigure IsStreamsSupported failed, rc:%{public}d", rc);
    } else {
        MEDIA_WARNING_LOG("NeedReconfigure unsupported HDI version major:%{public}u minor:%{public}u", major, minor);
        return HDI::Camera::V1_0::StreamSupportType::NOT_SUPPORTED;
    }

    return supportType;
}

int32_t HSharedCaptureSession::BeginConfig()
{
    if (realSession_ != nullptr) {
        CaptureSessionState currentState = CaptureSessionState::SESSION_INIT;
        GetSessionState(currentState);

        if (currentState == CaptureSessionState::SESSION_STARTED) {
            realSession_->stateMachine_.Transfer(CaptureSessionState::SESSION_CONFIG_INPROGRESS);
            return CAMERA_OK;
        }
        return realSession_->BeginConfig();
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::BeginConfig realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::CommitConfig()
{
    if (realSession_ == nullptr) {
        MEDIA_ERR_LOG("HSharedCaptureSession::CommitConfig realSession is null");
        return CAMERA_INVALID_STATE;
    }
    realSession_->UnlinkInputAndOutputs();
    return realSession_->CommitConfig();
}

int32_t HSharedCaptureSession::CanAddInput(const sptr<ICameraDeviceService>& cameraDevice, bool& result)
{
    if (realSession_ != nullptr) {
        return realSession_->CanAddInput(cameraDevice, result);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::CanAddInput realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::AddInput(const sptr<ICameraDeviceService>& cameraDevice)
{
    if (realSession_ != nullptr) {
        return realSession_->AddInput(cameraDevice);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::AddInput realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::AddOutput(StreamType streamType, const sptr<IRemoteObject>& stream)
{
    if (realSession_ == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    CaptureSessionState currentState = CaptureSessionState::SESSION_INIT;
    realSession_->GetSessionState(currentState);
    MEDIA_INFO_LOG("HSharedCaptureSession::AddOutput pre-BeginConfig state: %{public}d", currentState);
    return realSession_->AddOutput(streamType, stream);
}

int32_t HSharedCaptureSession::AddMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput, int32_t opMode)
{
    if (realSession_ != nullptr) {
        return realSession_->AddMultiStreamOutput(multiStreamOutput, opMode);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::AddMultiStreamOutput realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::RemoveMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput)
{
    if (realSession_ != nullptr) {
        return realSession_->RemoveMultiStreamOutput(multiStreamOutput);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::RemoveMultiStreamOutput realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::RemoveInput(const sptr<ICameraDeviceService>& cameraDevice)
{
    if (realSession_ != nullptr) {
        return realSession_->RemoveInput(cameraDevice);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::RemoveInput realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::RemoveOutput(StreamType streamType, const sptr<IRemoteObject>& stream)
{
    if (realSession_ == nullptr) {
        MEDIA_ERR_LOG("HSharedCaptureSession::RemoveOutput realSession is null");
        return CAMERA_INVALID_STATE;
    }
    CHECK_RETURN_RET_ELOG(stream == nullptr, CAMERA_INVALID_ARG,
        "HSharedCaptureSession::RemoveOutput stream is null");
    sptr<IStreamCommon> streamCommonIface = nullptr;
    sptr<HStreamCommon> streamCommon = nullptr;
    if (streamType == StreamType::CAPTURE) {
        streamCommonIface = iface_cast<IStreamCapture>(stream);
        streamCommon = static_cast<HStreamCapture*>(streamCommonIface.GetRefPtr());
    } else if (streamType == StreamType::REPEAT) {
        streamCommonIface = iface_cast<IStreamRepeat>(stream);
        streamCommon = static_cast<HStreamRepeat*>(streamCommonIface.GetRefPtr());
    } else if (streamType == StreamType::METADATA) {
        streamCommonIface = iface_cast<IStreamMetadata>(stream);
        streamCommon = static_cast<HStreamMetadata*>(streamCommonIface.GetRefPtr());
    } else if (streamType == StreamType::DEPTH) {
        streamCommonIface = iface_cast<IStreamDepthData>(stream);
        streamCommon = static_cast<HStreamDepthData*>(streamCommonIface.GetRefPtr());
    }
    CHECK_RETURN_RET_ELOG(streamCommonIface == nullptr || streamCommon == nullptr, CAMERA_INVALID_ARG,
        "HSharedCaptureSession::RemoveOutput invalid stream");
    int32_t hdiStreamId = streamCommon->GetHdiStreamId();
    int32_t rc = realSession_->RemoveOutput(streamType, stream);
    CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, rc,
        "HSharedCaptureSession::RemoveOutput realSession RemoveOutput failed, rc:%{public}d", rc);
    if (streamType == StreamType::CAPTURE) {
        HStreamCapture* captureStream = static_cast<HStreamCapture*>(streamCommon.GetRefPtr());
        CHECK_RETURN_RET(captureStream != nullptr && captureStream->IsHasEnableOfflinePhoto(), CAMERA_OK);
    }
    std::vector<int32_t> releaseStreamIds;
    if (hdiStreamId != STREAM_ID_UNSET) {
        releaseStreamIds.emplace_back(hdiStreamId);
    }
    auto hStreamOperatorSptr = realSession_->GetStreamOperator();
    CHECK_RETURN_RET_ELOG(hStreamOperatorSptr == nullptr, CAMERA_INVALID_STATE,
        "HSharedCaptureSession::RemoveOutput hStreamOperator is null");
    streamCommon->ReleaseStream(true);
    CHECK_EXECUTE(!releaseStreamIds.empty(), hStreamOperatorSptr->ReleaseStreams(releaseStreamIds));
    return CAMERA_OK;
}

int32_t HSharedCaptureSession::Start()
{
    if (realSession_ != nullptr) {
        return realSession_->Start();
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::Start realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::Stop()
{
    if (realSession_ != nullptr) {
        return realSession_->Stop();
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::Stop realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::Release()
{
    std::lock_guard<std::mutex> lock(refMutex_);
    if (!refCount_.empty()) {
        MEDIA_INFO_LOG("HSharedCaptureSession::Release skipped, refCount not empty");
        return CAMERA_OK;
    }

    if (realSession_ != nullptr) {
        MEDIA_INFO_LOG("HSharedCaptureSession::Release releasing real session");
        int32_t rc = realSession_->Release();
        UnregisterFromMap();
        return rc;
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::Release realSession is null");
    UnregisterFromMap();
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetCallback(const sptr<ICaptureSessionCallback>& callback)
{
    if (realSession_ != nullptr) {
        return realSession_->SetCallback(callback);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::UnSetCallback()
{
    MEDIA_WARNING_LOG("HSharedCaptureSession::UnSetCallback ignored");
    return CAMERA_OK;
}

int32_t HSharedCaptureSession::SetPressureCallback(const sptr<IPressureStatusCallback>& callback)
{
    if (realSession_ != nullptr) {
        return realSession_->SetPressureCallback(callback);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetPressureCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::UnSetPressureCallback()
{
    if (realSession_ != nullptr) {
        return realSession_->UnSetPressureCallback();
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::UnSetPressureCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetSessionState(CaptureSessionState& sessionState)
{
    if (realSession_ != nullptr) {
        return realSession_->GetSessionState(sessionState);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetSessionState realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetActiveColorSpace(int32_t& curColorSpace)
{
    if (realSession_ != nullptr) {
        return realSession_->GetActiveColorSpace(curColorSpace);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetActiveColorSpace realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetColorSpace(int32_t curColorSpace, bool isNeedUpdate)
{
    if (realSession_ != nullptr) {
        return realSession_->SetColorSpace(curColorSpace, isNeedUpdate);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetColorSpace realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetSmoothZoom(int32_t smoothZoomType, int32_t operationMode,
    float targetZoomRatio, float& duration)
{
    if (realSession_ != nullptr) {
        return realSession_->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetSmoothZoom realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetFeatureMode(int32_t featureMode)
{
    if (realSession_ != nullptr) {
        return realSession_->SetFeatureMode(featureMode);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetFeatureMode realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::EnableMovingPhoto(bool isEnable)
{
    if (realSession_ != nullptr) {
        return realSession_->EnableMovingPhoto(isEnable);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::EnableMovingPhoto realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
    if (realSession_ != nullptr) {
        return realSession_->EnableMovingPhotoMirror(isMirror, isConfig);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::EnableMovingPhotoMirror realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetPreviewRotation(const std::string& deviceClass)
{
    if (realSession_ != nullptr) {
        return realSession_->SetPreviewRotation(deviceClass);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetPreviewRotation realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetCommitConfigFlag(bool isNeedCommitting)
{
    if (realSession_ != nullptr) {
        return realSession_->SetCommitConfigFlag(isNeedCommitting);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetCommitConfigFlag realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetHasFitedRotation(bool isHasFitedRotation)
{
    if (realSession_ != nullptr) {
        return realSession_->SetHasFitedRotation(isHasFitedRotation);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetHasFitedRotation realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::CreateRecorder(const sptr<IRemoteObject>& stream, sptr<ICameraRecorder>& recorder)
{
    if (realSession_ != nullptr) {
        return realSession_->CreateRecorder(stream, recorder);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::CreateRecorder realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetVirtualApertureMetadata(std::vector<float>& virtualApertureMetadata)
{
    if (realSession_ != nullptr) {
        return realSession_->GetVirtualApertureMetadata(virtualApertureMetadata);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetVirtualApertureMetadata realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetVirtualApertureValue(float& value)
{
    if (realSession_ != nullptr) {
        return realSession_->GetVirtualApertureValue(value);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetVirtualApertureValue realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetVirtualApertureValue(float value, bool needPersist)
{
    if (realSession_ != nullptr) {
        return realSession_->SetVirtualApertureValue(value, needPersist);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetVirtualApertureValue realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetBeautyMetadata(std::vector<int32_t>& beautyApertureMetadata)
{
    if (realSession_ != nullptr) {
        return realSession_->GetBeautyMetadata(beautyApertureMetadata);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetBeautyMetadata realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetBeautyRange(std::vector<int32_t>& range, int32_t type)
{
    if (realSession_ != nullptr) {
        return realSession_->GetBeautyRange(range, type);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetBeautyRange realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetBeautyValue(int32_t type, int32_t& value)
{
    if (realSession_ != nullptr) {
        return realSession_->GetBeautyValue(type, value);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetBeautyValue realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetBeautyValue(int32_t type, int32_t value, bool needPersist)
{
    if (realSession_ != nullptr) {
        return realSession_->SetBeautyValue(type, value, needPersist);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetBeautyValue realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetColorEffectsMetadata(std::vector<int32_t>& colorEffectMetadata)
{
    if (realSession_ != nullptr) {
        return realSession_->GetColorEffectsMetadata(colorEffectMetadata);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetColorEffectsMetadata realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetColorEffect(int32_t& colourEffect)
{
    if (realSession_ != nullptr) {
        return realSession_->GetColorEffect(colourEffect);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetColorEffect realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetColorEffect(int32_t colourEffect)
{
    if (realSession_ != nullptr) {
        return realSession_->SetColorEffect(colourEffect);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetColorEffect realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::EnableKeyFrameReport(bool isKeyFrameReportEnabled)
{
    if (realSession_ != nullptr) {
        return realSession_->EnableKeyFrameReport(isKeyFrameReportEnabled);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::EnableKeyFrameReport realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetXtStyleStatus(bool status)
{
    if (realSession_ != nullptr) {
        return realSession_->SetXtStyleStatus(status);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetXtStyleStatus realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetCameraSwitchRequestCallback(const sptr<ICameraSwitchSessionCallback>& callback)
{
    if (realSession_ != nullptr) {
        return realSession_->SetCameraSwitchRequestCallback(callback);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetCameraSwitchRequestCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::UnSetCameraSwitchRequestCallback()
{
    if (realSession_ != nullptr) {
        return realSession_->UnSetCameraSwitchRequestCallback();
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::UnSetCameraSwitchRequestCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetCompositionStream(sptr<IRemoteObject>& compositionStreamRemote)
{
    if (realSession_ != nullptr) {
        return realSession_->GetCompositionStream(compositionStreamRemote);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetCompositionStream realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetSensorRotationOnce(int32_t& sensorRotation)
{
    if (realSession_ != nullptr) {
        return realSession_->GetSensorRotationOnce(sensorRotation);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetSensorRotationOnce realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::IsAutoFramingSupported(bool& support)
{
    if (realSession_ != nullptr) {
        return realSession_->IsAutoFramingSupported(support);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::IsAutoFramingSupported realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::GetAutoFramingStatus(bool& status)
{
    if (realSession_ != nullptr) {
        return realSession_->GetAutoFramingStatus(status);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::GetAutoFramingStatus realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::EnableAutoFraming(bool enable, bool needPersist)
{
    if (realSession_ != nullptr) {
        return realSession_->EnableAutoFraming(enable, needPersist);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::EnableAutoFraming realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::SetControlCenterEffectStatusCallback(
    const sptr<IControlCenterEffectStatusCallback>& callback)
{
    if (realSession_ != nullptr) {
        return realSession_->SetControlCenterEffectStatusCallback(callback);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::SetControlCenterEffectStatusCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::UnSetControlCenterEffectStatusCallback()
{
    if (realSession_ != nullptr) {
        return realSession_->UnSetControlCenterEffectStatusCallback();
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::UnSetControlCenterEffectStatusCallback realSession is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCaptureSession::CallbackEnter([[maybe_unused]] uint32_t code)
{
    if (realSession_ == nullptr) {
        MEDIA_ERR_LOG("HSharedCaptureSession::CallbackEnter realSession is null");
        return CAMERA_INVALID_STATE;
    }

    if (static_cast<ICaptureSessionIpcCode>(code) == ICaptureSessionIpcCode::COMMAND_START) {
        CaptureSessionState currentState;
        realSession_->GetSessionState(currentState);
        CHECK_RETURN_RET_ELOG(currentState == CaptureSessionState::SESSION_RELEASED,
            CAMERA_INVALID_STATE,
            "HSharedCaptureSession::CallbackEnter session is released");
        return CAMERA_OK;
    }

    return realSession_->CallbackEnter(code);
}

int32_t HSharedCaptureSession::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    if (realSession_ != nullptr) {
        return realSession_->CallbackExit(code, result);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::CallbackExit realSession is null");
    return CAMERA_INVALID_STATE;
}

void HSharedCaptureSession::BeforeDeviceClose()
{
    if (realSession_ != nullptr) {
        realSession_->BeforeDeviceClose();
        return;
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::BeforeDeviceClose realSession is null");
}

int32_t HSharedCaptureSession::OperatePermissionCheck(uint32_t interfaceCode)
{
    if (realSession_ != nullptr) {
        return realSession_->OperatePermissionCheck(interfaceCode);
    }
    MEDIA_ERR_LOG("HSharedCaptureSession::OperatePermissionCheck realSession is null");
    return CAMERA_INVALID_STATE;
}

} // namespace CameraStandard
} // namespace OHOS
