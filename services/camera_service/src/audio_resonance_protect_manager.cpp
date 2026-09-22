/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "audio_resonance_protect_manager.h"
#include <map>
#include <parameters.h>
#include "audio_resonance_dialog_manager.h"
#include "audio_errors.h"
#include "audio_info.h"
#include "audio_routing_manager.h"
#include "audio_stream_info.h"
#include "audio_stream_manager.h"
#include "audio_system_manager.h"
#include "camera_device_ability_items.h"
#include "camera_util.h"
#include "display_manager_lite.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#ifdef CAMERA_USE_MOVEMENT
#include "movement_client.h"
#include "movement_data_utils.h"
#endif

namespace OHOS {
namespace CameraStandard {
using namespace AudioStandard;
using namespace OHOS::Msdp;
constexpr int32_t PARAM_NUM2 = 2;
#ifdef CAMERA_USE_SENSOR
constexpr int32_t POSTURE_INTERVAL = 50000000; // 50ms
#endif

AudioResonanceProtectManager& AudioResonanceProtectManager::GetInstance()
{
    static AudioResonanceProtectManager instance;
    return instance;
}

bool AudioResonanceProtectManager::IsMusicSpeakOutput()
{
    auto streamManager = AudioStreamManager::GetInstance();
    CHECK_RETURN_RET_ELOG(streamManager == nullptr, false, "arpm get AudioStreamManager failed");
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> infos;
    auto ret = streamManager->GetCurrentRendererChangeInfos(infos);
    CHECK_RETURN_RET_ELOG(ret != SUCCESS, false, "arpm get renderer infos failed, ret: %{public}d", ret);
    for (const auto& info : infos) {
        if (info == nullptr) {
            continue;
        }
        MEDIA_DEBUG_LOG("arpm renderer sessionId: %{public}d, state: %{public}d, deviceType: %{public}d, "
                        "streamUsage: %{public}d", info->sessionId, static_cast<int32_t>(info->rendererState),
                        static_cast<int32_t>(info->outputDeviceInfo.deviceType_),
                        static_cast<int32_t>(info->rendererInfo.streamUsage));
        if (info->rendererState == RendererState::RENDERER_RUNNING &&
            info->outputDeviceInfo.deviceType_ == DEVICE_TYPE_SPEAKER /* && streamUsage == STREAM_USAGE_MUSIC */) {
            return true;
        }
    }
    return false;
}

void AudioResonanceProtectManager::CheckForMusicNotify()
{
    CHECK_RETURN(!audioResProtect_.load() || backCameraCount_.load() <= 0);
    std::lock_guard<std::mutex> lock(checkForMusicNotifyMutex_);
    MEDIA_DEBUG_LOG("arpm check: fold[%{public}d] vol[%{public}d] hall[%{public}d] dev[%{public}d] "
                    "render[%{public}d] move[%{public}d]", nowFoldStatus_, nowVolLevel_, nowHallStatus_,
                    nowAudioDeviceType_, nowRenderRunning_, nowMovementValue_);
    CHECK_RETURN_ILOG(nowHallStatus_ > 0, "arpm hall ret: %{public}d", nowHallStatus_);
    CHECK_RETURN_ILOG(static_cast<int>(nowFoldStatus_) != 1, "arpm fold ret: %{public}d", nowFoldStatus_);
    CHECK_RETURN_ILOG(nowVolLevel_ <= 0, "arpm volume ret: %{public}d", nowVolLevel_);
    CHECK_RETURN_ILOG(!nowRenderRunning_, "arpm render ret: %{public}d", nowRenderRunning_);
    CHECK_RETURN_ILOG(nowMovementValue_ != PARAM_NUM2, "arpm movement ret: %{public}d", nowMovementValue_);
    CHECK_RETURN_ILOG(!IsMusicSpeakOutput(), "arpm music speak output ret");
    int64_t currentTime = GetTimestamp();
    CHECK_RETURN_ILOG(currentTime - lastMusicNotifyTime_ < MUSIC_NOTIFY_INTERVAL_MS, "arpm notify interval ret");
    lastMusicNotifyTime_ = currentTime;
    MEDIA_INFO_LOG("arpm all conditions satisfied, show dialog");
    AudioResonanceDialog::GetInstance()->ShowCameraDialog();
}

void AudioResonanceProtectManager::RegisterCallbacks(const std::string& cameraId, int32_t cameraPosition)
{
    std::lock_guard<std::mutex> lock(registerMutex_);
    audioResProtect_.store(
        system::GetParameter("const.multimedia.camera.audio_resonance_protection", "false") == "true");
    CHECK_RETURN_ILOG(!audioResProtect_.load(), "arpm disabled");
    CHECK_RETURN_ILOG(cameraPosition != OHOS_CAMERA_POSITION_BACK, "arpm no back cam");
    backCameraCount_++;
    MEDIA_INFO_LOG("arpm register cameraId: %{public}s, cnt: %{public}d", cameraId.c_str(), backCameraCount_.load());
    if (backCameraCount_.load() == 1) {
        nowFoldStatus_ = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus());
        lstFoldStatus_ = nowFoldStatus_;
        RegisterFoldStatusListener();
        RegisterSystemVolumeChangeListener();
        RegisterOutputDeviceChangeListener();
        RegisterAudioRendererChangeListener();
#ifdef CAMERA_USE_SENSOR
        RegisterSensorCallbackHall();
#endif
#ifdef CAMERA_USE_MOVEMENT
        RegisterMovementListener();
#endif
    }
    CheckForMusicNotify();
}

void AudioResonanceProtectManager::UnregisterCallbacks(const std::string& cameraId, int32_t cameraPosition)
{
    std::lock_guard<std::mutex> lock(registerMutex_);
    CHECK_RETURN_ILOG(!audioResProtect_.load(), "arpm disabled");
    CHECK_RETURN_ILOG(cameraPosition != OHOS_CAMERA_POSITION_BACK, "arpm no back cam");
    backCameraCount_--;
    MEDIA_INFO_LOG("arpm unregister cnt: %{public}d", backCameraCount_.load());
    CHECK_RETURN(backCameraCount_.load() > 0);
    UnregisterFoldStatusListener();
    UnregisterSystemVolumeChangeListener();
    UnregisterOutputDeviceChangeListener();
    UnregisterAudioRendererChangeListener();
#ifdef CAMERA_USE_SENSOR
    UnRegisterSensorCallbackHall();
#endif
#ifdef CAMERA_USE_MOVEMENT
    UnregisterMovementListener();
#endif
}

class AudioResonanceProtectManager::FoldStatusListener : public OHOS::Rosen::DisplayManagerLite::IFoldStatusListener {
public:
    void OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldStatus) override
    {
        auto& manager = GetInstance();
        manager.OnStateChanged("fold", manager.nowFoldStatus_, manager.lstFoldStatus_,
                               static_cast<int32_t>(foldStatus));
    }
};

void AudioResonanceProtectManager::RegisterFoldStatusListener()
{
    std::lock_guard<std::mutex> lock(foldStatusListenerMutex_);
    CHECK_RETURN_ELOG(foldStatusListener_ != nullptr, "arpm fold listener already registered");
    foldStatusListener_ = new (std::nothrow) FoldStatusListener();
    CHECK_RETURN_ELOG(foldStatusListener_ == nullptr, "arpm fold listener create failed");
    auto ret = OHOS::Rosen::DisplayManagerLite::GetInstance().RegisterFoldStatusListener(foldStatusListener_);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_ERR_LOG("arpm register fold listener failed, ret: %{public}d", static_cast<int32_t>(ret));
        foldStatusListener_ = nullptr;
    }
}

void AudioResonanceProtectManager::UnregisterFoldStatusListener()
{
    std::lock_guard<std::mutex> lock(foldStatusListenerMutex_);
    CHECK_RETURN_ELOG(foldStatusListener_ == nullptr, "arpm fold listener not registered");
    auto ret = OHOS::Rosen::DisplayManagerLite::GetInstance().UnregisterFoldStatusListener(foldStatusListener_);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_ERR_LOG("arpm unregister fold listener failed, ret: %{public}d", static_cast<int32_t>(ret));
    }
    foldStatusListener_ = nullptr;
}

constexpr AudioVolumeType WATCHED_VOLUME_TYPES[] = {
    STREAM_MUSIC, STREAM_SYSTEM, STREAM_VOICE_CALL,
};

class AudioResonanceProtectManager::SystemVolumeChangeListener : public SystemVolumeChangeCallback {
public:
    SystemVolumeChangeListener()
    {
        auto audioManager = AudioSystemManager::GetInstance();
        CHECK_RETURN(audioManager == nullptr);
        for (auto type : WATCHED_VOLUME_TYPES) {
            lastVolumes_[type] = audioManager->GetVolume(type);
        }
        auto& manager = GetInstance();
        manager.lstVolLevel_ = CalcVolumeLevel();
        manager.nowVolLevel_ = manager.lstVolLevel_;
    }

    void OnSystemVolumeChange(VolumeEvent volumeEvent) override
    {
        MEDIA_INFO_LOG("arpm OnSystemVolumeChange: deviceType[%{public}d] volumeType[%{public}d] volume[%{public}d] "
                       "updateUi[%{public}d]", volumeEvent.deviceType, volumeEvent.volumeType, volumeEvent.volume,
                       volumeEvent.updateUi);
        CHECK_RETURN(volumeEvent.deviceType != DEVICE_TYPE_SPEAKER);
        auto it = lastVolumes_.find(volumeEvent.volumeType);
        CHECK_RETURN(it == lastVolumes_.end());
        CHECK_RETURN(volumeEvent.volume == it->second && !volumeEvent.updateUi);
        it->second = volumeEvent.volume;
        auto& manager = GetInstance();
        manager.OnStateChanged("volume", manager.nowVolLevel_, manager.lstVolLevel_, CalcVolumeLevel());
    }

private:
    int32_t CalcVolumeLevel() const
    {
        for (const auto& [type, volume] : lastVolumes_) {
            if (volume > VOL_LEVEL_TH) {
                return 1;
            }
        }
        return 0;
    }

    std::map<AudioVolumeType, int32_t> lastVolumes_;
};

class AudioResonanceProtectManager::OutputDeviceChangeListener : public AudioPreferredOutputDeviceChangeCallback {
public:
    void OnPreferredOutputDeviceUpdated(const std::vector<std::shared_ptr<AudioDeviceDescriptor>>& desc) override
    {
        CHECK_RETURN_ELOG(desc.empty(), "arpm device listener desc is empty");
        auto& manager = GetInstance();
        manager.OnStateChanged("device", manager.nowAudioDeviceType_, manager.lstAudioDeviceType_,
                               static_cast<int32_t>(desc[0]->deviceType_));
    }
};

class AudioResonanceProtectManager::AudioRendererChangeListener : public AudioRendererStateChangeCallback {
public:
    AudioRendererChangeListener()
    {
        auto& manager = GetInstance();
        manager.nowRenderRunning_ = manager.IsMusicSpeakOutput();
        manager.lstRenderRunning_ = manager.nowRenderRunning_;
    }

    void OnRendererStateChange(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>>& audioRendererChangeInfos) override
    {
        auto& manager = GetInstance();
        MEDIA_INFO_LOG("arpm OnRendererStateChange enter, size: %{public}zu, lstRunning: %{public}d",
                       audioRendererChangeInfos.size(), manager.lstRenderRunning_);
        manager.nowRenderRunning_ = false;
        for (const auto& info : audioRendererChangeInfos) {
            if (info == nullptr) {
                MEDIA_INFO_LOG("arpm renderer info is nullptr");
                continue;
            }
            MEDIA_INFO_LOG("arpm renderer sessionId: %{public}d, state: %{public}d, deviceType: %{public}d, "
                           "streamUsage: %{public}d, contentType: %{public}d", info->sessionId,
                           static_cast<int32_t>(info->rendererState),
                           static_cast<int32_t>(info->outputDeviceInfo.deviceType_),
                           static_cast<int32_t>(info->rendererInfo.streamUsage),
                           static_cast<int32_t>(info->rendererInfo.contentType));
            if (info->rendererState == RendererState::RENDERER_RUNNING &&
                info->outputDeviceInfo.deviceType_ == DEVICE_TYPE_SPEAKER) {
                manager.nowRenderRunning_ = true;
                break;
            }
        }
        manager.OnStateChanged("render", manager.nowRenderRunning_, manager.lstRenderRunning_,
                               manager.nowRenderRunning_);
    }
};

#ifdef CAMERA_USE_MOVEMENT
class AudioResonanceProtectManager::MovementListener : public MovementCallbackStub {
public:
    void OnMovementChanged(const MovementDataUtils::MovementData& data) override
    {
        auto& manager = GetInstance();
        manager.OnStateChanged("movement", manager.nowMovementValue_, manager.lstMovementValue_,
                               static_cast<int32_t>(data.value));
    }
};
#endif

void AudioResonanceProtectManager::RegisterSystemVolumeChangeListener()
{
    std::lock_guard<std::mutex> lock(systemVolumeChangeListenerMutex_);
    CHECK_RETURN_ELOG(systemVolumeChangeListener_ != nullptr, "arpm volume listener already registered");
    systemVolumeChangeListener_ = std::make_shared<SystemVolumeChangeListener>();
    auto audioManager = AudioSystemManager::GetInstance();
    CHECK_RETURN_ELOG(audioManager == nullptr, "arpm get AudioSystemManager failed");
    auto ret = audioManager->RegisterSystemVolumeChangeCallback(IPCSkeleton::GetCallingPid(),
                                                                systemVolumeChangeListener_);
    if (ret != SUCCESS) {
        MEDIA_ERR_LOG("arpm register volume listener failed, ret: %{public}d", ret);
        systemVolumeChangeListener_ = nullptr;
    }
}

void AudioResonanceProtectManager::UnregisterSystemVolumeChangeListener()
{
    std::lock_guard<std::mutex> lock(systemVolumeChangeListenerMutex_);
    CHECK_RETURN_ELOG(systemVolumeChangeListener_ == nullptr, "arpm volume listener not registered");
    auto audioManager = AudioSystemManager::GetInstance();
    CHECK_RETURN_ELOG(audioManager == nullptr, "arpm get AudioSystemManager failed");
    auto ret = audioManager->UnregisterSystemVolumeChangeCallback(IPCSkeleton::GetCallingPid(),
                                                                  systemVolumeChangeListener_);
    if (ret != SUCCESS) {
        MEDIA_ERR_LOG("arpm unregister volume listener failed, ret: %{public}d", ret);
    }
    systemVolumeChangeListener_ = nullptr;
}

void AudioResonanceProtectManager::RegisterOutputDeviceChangeListener()
{
    std::lock_guard<std::mutex> lock(outputDeviceChangeListenerMutex_);
    CHECK_RETURN_ELOG(outputDeviceChangeListener_ != nullptr, "arpm device listener already registered");
    outputDeviceChangeListener_ = std::make_shared<OutputDeviceChangeListener>();
    auto audioRoutingManager = AudioRoutingManager::GetInstance();
    CHECK_RETURN_ELOG(audioRoutingManager == nullptr, "arpm get AudioRoutingManager failed");
    AudioRendererInfo rendererInfo;
    rendererInfo.streamUsage = StreamUsage::STREAM_USAGE_INVALID;
    auto ret = audioRoutingManager->SetPreferredOutputDeviceChangeCallback(rendererInfo, outputDeviceChangeListener_);
    if (ret != SUCCESS) {
        MEDIA_ERR_LOG("arpm register device listener failed, ret: %{public}d", ret);
        outputDeviceChangeListener_ = nullptr;
    }
}

void AudioResonanceProtectManager::UnregisterOutputDeviceChangeListener()
{
    std::lock_guard<std::mutex> lock(outputDeviceChangeListenerMutex_);
    CHECK_RETURN_ELOG(outputDeviceChangeListener_ == nullptr, "arpm device listener not registered");
    auto audioRoutingManager = AudioRoutingManager::GetInstance();
    CHECK_RETURN_ELOG(audioRoutingManager == nullptr, "arpm get AudioRoutingManager failed");
    auto ret = audioRoutingManager->UnsetPreferredOutputDeviceChangeCallback(outputDeviceChangeListener_);
    if (ret != SUCCESS) {
        MEDIA_ERR_LOG("arpm unregister device listener failed, ret: %{public}d", ret);
    }
    outputDeviceChangeListener_ = nullptr;
}

void AudioResonanceProtectManager::RegisterAudioRendererChangeListener()
{
    std::lock_guard<std::mutex> lock(audioRendererChangeListenerMutex_);
    CHECK_RETURN_ELOG(audioRendererChangeListener_ != nullptr, "arpm renderer listener already registered");
    audioRendererChangeListener_ = std::make_shared<AudioRendererChangeListener>();
    auto audioStreamManager = AudioStreamManager::GetInstance();
    CHECK_RETURN_ELOG(audioStreamManager == nullptr, "arpm get AudioStreamManager failed");
    auto ret = audioStreamManager->RegisterAudioRendererEventListener(audioRendererChangeListener_);
    if (ret != SUCCESS) {
        MEDIA_ERR_LOG("arpm register renderer listener failed, ret: %{public}d", ret);
        audioRendererChangeListener_ = nullptr;
    }
}

void AudioResonanceProtectManager::UnregisterAudioRendererChangeListener()
{
    std::lock_guard<std::mutex> lock(audioRendererChangeListenerMutex_);
    CHECK_RETURN_ELOG(audioRendererChangeListener_ == nullptr, "arpm renderer listener not registered");
    auto audioStreamManager = AudioStreamManager::GetInstance();
    CHECK_RETURN_ELOG(audioStreamManager == nullptr, "arpm get AudioStreamManager failed");
    auto ret = audioStreamManager->UnregisterAudioRendererEventListener(audioRendererChangeListener_);
    if (ret != SUCCESS) {
        MEDIA_ERR_LOG("arpm unregister renderer listener failed, ret: %{public}d", ret);
    }
    audioRendererChangeListener_ = nullptr;
}

#ifdef CAMERA_USE_MOVEMENT
void AudioResonanceProtectManager::RegisterMovementListener()
{
    std::lock_guard<std::mutex> lock(movementListenerMutex_);
    CHECK_RETURN_ELOG(movementListener_ != nullptr, "arpm movement listener already registered");
    movementListener_ = new (std::nothrow) MovementListener();
    CHECK_RETURN_ELOG(movementListener_ == nullptr, "arpm movement listener create failed");
    constexpr int64_t interval = 5000000000L; // 5s
    auto ret = MovementClient::GetInstance().SubscribeCallback(MovementDataUtils::MovementType::TYPE_IN_ELEVATOR,
        MovementDataUtils::MovementEvent::ENTER_EXIT, interval, movementListener_);
    if (ret != 0) {
        MEDIA_ERR_LOG("arpm register movement listener failed, ret: %{public}d", ret);
        movementListener_ = nullptr;
    }
}

void AudioResonanceProtectManager::UnregisterMovementListener()
{
    std::lock_guard<std::mutex> lock(movementListenerMutex_);
    CHECK_RETURN_ELOG(movementListener_ == nullptr, "arpm movement listener not registered");
    auto ret = MovementClient::GetInstance().UnSubscribeCallback(
        MovementDataUtils::MovementType::TYPE_IN_ELEVATOR, movementListener_);
    if (ret != 0) {
        MEDIA_ERR_LOG("arpm unregister movement listener failed, ret: %{public}d", ret);
    }
    movementListener_ = nullptr;
}
#endif

#ifdef CAMERA_USE_SENSOR
void AudioResonanceProtectManager::RegisterSensorCallbackHall()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sensorLockHall_);
    CHECK_RETURN_ILOG(isRegisterSensorSuccess_, "arpm hall sensor already registered");
    sensorUserHall_.callback = HallDataCallbackImpl;
    int32_t subscribeRet = SubscribeSensor(SENSOR_TYPE_ID_HALL, &sensorUserHall_);
    int32_t setBatchRet = SetBatch(SENSOR_TYPE_ID_HALL, &sensorUserHall_, POSTURE_INTERVAL, 0);
    int32_t activateRet = ActivateSensor(SENSOR_TYPE_ID_HALL, &sensorUserHall_);
    isRegisterSensorSuccess_ = subscribeRet == CAMERA_OK && setBatchRet == CAMERA_OK && activateRet == CAMERA_OK;
    if (!isRegisterSensorSuccess_) { // LCOV_EXCL_LINE
        MEDIA_ERR_LOG("arpm hall sensor register failed, sub: %{public}d, batch: %{public}d, act: %{public}d",
                      subscribeRet, setBatchRet, activateRet);
    }
    // LCOV_EXCL_STOP
}

void AudioResonanceProtectManager::UnRegisterSensorCallbackHall()
{
    std::lock_guard<std::mutex> lock(sensorLockHall_);
    int32_t deactivateRet = DeactivateSensor(SENSOR_TYPE_ID_HALL, &sensorUserHall_);
    int32_t unsubscribeRet = UnsubscribeSensor(SENSOR_TYPE_ID_HALL, &sensorUserHall_);
    // hold until any in-flight sensor callback completes (drain)
    std::lock_guard<std::mutex> cbLock(hallSensorCbMutex_);
    // LCOV_EXCL_START
    if (deactivateRet == CAMERA_OK && unsubscribeRet == CAMERA_OK) {
        isRegisterSensorSuccess_ = false;
    } else {
        MEDIA_ERR_LOG("arpm hall sensor unregister failed, deact: %{public}d, unsub: %{public}d",
                      deactivateRet, unsubscribeRet);
    }
    // LCOV_EXCL_STOP
}

void AudioResonanceProtectManager::HallDataCallbackImpl(SensorEvent* event)
{
    // LCOV_EXCL_START
    CHECK_RETURN_ELOG(event == nullptr, "arpm hall SensorEvent is nullptr");
    CHECK_RETURN_ELOG(event[0].data == nullptr, "arpm hall SensorEvent data is nullptr");
    CHECK_RETURN_ELOG(event->sensorTypeId != SENSOR_TYPE_ID_HALL, "arpm hall sensor type mismatch");
    GetInstance().HandleHallSensorData(event);
    // LCOV_EXCL_STOP
}

void AudioResonanceProtectManager::HandleHallSensorData(SensorEvent* event)
{
    // LCOV_EXCL_START
    CHECK_RETURN(!audioResProtect_.load());
    std::lock_guard<std::mutex> lock(hallSensorCbMutex_);
    auto data = reinterpret_cast<HallData*>(event->data);
    OnStateChanged("hall", nowHallStatus_, lstHallStatus_, static_cast<uint32_t>(data->status));
    // LCOV_EXCL_STOP
}
#endif
} // namespace CameraStandard
} // namespace OHOS
