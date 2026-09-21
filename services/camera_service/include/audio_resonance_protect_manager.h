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

#ifndef AUDIO_RESONANCE_PROTECT_MANAGER_H
#define AUDIO_RESONANCE_PROTECT_MANAGER_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include "camera_log.h"
#include "refbase.h"
#ifdef CAMERA_USE_MOVEMENT
#include "movement_callback_stub.h"
#endif
#ifdef CAMERA_USE_SENSOR
#include "sensor_agent.h"
#include "sensor_agent_type.h"
#endif

namespace OHOS {
namespace CameraStandard {

class AudioResonanceProtectManager {
public:
    static AudioResonanceProtectManager& GetInstance();

    void RegisterCallbacks(const std::string& cameraId, int32_t cameraPosition);
    void UnregisterCallbacks(const std::string& cameraId, int32_t cameraPosition);

private:
    AudioResonanceProtectManager() = default;
    ~AudioResonanceProtectManager() = default;
    AudioResonanceProtectManager(const AudioResonanceProtectManager&) = delete;
    AudioResonanceProtectManager& operator=(const AudioResonanceProtectManager&) = delete;

    class FoldStatusListener;
    class SystemVolumeChangeListener;
    class OutputDeviceChangeListener;
    class AudioRendererChangeListener;
    class MovementListener;

    void CheckForMusicNotify();
    bool IsMusicSpeakOutput();
    template<typename T>
    void OnStateChanged(const char* tag, T& now, T& lst, T value)
    {
        now = value;
        CHECK_RETURN(now == lst);
        MEDIA_INFO_LOG("arpm %{public}s: [%{public}d->%{public}d]",
            tag, static_cast<int32_t>(lst), static_cast<int32_t>(now));
        CheckForMusicNotify();
        lst = now;
    }

    void RegisterFoldStatusListener();
    void UnregisterFoldStatusListener();
    void RegisterSystemVolumeChangeListener();
    void UnregisterSystemVolumeChangeListener();
    void RegisterOutputDeviceChangeListener();
    void UnregisterOutputDeviceChangeListener();
    void RegisterAudioRendererChangeListener();
    void UnregisterAudioRendererChangeListener();
    void RegisterMovementListener();
    void UnregisterMovementListener();
    void RegisterSensorCallbackHall();
    void UnRegisterSensorCallbackHall();
    static void HallDataCallbackImpl(SensorEvent* event);
    void HandleHallSensorData(SensorEvent* event);

    static constexpr int64_t MUSIC_NOTIFY_INTERVAL_MS = 24*3600*1000; // 24h
    static constexpr int32_t VOL_LEVEL_TH = 10;

    std::mutex registerMutex_;
    std::atomic<bool> audioResProtect_{false};
    std::atomic<int32_t> backCameraCount_{0};

    int64_t lastMusicNotifyTime_ = 0;
    int32_t lstFoldStatus_ = -1;
    int32_t nowFoldStatus_ = -1;
    uint32_t lstHallStatus_ = 0xFF;
    uint32_t nowHallStatus_ = 0xFF;
    int32_t lstVolLevel_ = 0;
    int32_t nowVolLevel_ = 0;
    bool lstRenderRunning_ = false;
    bool nowRenderRunning_ = false;
    int32_t lstAudioDeviceType_ = -1;
    int32_t nowAudioDeviceType_ = -1;
    int32_t lstMovementValue_ = -1;
    int32_t nowMovementValue_ = -1;
    std::mutex checkForMusicNotifyMutex_;

    std::mutex foldStatusListenerMutex_;
    sptr<FoldStatusListener> foldStatusListener_;
    std::mutex systemVolumeChangeListenerMutex_;
    std::shared_ptr<SystemVolumeChangeListener> systemVolumeChangeListener_;
    std::mutex outputDeviceChangeListenerMutex_;
    std::shared_ptr<OutputDeviceChangeListener> outputDeviceChangeListener_;
    std::mutex audioRendererChangeListenerMutex_;
    std::shared_ptr<AudioRendererChangeListener> audioRendererChangeListener_;
#ifdef CAMERA_USE_MOVEMENT
    std::mutex movementListenerMutex_;
    sptr<MovementListener> movementListener_;
#endif
#ifdef CAMERA_USE_SENSOR
    std::mutex sensorLockHall_;
    std::mutex hallSensorCbMutex_;
    bool isRegisterSensorSuccess_ = false;
    SensorUser sensorUserHall_ = { "", nullptr, nullptr };
#endif
};
} // namespace CameraStandard
} // namespace OHOS

#endif // AUDIO_RESONANCE_PROTECT_MANAGER_H
