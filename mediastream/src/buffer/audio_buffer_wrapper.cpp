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

#include "audio_buffer_wrapper.h"
#include "camera_log.h"
#include "sync_fence.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

AudioBufferWrapper::AudioBufferWrapper(int64_t timestamp) : BufferWrapperBase(Type::AUDIO, timestamp),
    wrapperId_(std::to_string(timestamp))
{
    MEDIA_DEBUG_LOG("AudioBufferWrapper %{public}" PRId64, timestamp);
}

AudioBufferWrapper::AudioBufferWrapper(
    int64_t timestamp, uint8_t* audioBuffer, uint32_t bufferSize) : AudioBufferWrapper(timestamp)
{
    SetAudioBuffer(audioBuffer, bufferSize);
}

AudioBufferWrapper::~AudioBufferWrapper()
{
    MEDIA_DEBUG_LOG("~AudioBufferWrapper %{public}" PRId64, GetTimestamp());
    if (audioBuffer_ != nullptr) {
        delete audioBuffer_;
        audioBuffer_ = nullptr;
    }
}

bool AudioBufferWrapper::Release()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (IsReadyConvert()) {
        MEDIA_DEBUG_LOG("Release when isReadyConvert");
        canReleased_.wait_for(lock, std::chrono::milliseconds(150),
            [this] { return IsFinishEncode(); });
        MEDIA_DEBUG_LOG("releaseSurfaceBuffer go %{public}s", wrapperId_.c_str());
    }
    if (audioBuffer_ != nullptr) {
        delete audioBuffer_;
        audioBuffer_ = nullptr;
    }
    return MEDIA_OK;
}

} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP