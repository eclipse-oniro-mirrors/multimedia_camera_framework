/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "audio_deferred_process.h"

#include "camera_log.h"
#include "camera_util.h"
#include "sample_info.h"
#include <cstring>

namespace OHOS {
namespace CameraStandard {

AudioDeferredProcess::AudioDeferredProcess()
{
    MEDIA_INFO_LOG("AudioDeferredProcess() Enter");
    if (!offlineAudioEffectManager_) {
        offlineAudioEffectManager_ = std::make_unique<OfflineAudioEffectManager>();
    }
}

AudioDeferredProcess::~AudioDeferredProcess()
{
    MEDIA_INFO_LOG("~AudioDeferredProcess Enter");
    Release();
}

int32_t AudioDeferredProcess::GetOfflineEffectChain()
{
    MEDIA_INFO_LOG("AudioDeferredProcess::GetOfflineEffectChain Enter");
    if (!offlineAudioEffectManager_) {
        MEDIA_ERR_LOG("AudioDeferredProcess::GetOfflineEffectChain offlineAudioEffectManager_ is nullptr");
        return -1;
    }
    vector<std::string> effectChains = offlineAudioEffectManager_->GetOfflineAudioEffectChains();
    if (std::find(effectChains.begin(), effectChains.end(), chainName_) == effectChains.end()) {
        MEDIA_ERR_LOG("AudioDeferredProcess::GetOfflineEffectChain no effectChain moving photo needed");
        return -1;
    }
    offlineEffectChain_ = offlineAudioEffectManager_->CreateOfflineAudioEffectChain(chainName_);
    if (!offlineEffectChain_) {
        MEDIA_ERR_LOG("AudioDeferredProcess::GetOfflineEffectChain ERR");
        return -1;
    }
    return CAMERA_OK;
}

int32_t AudioDeferredProcess::ConfigOfflineAudioEffectChain(const AudioStreamInfo& inputOptions,
    const AudioStreamInfo& outputOptions)
{
    MEDIA_INFO_LOG("AudioDeferredProcess::ConfigOfflineAudioEffectChain Enter");
    if (offlineEffectChain_->Configure(inputOptions, outputOptions) != 0) {
        MEDIA_ERR_LOG("AudioDeferredProcess::ConfigOfflineAudioEffectChain Err");
        return -1;
    }
    inputOptions_ = inputOptions;
    outputOptions_ = outputOptions;
    return CAMERA_OK;
}

int32_t AudioDeferredProcess::PrepareOfflineAudioEffectChain()
{
    MEDIA_INFO_LOG("AudioDeferredProcess::PrepareOfflineAudioEffectChain Enter");
    if (offlineEffectChain_->Prepare() != 0) {
        MEDIA_ERR_LOG("AudioDeferredProcess::PrepareOfflineAudioEffectChain Err");
        return -1;
    }
    return CAMERA_OK;
}

int32_t AudioDeferredProcess::GetMaxBufferSize(const AudioStreamInfo& inputOptions,
    const AudioStreamInfo& outputOptions)
{
    MEDIA_INFO_LOG("AudioDeferredProcess::GetMaxBufferSize Enter");
    if (offlineEffectChain_->GetEffectBufferSize(maxUnprocessedBufferSize_, maxProcessedBufferSize_) != 0) {
        MEDIA_ERR_LOG("AudioDeferredProcess::GetMaxBufferSize Err");
        return -1;
    }
    oneUnprocessedSize_ = inputOptions.samplingRate / ONE_THOUSAND *
        inputOptions.channels * DURATION_EACH_AUDIO_FRAME * sizeof(short);
    oneProcessedSize_ = outputOptions.samplingRate / ONE_THOUSAND *
        outputOptions.channels * DURATION_EACH_AUDIO_FRAME * sizeof(short);
    MEDIA_INFO_LOG("AudioDeferredProcess::GetMaxBufferSize %{public}d", oneProcessedSize_);
    if (oneUnprocessedSize_ * PROCESS_BATCH_SIZE > maxUnprocessedBufferSize_ ||
        oneProcessedSize_ * PROCESS_BATCH_SIZE > maxProcessedBufferSize_) {
        MEDIA_ERR_LOG("AudioDeferredProcess::GetMaxBufferSize MaxBufferSize Not Enough");
        return -1;
    }
    return CAMERA_OK;
}

int32_t AudioDeferredProcess::GetOneUnprocessedSize()
{
    return oneUnprocessedSize_;
}

int32_t AudioDeferredProcess::GetOutputSampleRate()
{
    return outputOptions_.samplingRate;
}

int32_t AudioDeferredProcess::GetOutputChannelCount()
{
    return outputOptions_.channels;
}

int32_t AudioDeferredProcess::Process(vector<sptr<AudioRecord>>& audioRecords,
    vector<sptr<AudioRecord>>& processedRecords)
{
    if (offlineEffectChain_ == nullptr) {
        MEDIA_WARNING_LOG("AudioDeferredProcess::Process offlineEffectChain_ is nullptr.");
        return -1;
    }
    MEDIA_INFO_LOG("AudioDeferredProcess::Process Enter");
    uint32_t audioRecordsLen = audioRecords.size();
    std::unique_ptr<uint8_t[]> rawArr = std::make_unique<uint8_t[]>(oneUnprocessedSize_ * PROCESS_BATCH_SIZE);
    std::unique_ptr<uint8_t[]> processedArr = std::make_unique<uint8_t[]>(oneProcessedSize_ * PROCESS_BATCH_SIZE);

    uint32_t count = 0;
    lock_guard<std::mutex> lock(mutex_);
    auto returnToRecords = [this, &processedRecords, &rawArr, &processedArr](uint32_t i, uint32_t batchSize)->void {
        int32_t ret = offlineEffectChain_->Process(rawArr.get(), oneUnprocessedSize_ * batchSize,
            processedArr.get(), oneProcessedSize_ * batchSize);
        CHECK_ERROR_PRINT_LOG(ret != 0, "AudioDeferredProcess::Process err");
        for (uint32_t j = 0; j < batchSize; ++ j) {
            uint8_t* temp = new uint8_t[oneProcessedSize_];
            ret = memcpy_s(temp, oneProcessedSize_, processedArr.get() + j * oneProcessedSize_, oneProcessedSize_);
            CHECK_AND_PRINT_LOG(ret == 0, "AudioDeferredProcess::Process returnToRecords memcpy_s err");
            processedRecords[i - batchSize + 1 + j]->SetAudioBuffer(temp);
        }
    };

    for (uint32_t i = 0; i < audioRecordsLen; i ++) {
        int32_t ret = memcpy_s(rawArr.get() + count * oneUnprocessedSize_, oneUnprocessedSize_,
            audioRecords[i]->GetAudioBuffer(), oneUnprocessedSize_);
        CHECK_ERROR_PRINT_LOG(ret != 0, "AudioDeferredProcess::Process memcpy_s err");
        if (count == PROCESS_BATCH_SIZE - 1) {
            returnToRecords(i, PROCESS_BATCH_SIZE);
        } else if (i == audioRecordsLen - 1) { // last
            returnToRecords(i, count + 1);
        }
        count = (count + 1) % PROCESS_BATCH_SIZE;
    }

    return CAMERA_OK;
}

void AudioDeferredProcess::Release()
{
    lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("AudioDeferredProcess::Release Enter");
    if (offlineEffectChain_) {
        offlineEffectChain_->Release();
    }
    offlineEffectChain_ = nullptr;
    offlineAudioEffectManager_ = nullptr;
}

} // CameraStandard
} // OHOS