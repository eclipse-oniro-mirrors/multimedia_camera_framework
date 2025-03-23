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
#include <cstring>

namespace OHOS {
namespace CameraStandard {

AudioDeferredProcess::AudioDeferredProcess()
{
    MEDIA_INFO_LOG("AudioDeferredProcess() Enter");
}

AudioDeferredProcess::~AudioDeferredProcess()
{
    MEDIA_INFO_LOG("~AudioDeferredProcess Enter");
    Release();
}

int32_t AudioDeferredProcess::GetOfflineEffectChain()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcess::GetOfflineEffectChain Enter");
    if (!offlineAudioEffectManager_) {
        offlineAudioEffectManager_ = std::make_unique<OfflineAudioEffectManager>();
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

void AudioDeferredProcess::StoreOptions(const AudioStreamInfo& inputOptions,
    const AudioStreamInfo& outputOptions)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcess::StoreConfig Enter");
    inputOptions_ = inputOptions;
    outputOptions_ = outputOptions;
}

int32_t AudioDeferredProcess::ConfigOfflineAudioEffectChain()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcess::ConfigOfflineAudioEffectChain Enter");
    if (offlineEffectChain_->Configure(inputOptions_, outputOptions_) != 0) {
        MEDIA_ERR_LOG("AudioDeferredProcess::ConfigOfflineAudioEffectChain Err");
        return -1;
    }
    return CAMERA_OK;
}

int32_t AudioDeferredProcess::PrepareOfflineAudioEffectChain()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcess::PrepareOfflineAudioEffectChain Enter");
    CHECK_ERROR_RETURN_RET_LOG(offlineEffectChain_->Prepare() != 0, -1,
        "AudioDeferredProcess::PrepareOfflineAudioEffectChain Err");
    return CAMERA_OK;
}

int32_t AudioDeferredProcess::GetMaxBufferSize(const AudioStreamInfo& inputOptions,
    const AudioStreamInfo& outputOptions)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcess::GetMaxBufferSize Enter");
    uint32_t maxUnprocessedBufferSize_ = 0;
    uint32_t maxProcessedBufferSize_ = 0;
    CHECK_ERROR_RETURN_RET_LOG(offlineEffectChain_->GetEffectBufferSize(maxUnprocessedBufferSize_,
        maxProcessedBufferSize_) != 0, -1, "AudioDeferredProcess::GetMaxBufferSize Err");
    oneUnprocessedSize_ = inputOptions.samplingRate / ONE_THOUSAND *
        inputOptions.channels * DURATION_EACH_AUDIO_FRAME * sizeof(short);
    oneProcessedSize_ = outputOptions.samplingRate / ONE_THOUSAND *
        outputOptions.channels * DURATION_EACH_AUDIO_FRAME * sizeof(short);
    CHECK_ERROR_RETURN_RET_LOG(oneUnprocessedSize_ * PROCESS_BATCH_SIZE > maxUnprocessedBufferSize_ ||
        oneProcessedSize_ * PROCESS_BATCH_SIZE > maxProcessedBufferSize_, -1,
        "AudioDeferredProcess::GetMaxBufferSize MaxBufferSize Not Enough");
    return CAMERA_OK;
}

uint32_t AudioDeferredProcess::GetOneUnprocessedSize()
{
    return oneUnprocessedSize_;
}

void fadeOneBatch(uint8_t* processedArr)
{
    float rate;
    int16_t *data = (int16_t *)processedArr;
    int32_t temp;
    constexpr int32_t oneSize = 32 * 32;
    for (int k = 0; k < oneSize; k++) {
        temp = static_cast<int32_t>(data[k]);
        rate = static_cast<float>(k) / oneSize;
        temp = temp - static_cast<int32_t>(temp * rate);
        data[k] = static_cast<int16_t>(temp);
    }
}

int32_t AudioDeferredProcess::Process(vector<sptr<AudioRecord>>& audioRecords,
    vector<sptr<AudioRecord>>& processedRecords)
{
    CAMERA_SYNC_TRACE;
    if (offlineEffectChain_ == nullptr) {
        MEDIA_WARNING_LOG("AudioDeferredProcess::Process offlineEffectChain_ is nullptr.");
        return -1;
    }
    MEDIA_INFO_LOG("AudioDeferredProcess::Process Enter");
    uint32_t audioRecordsLen = audioRecords.size();
    uint8_t rawArr[MAX_UNPROCESSED_SIZE * PROCESS_BATCH_SIZE] = {0};
    uint8_t processedArr[MAX_PROCESSED_SIZE * PROCESS_BATCH_SIZE] = {0};
    uint32_t count = 0;
    lock_guard<std::mutex> lock(mutex_);
    auto EffectChainProcess = [this, &rawArr, &processedArr]()->void {
        int32_t ret = offlineEffectChain_->Process(rawArr, oneUnprocessedSize_ * PROCESS_BATCH_SIZE,
            processedArr, oneProcessedSize_ * PROCESS_BATCH_SIZE);
        CHECK_ERROR_PRINT_LOG(ret != 0, "AudioDeferredProcess::Process err");
    }
    auto ReturnToRecords = [this, &processedRecords, &processedArr](uint32_t i, uint32_t batchSize)->void {
        for (uint32_t j = 0; j < batchSize; ++ j) {
            uint8_t* temp = new uint8_t[oneProcessedSize_];
            int32_t ret = memcpy_s(temp, oneProcessedSize_, processedArr.get() + j * oneProcessedSize_, oneProcessedSize_);
            CHECK_ERROR_PRINT_LOG(ret != 0, "AudioDeferredProcess::Process returnToRecords memcpy_s err");
            processedRecords[i + 1 + j - batchSize]->SetAudioBuffer(temp);
        }
    };

    for (uint32_t i = 0; i < audioRecordsLen; i ++) {
        int32_t ret = memcpy_s(rawArr + count * oneUnprocessedSize_, oneUnprocessedSize_,
            audioRecords[i]->GetAudioBuffer(), oneUnprocessedSize_);
        CHECK_ERROR_PRINT_LOG(ret != 0, "AudioDeferredProcess::Process memcpy_s err");
        if (audioRecordsLen - 1 == i) {
            memset_s(rawArr, MAX_UNPROCESSED_SIZE * PROCESS_BATCH_SIZE, 0, PROCESS_BATCH_SIZE * oneUnprocessedSize_);
            EffectChainProcess();
            memset_s(processedArr, MAX_PROCESSED_SIZE * PROCESS_BATCH_SIZE, 0, PROCESS_BATCH_SIZE * oneProcessedSize_);
            ReturnToRecords(i, count + 1);
        } else if (i >= audioRecordsLen - PROCESS_BATCH_SIZE - 1 && count == PROCESS_BATCH_SIZE - 1) {
            EffectChainProcess();
            fadeOneBatch(processedArr);
            memset_s(processedArr + oneProcessedSize_, MAX_PROCESSED_SIZE * PROCESS_BATCH_SIZE,
                0, (PROCESS_BATCH_SIZE - 1) * oneProcessedSize_);
            ReturnToRecords(i, PROCESS_BATCH_SIZE);
        } else if (count == PROCESS_BATCH_SIZE - 1) {
            EffectChainProcess();
            ReturnToRecords(i, PROCESS_BATCH_SIZE);
        }
        count = (count + 1) % PROCESS_BATCH_SIZE;
    }

    return CAMERA_OK;
}

void AudioDeferredProcess::Release()
{
    CAMERA_SYNC_TRACE;
    lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("AudioDeferredProcess::Release Enter");
    CHECK_EXECUTE(offlineEffectChain_, offlineEffectChain_->Release());
    offlineEffectChain_ = nullptr;
    offlineAudioEffectManager_ = nullptr;
}

} // CameraStandard
} // OHOS