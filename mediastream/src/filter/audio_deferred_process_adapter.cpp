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

#include "audio_deferred_process_adapter.h"

#include "camera_log.h"
#include <cstring>

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

AudioDeferredProcessAdapter::AudioDeferredProcessAdapter()
{
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter() Enter");
}

AudioDeferredProcessAdapter::~AudioDeferredProcessAdapter()
{
    MEDIA_INFO_LOG("~AudioDeferredProcessAdapter Enter");
    Release();
}

int32_t AudioDeferredProcessAdapter::GetOfflineEffectChain()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::GetOfflineEffectChain Enter");
    if (!offlineAudioEffectManager_) {
        offlineAudioEffectManager_ = std::make_unique<OfflineAudioEffectManager>();
    }
    vector<std::string> effectChains = offlineAudioEffectManager_->GetOfflineAudioEffectChains();
    CHECK_RETURN_RET_ELOG(std::find(effectChains.begin(), effectChains.end(), chainName_) == effectChains.end(),
        MEDIA_ERR, "AudioDeferredProcessAdapter::GetOfflineEffectChain no effectChain moving photo needed");
    offlineEffectChain_ = offlineAudioEffectManager_->CreateOfflineAudioEffectChain(chainName_);
    CHECK_RETURN_RET_ELOG(!offlineEffectChain_, MEDIA_ERR, "AudioDeferredProcessAdapter::GetOfflineEffectChain ERR");
    return MEDIA_OK;
}

int32_t AudioDeferredProcessAdapter::Init(const AudioStreamInfo& inputOptions, const AudioStreamInfo& outputOptions)
{
    StoreOptions(inputOptions, outputOptions);
    CHECK_RETURN_RET(GetOfflineEffectChain() != MEDIA_OK, MEDIA_ERR);
    CHECK_RETURN_RET(ConfigOfflineAudioEffectChain() != MEDIA_OK, MEDIA_ERR);
    CHECK_RETURN_RET(PrepareOfflineAudioEffectChain() != MEDIA_OK, MEDIA_ERR);
    CHECK_RETURN_RET(GetMaxBufferSize() != MEDIA_OK, MEDIA_ERR);
    return MEDIA_OK;
}

void AudioDeferredProcessAdapter::StoreOptions(const AudioStreamInfo& inputOptions,
    const AudioStreamInfo& outputOptions)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::StoreConfig Enter");
    inputOptions_ = inputOptions;
    outputOptions_ = outputOptions;
    singleInputSize_ = CalculateBufferSize(inputOptions_);
    singleOutputSize_ = CalculateBufferSize(outputOptions_);
}

int32_t AudioDeferredProcessAdapter::ConfigOfflineAudioEffectChain()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::ConfigOfflineAudioEffectChain Enter");
    CHECK_RETURN_RET_ELOG(offlineEffectChain_->Configure(inputOptions_, outputOptions_) != 0, MEDIA_ERR,
        "AudioDeferredProcessAdapter::ConfigOfflineAudioEffectChain Err");
    return MEDIA_OK;
}

int32_t AudioDeferredProcessAdapter::PrepareOfflineAudioEffectChain()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::PrepareOfflineAudioEffectChain Enter");
    CHECK_RETURN_RET_ELOG(offlineEffectChain_->Prepare() != 0, MEDIA_ERR,
        "AudioDeferredProcessAdapter::PrepareOfflineAudioEffectChain Err");
    return MEDIA_OK;
}

uint32_t AudioDeferredProcessAdapter::CalculateBufferSize(const AudioStreamInfo& streamInfo)
{
    return streamInfo.samplingRate / ONE_THOUSAND * streamInfo.channels * DURATION_EACH_AUDIO_FRAME * sizeof(short);
}

int32_t AudioDeferredProcessAdapter::GetMaxBufferSize()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::GetMaxBufferSize Enter");
    uint32_t batchMaxInputSize = 0;
    uint32_t batchMaxOutputSize = 0;
    int32_t ret = offlineEffectChain_->GetEffectBufferSize(batchMaxInputSize, batchMaxOutputSize);
    CHECK_RETURN_RET_ELOG(ret != 0, MEDIA_ERR, "AudioDeferredProcessAdapter::GetMaxBufferSize Err");
    CHECK_RETURN_RET_ELOG(singleInputSize_ * PROCESS_BATCH_SIZE > batchMaxInputSize ||
            singleOutputSize_ * PROCESS_BATCH_SIZE > batchMaxOutputSize,
        MEDIA_ERR, "AudioDeferredProcessAdapter::GetMaxBufferSize MaxBufferSize Not Enough");
    return MEDIA_OK;
}

uint32_t AudioDeferredProcessAdapter::GetSingleInputSize()
{
    return singleInputSize_;
}

void AudioDeferredProcessAdapter::FadeOneBatch(OutputArray& outputArr)
{
    float rate;
    int16_t* data = reinterpret_cast<int16_t*>(outputArr.data());
    int32_t temp;
    int32_t oneSize = outputOptions_.samplingRate / ONE_THOUSAND * DURATION_EACH_AUDIO_FRAME;
    CHECK_RETURN_ELOG(oneSize >= MAX_BATCH_OUTPUT_SIZE, "AudioDeferredProcessAdapter::FadeOneBatch arrSize overSize");
    for (int k = 0; k < oneSize; k++) {
        temp = static_cast<int32_t>(data[k]);
        rate = static_cast<float>(k) / oneSize;
        temp = temp - static_cast<int32_t>(temp * rate);
        data[k] = static_cast<int16_t>(temp);
    }
}

void AudioDeferredProcessAdapter::EffectChainProcess(InputArray& inputArr, OutputArray& outputArr)
{
    int32_t ret = offlineEffectChain_->Process(inputArr.data(), singleInputSize_ * PROCESS_BATCH_SIZE,
        outputArr.data(), singleOutputSize_ * PROCESS_BATCH_SIZE);
    CHECK_PRINT_ELOG(ret != 0, "AudioDeferredProcessAdapter::Process err");
}

void AudioDeferredProcessAdapter::ReturnToRecords(OutputArray& outputArr,
    vector<sptr<AudioBufferWrapper>>& processedRecords, uint32_t endIndex, uint32_t batchSize)
{
    CHECK_RETURN_WLOG(endIndex < batchSize, "Invalid endIndex or batchSize");
    uint32_t startIndex = endIndex - batchSize + 1;
    for (uint32_t j = 0; j < batchSize; ++ j) {
        uint8_t* temp = new uint8_t[singleOutputSize_];
        int32_t ret = memcpy_s(temp, singleOutputSize_, outputArr.data() + j * singleOutputSize_, singleOutputSize_);
        CHECK_PRINT_ELOG(ret != 0, "AudioDeferredProcessAdapter::Process returnToRecords memcpy_s err");
        CHECK_RETURN_ELOG(startIndex + j < 0, "ReturnToRecords unexpected error occured");
        processedRecords[startIndex + j]->SetAudioBuffer(temp, singleOutputSize_);
    }
}

void MemsetAndCheck(void *dest, size_t destMax, int c, size_t count)
{
    int32_t ret = memset_s(dest, destMax, c, count);
    CHECK_PRINT_ELOG(ret != 0, "AudioDeferredProcessAdapter::Process memset_s err");
}

int32_t AudioDeferredProcessAdapter::Process(vector<sptr<AudioBufferWrapper>>& audioRecords,
    vector<sptr<AudioBufferWrapper>>& processedRecords)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_WLOG(offlineEffectChain_ == nullptr, MEDIA_ERR,
        "AudioDeferredProcessAdapter::Process offlineEffectChain_ is nullptr.");
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::Process Enter");
    CHECK_RETURN_RET_ELOG(audioRecords.empty(), MEDIA_OK, "audioRecords is empty");
    uint32_t audioRecordsLen = audioRecords.size();
    InputArray inputArr{};
    OutputArray outputArr{};
    uint32_t count = 0;
    lock_guard<std::mutex> lock(mutex_);
    for (uint32_t i = 0; i < audioRecordsLen; i ++) {
        int32_t ret = memcpy_s(inputArr.data() + count * singleInputSize_, singleInputSize_,
            audioRecords[i]->GetAudioBuffer(), singleInputSize_);
        CHECK_PRINT_ELOG(ret != 0, "AudioDeferredProcessAdapter::Process memcpy_s err");
        if (i == audioRecordsLen - 1) {
            MemsetAndCheck(inputArr.data(), MAX_BATCH_INPUT_SIZE,
                0, PROCESS_BATCH_SIZE * singleInputSize_);
            EffectChainProcess(inputArr, outputArr);
            MemsetAndCheck(outputArr.data(), MAX_BATCH_OUTPUT_SIZE,
                0, PROCESS_BATCH_SIZE * singleOutputSize_);
            ReturnToRecords(outputArr, processedRecords, i, count + 1);
        } else if (count == PROCESS_BATCH_SIZE - 1 && audioRecordsLen >= PROCESS_BATCH_SIZE + 1 &&
            i >= audioRecordsLen - PROCESS_BATCH_SIZE - 1) {
            EffectChainProcess(inputArr, outputArr);
            FadeOneBatch(outputArr);
            MemsetAndCheck(outputArr.data() + singleOutputSize_, MAX_BATCH_OUTPUT_SIZE,
                0, (PROCESS_BATCH_SIZE - 1) * singleOutputSize_);
            ReturnToRecords(outputArr, processedRecords, i, PROCESS_BATCH_SIZE);
        } else if (count == PROCESS_BATCH_SIZE - 1) {
            EffectChainProcess(inputArr, outputArr);
            ReturnToRecords(outputArr, processedRecords, i, PROCESS_BATCH_SIZE);
        }
        count = (count + 1) % PROCESS_BATCH_SIZE;
    }
    return MEDIA_OK;
}

void AudioDeferredProcessAdapter::Release()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("AudioDeferredProcessAdapter::Release Enter");
    CHECK_EXECUTE(offlineEffectChain_, offlineEffectChain_->Release());
    offlineEffectChain_ = nullptr;
    offlineAudioEffectManager_ = nullptr;
}
} // CameraStandard
} // OHOS
// LCOV_EXCL_STOP