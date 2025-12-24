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

#include "movie_file_audio_offline_algo_node.h"

#include <memory>
#include <vector>

#include "camera_log.h"
#include "movie_file_common_const.h"
#include "movie_file_common_utils.h"
#include "unified_pipeline_audio_encoded_buffer.h"

namespace OHOS {
namespace CameraStandard {
namespace {
// 注意：此处g_packageBufferList是 thread_local 类型，如果pipeline开启了多线程，这个地方需要做必要的优化适配
thread_local std::list<PipelineAudioBufferData> g_packageBufferList {};
constexpr int32_t PACKAGE_COUNT = 5;
} // namespace

const std::string MovieFileAudioOfflineAlgoNode::CHAIN_NAME_OFFLINE = "offline_record_algo";
const std::string MovieFileAudioOfflineAlgoNode::CHAIN_NAME_POST_EDIT = "record_post_edit";

MovieFileAudioOfflineAlgoNode::MovieFileAudioOfflineAlgoNode()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileAudioOfflineAlgoNode construct");
    offlineAudioEffectManager_ = std::make_unique<AudioStandard::OfflineAudioEffectManager>();
    std::vector<std::string> effectChains = offlineAudioEffectManager_->GetOfflineAudioEffectChains();
    for (auto& chain : effectChains) {
        MEDIA_INFO_LOG("MovieFileAudioOfflineAlgoNode get chain:%{public}s", chain.c_str());
        if (chain == CHAIN_NAME_POST_EDIT) {
            selectedChain_ = chain;
            break;
        }
        // 优先选择 CHAIN_NAME_POST_EDIT 算法，在找不到 CHAIN_NAME_POST_EDIT 的时候选择 CHAIN_NAME_OFFLINE
        if (chain == CHAIN_NAME_OFFLINE && selectedChain_.empty()) {
            selectedChain_ = chain;
        }
    }

    CHECK_RETURN_ELOG(
        selectedChain_.empty(), "MovieFileAudioOfflineAlgoNode GetOfflineEffectChain no effectChain needed");
    offlineEffectChain_ = offlineAudioEffectManager_->CreateOfflineAudioEffectChain(selectedChain_);
    CHECK_RETURN_ELOG(!offlineEffectChain_, "MovieFileAudioOfflineAlgoNode GetOfflineEffectChain ERR");
}

std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> MovieFileAudioOfflineAlgoNode::MakeUpResultPack(
    uint8_t* processedPtr, size_t dataSize)
{
    size_t packagesSize = g_packageBufferList.size() * oneProcessedSize_;
    if (dataSize < packagesSize) {
        MEDIA_ERR_LOG("MovieFileAudioOfflineAlgoNode MakeUpResultPack ERR");
        return nullptr;
    }
    auto packagedAudioBuffer =
        std::make_unique<UnifiedPipelineAudioPackagedBuffer>(BufferType::CAMERA_AUDIO_PACKAGED_BUFFER);
    PipelinePackagedAudioBufferData packagedData {};

    int32_t currentIndex = 0;
    for (auto& originBufferData : g_packageBufferList) {
        PipelineAudioBufferData data { .timestamp = originBufferData.timestamp,
            .data = MovieFile::CopyData(processedPtr + currentIndex * oneProcessedSize_, oneProcessedSize_),
            .dataSize = oneProcessedSize_ };
        packagedData.bufferDatas.emplace_back(data);
        currentIndex++;
    }
    if (!packagedData.bufferDatas.empty()) {
        packagedData.timestamp = packagedData.bufferDatas.front().timestamp;
    }
    packagedAudioBuffer->WrapData(packagedData);
    return packagedAudioBuffer;
}

std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> MovieFileAudioOfflineAlgoNode::ProcessBuffer(
    std::unique_ptr<UnifiedPipelineAudioBuffer> bufferIn)
{
    CHECK_RETURN_RET_ELOG(offlineEffectChain_ == nullptr, nullptr,
        "MovieFileAudioOfflineAlgoNode ProcessBuffer offlineEffectChain_ is null");
    auto bufferData = bufferIn->UnwrapData();
    MEDIA_DEBUG_LOG(
        "MovieFileAudioOfflineAlgoNode::ProcessBuffer data size is:%{public}zu g_packageBufferList size:%{public}zu",
        bufferData.dataSize, g_packageBufferList.size());
    CHECK_RETURN_RET_ELOG(bufferData.dataSize < oneUnprocessedSize_, nullptr,
        "MovieFileAudioOfflineAlgoNode::ProcessBuffer bufferData.dataSize not enough");
    g_packageBufferList.emplace_back(bufferData);
    size_t dataCount = g_packageBufferList.size();
    CHECK_RETURN_RET(dataCount < PACKAGE_COUNT, nullptr);
    // 达到缓存数量，进行内存复制
    size_t unprocessedSize = oneUnprocessedSize_ * dataCount;
    uint8_t unprocessedPtr[unprocessedSize];
    int32_t ret = memset_s(unprocessedPtr, unprocessedSize, 0, unprocessedSize);
    CHECK_PRINT_ELOG(ret != 0, "MovieFileAudioOfflineAlgoNode ProcessBuffer unprocessedPtr memset_s err");

    uint8_t* currentPtr = unprocessedPtr;
    for (auto& cachedBuffer : g_packageBufferList) {
        size_t bufferSize = cachedBuffer.dataSize;
        int ret = memcpy_s(currentPtr, oneUnprocessedSize_, cachedBuffer.data.get(), bufferSize);
        if (ret != 0) {
            MEDIA_ERR_LOG("memcpy_s failed with error code: %d", ret);
            return nullptr;
        }
        currentPtr += oneUnprocessedSize_;
    }

    size_t processedSize = oneProcessedSize_ * dataCount;
    uint8_t processedPtr[processedSize];
    ret = memset_s(processedPtr, processedSize, 0, processedSize);
    CHECK_PRINT_ELOG(ret != 0, "MovieFileAudioOfflineAlgoNode ProcessBuffer processedPtr memset_s err");

    MEDIA_DEBUG_LOG("MovieFileAudioOfflineAlgoNode::ProcessBuffer in size:%{public}zu out size:%{public}zu",
        unprocessedSize, processedSize);

    ret = offlineEffectChain_->Process(unprocessedPtr, unprocessedSize, processedPtr, processedSize);
    CHECK_RETURN_RET_ELOG(ret != 0, nullptr, "MovieFileAudioOfflineAlgoNode Process err:%{public}d", ret);
    MEDIA_DEBUG_LOG("MovieFileAudioOfflineAlgoNode::ProcessBuffer done timestamp:%{public}" PRIu64,
        g_packageBufferList.front().timestamp);

    // 算法处理完，将数据拆分成之前的包，代码处理可以保证 processedPtr 不会踩内存，无需传入数组大小
    auto packagedAduioBuffer = MakeUpResultPack(processedPtr, processedSize);
    g_packageBufferList.clear();
    return packagedAduioBuffer;
};

void MovieFileAudioOfflineAlgoNode::ProcessCommand(UnifiedPipelineCommand* command)
{
    CHECK_RETURN(command == nullptr || command->IsConsumed());
    if (command->GetCommandId() == UnifiedPipelineCommandId::AUDIO_BUFFER_START) {
        MEDIA_INFO_LOG(
            "MovieFileAudioOfflineAlgoNode::ProcessCommand AUDIO_BUFFER_START g_packageBufferList size:%{public}zu",
            g_packageBufferList.size());
        g_packageBufferList.clear();
    }
}

void MovieFileAudioOfflineAlgoNode::InitAudioProcessConfig(
    const AudioStandard::AudioStreamInfo& inputStreamInfo, const AudioStandard::AudioStreamInfo& outputStreamInfo)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(offlineEffectChain_ == nullptr, "offlineEffectChain_ is null");

    CHECK_RETURN_ELOG(offlineEffectChain_->Configure(inputStreamInfo, outputStreamInfo) != 0,
        "MovieFileAudioOfflineAlgoNode InitAudioProcessConfig Configure Err");

    CHECK_RETURN_ELOG(
        offlineEffectChain_->Prepare() != 0, "MovieFileAudioOfflineAlgoNode InitAudioProcessConfig Prepare Err");

    MEDIA_INFO_LOG(
        "MovieFileAudioOfflineAlgoNode::inputStreamInfo %{public}d %{public}d %{public}d %{public}d %{public}" PRIu64,
        inputStreamInfo.samplingRate, inputStreamInfo.encoding, inputStreamInfo.format, inputStreamInfo.channels,
        inputStreamInfo.channelLayout);

    MEDIA_INFO_LOG(
        "MovieFileAudioOfflineAlgoNode::outputStreamInfo %{public}d %{public}d %{public}d %{public}d %{public}" PRIu64,
        outputStreamInfo.samplingRate, outputStreamInfo.encoding, outputStreamInfo.format, outputStreamInfo.channels,
        outputStreamInfo.channelLayout);

    MEDIA_INFO_LOG("MovieFileAudioOfflineAlgoNode::GetMaxBufferSize Enter");
    uint32_t maxUnprocessedBufferSize = 0;
    uint32_t maxProcessedBufferSize = 0;
    CHECK_RETURN_ELOG(offlineEffectChain_->GetEffectBufferSize(maxUnprocessedBufferSize, maxProcessedBufferSize) != 0,
        "MovieFileAudioOfflineAlgoNode::GetMaxBufferSize Err");
    oneUnprocessedSize_ = inputStreamInfo.samplingRate / MOVIE_FILE_AUDIO_ONE_THOUSAND * inputStreamInfo.channels *
                          MOVIE_FILE_AUDIO_DURATION_EACH_AUDIO_FRAME * sizeof(short);
    oneProcessedSize_ = outputStreamInfo.samplingRate / MOVIE_FILE_AUDIO_ONE_THOUSAND * outputStreamInfo.channels *
                        MOVIE_FILE_AUDIO_DURATION_EACH_AUDIO_FRAME * sizeof(short);
    CHECK_RETURN_ELOG(oneUnprocessedSize_ * MOVIE_FILE_AUDIO_PROCESS_BATCH_SIZE > maxUnprocessedBufferSize ||
            oneProcessedSize_ * MOVIE_FILE_AUDIO_PROCESS_BATCH_SIZE > maxProcessedBufferSize,
        "MovieFileAudioOfflineAlgoNode::GetMaxBufferSize MaxBufferSize Not Enough");
    MEDIA_INFO_LOG("MovieFileAudioOfflineAlgoNode::InitAudioProcessConfig "
                   "oneUnprocessedSize_:%{public}d, oneProcessedSize_:%{public}d",
        oneUnprocessedSize_, oneProcessedSize_);
}

MovieFileAudioOfflineAlgoNode::~MovieFileAudioOfflineAlgoNode()
{
    MEDIA_INFO_LOG("MovieFileAudioOfflineAlgoNode destruct");
    CHECK_EXECUTE(offlineEffectChain_, offlineEffectChain_->Release());
}

} // namespace CameraStandard
} // namespace OHOS
