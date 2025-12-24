/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CFILTER_H
#define OHOS_CAMERA_CFILTER_H

#include <condition_variable>
#include <mutex>

#include "avbuffer_queue_producer.h"
#include "event.h"
#include "osal/task/task.h"

namespace OHOS {
namespace CameraStandard {
using namespace Media;

class CFilter;

enum class CFilterType {
    AUDIO_ENC,
    AUDIO_DEC,
    VIDEO_ENC,
    VIDEO_DEC,
    MUXER,
    DEMUXER,
    AUDIO_CAPTURE,
    AUDIO_FORK,
    AUDIO_PROCESS,
    TIMED_METADATA,
    DEFER_VIDEO_SOURCE,
    DEFER_AUDIO_SOURCE,
    DEFER_META_SOURCE,
    IMAGE_EFFECT,
    MOVING_PHOTO_AUDIO_CACHE,
    MOVING_PHOTO_VIDEO_CACHE,
    MOVING_PHOTO_META_CACHE,
    MOVING_PHOTO_AUDIO_ENCODE,
    MOVING_PHOTO_VIDEO_ENCODE,
    MOVING_PHOTO_AUDIO_CAPTURE,
    MOVING_PHOTO_MUXER,
    CINEMATIC_VIDEO_CACHE,
    MAX,
};

enum class CStreamType {
    PACKED,
    ENCODED_AUDIO,
    ENCODED_VIDEO,
    ENCODED_METADATA,
    RAW_AUDIO,
    RAW_VIDEO,
    RAW_METADATA,
    FORK_AUDIO,
    SUBTITLE,
    CACHED_VIDEO,
    PROCESSED_AUDIO,
    MAX,
};

enum class CFilterState {
    CREATED,     // CFilter created
    INITIALIZED, // Init called
    PREPARING,   // Prepare called
    READY,       // Ready Event reported
    RUNNING,     // Start called
    PAUSED,      // Pause called
    STOPPED,     // Stop called
    RELEASED,    // Release called
    ERROR,       // State fail
};

enum class CFilterCallBackCommand {
    NEXT_FILTER_NEEDED,
    NEXT_FILTER_REMOVED,
    NEXT_FILTER_UPDATE,
    FILTER_CALLBACK_COMMAND_MAX,
};

enum class BufferQueueBufferAVailable : int {
    BUFFER_AVAILABLE_IN_PORT = 0,
    BUFFER_AVAILABLE_OUT_PORT = 1,
};

class CEventReceiver {
public:
    virtual ~CEventReceiver() = default;
    virtual void OnEvent(const Event& event) = 0;
    virtual void OnDfxEvent(const DfxEvent& event)
    {
        (void)event;
    }
    virtual void NotifyRelease() {}
};

class CFilterCallback {
public:
    virtual ~CFilterCallback() = default;
    virtual Status OnCallback(
        const std::shared_ptr<CFilter>& filter, CFilterCallBackCommand cmd, CStreamType outType) = 0;
    virtual void NotifyRelease() {}
};

class CFilterLinkCallback {
public:
    virtual ~CFilterLinkCallback() = default;
    virtual void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) = 0;
    virtual void OnUnlinkedResult(std::shared_ptr<Meta>& meta) = 0;
    virtual void OnUpdatedResult(std::shared_ptr<Meta>& meta) = 0;
    virtual void OnLinkedResult(sptr<Surface> surface) {};
};

class CFilter {
public:
    explicit CFilter(const std::string& name, CFilterType type, bool asyncMode = false);
    virtual ~CFilter();

    virtual void Init(
        const std::shared_ptr<CEventReceiver>& receiver, const std::shared_ptr<CFilterCallback>& callback);
    virtual void LinkPipeLine(const std::string& groupId, bool needTurbo = false) final;
    virtual Status Prepare() final;
    virtual Status Start() final;
    virtual Status Pause() final;
    virtual Status PauseDragging() final;
    virtual Status PauseAudioAlign() final;
    virtual Status Resume() final;
    virtual Status ResumeDragging() final;
    virtual Status ResumeAudioAlign() final;
    virtual Status Stop() final;
    virtual Status Flush() final;
    virtual Status Release() final;
    virtual Status Preroll() final;
    virtual Status WaitPrerollDone(bool render) final;
    virtual void StartCFilterTask() final;
    virtual void PauseCFilterTask() final;
    virtual Status SetPlayRange(int64_t start, int64_t end) final;
    virtual Status ProcessInputBuffer(int sendArg = 0, int64_t delayUs = 0) final;
    virtual Status ProcessOutputBuffer(int sendArg = 0, int64_t delayUs = 0, bool byIdx = false, uint32_t idx = 0,
        int64_t renderTime = -1) final;
    virtual Status WaitAllState(CFilterState state) final;
    virtual Status SetPerfRecEnabled(bool isPerfRecEnabled) final;
    virtual void SetClusterId(int32_t clusterId) final;
    virtual Status GetClusterId(int32_t& clusterId) final;
    virtual Status DoSetPerfRecEnabled(bool isPerfRecEnabled);
    virtual Status DoInitAfterLink();
    virtual Status DoPrepare();
    virtual Status DoStart();
    virtual Status DoPause();
    virtual Status DoPauseDragging();
    virtual Status DoPauseAudioAlign();
    virtual Status DoResume();
    virtual Status DoResumeDragging();
    virtual Status DoResumeAudioAlign();
    virtual Status DoStop();
    virtual Status DoFlush();
    virtual Status DoRelease();
    virtual Status DoPreroll();
    virtual Status DoWaitPrerollDone(bool render);
    virtual Status DoSetPlayRange(int64_t start, int64_t end);
    virtual Status DoProcessInputBuffer(int recvArg, bool dropFrame);
    virtual Status DoProcessOutputBuffer(int recvArg, bool dropFrame, bool byIdx, uint32_t idx, int64_t renderTime);
    virtual void SetParameter(const std::shared_ptr<Meta>& meta);
    virtual void GetParameter(std::shared_ptr<Meta>& meta);
    virtual Status LinkNext(const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType) = 0;
    virtual Status UpdateNext(const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType);
    virtual Status UnLinkNext(const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType);
    CFilterType GetCFilterType();
    virtual Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) = 0;
    virtual Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta, 
        const std::shared_ptr<CFilterLinkCallback>& callback);
    virtual Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback);
    virtual Status ClearAllNextCFilters();
    virtual Status SetMuted(bool isMuted)
    {
        (void)isMuted;
        return Status::OK;
    }
    virtual sptr<Surface> GetInputSurface()
    {
        return nullptr;
    }

    inline std::string GetName()
    {
        return name_;
    }

    inline void SetStreamStarted(bool isStreamStarted) {}

protected:
    inline bool IsAsyncMode()
    {
        return isAsyncMode_;
    }

    std::string name_;
    std::string groupId_;
    std::shared_ptr<Meta> meta_ {nullptr};
    CFilterType filterType_;
    std::vector<CStreamType> supportedInStreams_ {};
    std::vector<CStreamType> supportedOutStreams_ {};
    std::shared_ptr<CEventReceiver> receiver_ {nullptr};
    std::shared_ptr<CFilterCallback> callback_ {nullptr};
    std::map<CStreamType, std::vector<std::shared_ptr<CFilter>>> nextCFiltersMap_ {};
    std::map<CStreamType, std::vector<std::shared_ptr<CFilterLinkCallback>>> linkCallbackMaps_ {};
    bool isPerfRecEnabled_ {false};
    int32_t clusterId_{0};

private:
    void ChangeState(CFilterState state);
    void SetErrCode(Status errCode);
    Status GetErrCode();
    Status PrepareDone();
    Status StartDone();
    Status PauseDone();
    Status ResumeDone();
    Status StopDone();
    Status ReleaseDone();

    std::mutex stateMutex_;
    std::condition_variable cond_;
    CFilterState curState_ {CFilterState::CREATED};
    Status errCode_ {Status::OK};
    std::mutex generationMutex_;
    int64_t jobIdx_ {0};
    int64_t jobIdxBase_ {0};
    std::unique_ptr<Task> filterTask_ {nullptr};
    bool isAsyncMode_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CFILTER_H
