/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "avcodev_task_manager_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"
#include "audio_video_muxer.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 256;
const int32_t CONST_2 = 2;
const int32_t FRAME_RECORD_COUNT = 3;
const int32_t EXTEND_FRAME_RECORD_COUNT = 2;
const int32_t AUDIO_RECORD_COUNT = 3;
std::shared_ptr<AvcodecTaskManager> AvcodecTaskManagerFuzzer::fuzz_{nullptr};
sptr<AudioTaskManager> AudioTaskManagerFuzzer::audioTaskFuzz_{nullptr};

static sptr<FrameRecord> CreateFrameRecord(FuzzedDataProvider& fdp, int64_t baseTimestamp)
{
    int64_t timestamp = baseTimestamp + fdp.ConsumeIntegral<int32_t>();
    GraphicTransformType formType = static_cast<GraphicTransformType>(fdp.ConsumeIntegral<uint8_t>()
        % (GraphicTransformType::GRAPHIC_ROTATE_BUTT + CONST_2));
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    sptr<FrameRecord> frameRecord = new(std::nothrow) FrameRecord(videoBuffer, timestamp, formType);
    if (frameRecord != nullptr) {
        frameRecord->SetIDRProperty(fdp.ConsumeBool());
        frameRecord->SetMuxerIndex(fdp.ConsumeIntegral<int32_t>());
    }
    return frameRecord;
}

static vector<sptr<FrameRecord>> CreateFrameRecordVector(FuzzedDataProvider& fdp, int32_t count, int64_t baseTimestamp)
{
    vector<sptr<FrameRecord>> frameRecords;
    for (int32_t i = 0; i < count; i++) {
        sptr<FrameRecord> record = CreateFrameRecord(fdp, baseTimestamp + i);
        if (record != nullptr) {
            frameRecords.emplace_back(record);
        }
    }
    return frameRecords;
}

void AvcodecTaskManagerFuzzer::AvcodecTaskManagerFuzzTest(FuzzedDataProvider& fdp)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType mode = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>()
        % (static_cast<int32_t>(VideoCodecType::VIDEO_ENCODE_TYPE_HEVC) + CONST_2));
    ColorSpace color = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>()
        % (ColorSpace::DISPLAY_P3 + CONST_2));
    bool useSecondCtor = fdp.ConsumeBool();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(session);
    if (useSecondCtor) {
        wptr<Surface> movingSurface = nullptr;
        shared_ptr<Size> size = std::make_shared<Size>();
        fuzz_ = std::make_shared<AvcodecTaskManager>(movingSurface, size, audioTaskManager, mode, color);
    } else {
        fuzz_ = std::make_shared<AvcodecTaskManager>(session, mode, color);
    }
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetTaskManager();
    fuzz_->GetEncoderManager();

    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    int32_t captureId2 = fdp.ConsumeIntegral<int32_t>();
    int32_t captureRotation = fdp.ConsumeIntegral<int32_t>();
    uint64_t taskName = fdp.ConsumeIntegral<uint64_t>();

    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = nullptr;
    fuzz_->SetVideoFd(timestamp, photoAssetProxy, captureId);

    uint32_t preBufferCount = fdp.ConsumeIntegral<uint32_t>();
    uint32_t postBufferCount = fdp.ConsumeIntegral<uint32_t>();
    fuzz_->SetVideoBufferDuration(preBufferCount, postBufferCount);

    VideoType videoType = static_cast<VideoType>(fdp.ConsumeIntegral<uint8_t>()
        % (static_cast<int32_t>(VideoType::XT_EFFECT_VIDEO) + 1));
    fuzz_->RecordVideoType(captureId, videoType);

    uint32_t deferredVideoEnhanceFlag = fdp.ConsumeIntegral<uint32_t>();
    fuzz_->SetDeferredVideoEnhanceFlag(captureId, deferredVideoEnhanceFlag);
    fuzz_->SetDeferredVideoEnhanceFlag(captureId, deferredVideoEnhanceFlag);
    fuzz_->GetDeferredVideoEnhanceFlag(captureId);
    fuzz_->GetDeferredVideoEnhanceFlag(captureId2);

    std::string videoId = fdp.ConsumeRandomLengthString(32);
    fuzz_->SetVideoId(captureId, videoId);
    fuzz_->SetVideoId(captureId, videoId);
    fuzz_->GetVideoId(captureId);
    fuzz_->GetVideoId(captureId2);

    fuzz_->isEmptyVideoFdMap();

    int32_t calCompleteSize1 = fdp.ConsumeIntegral<int32_t>();
    int32_t calCompleteSize2 = fdp.ConsumeIntegral<int32_t>();
    int32_t calCompleteSize3 = fdp.ConsumeIntegral<int32_t>();
    fuzz_->CalComplete(calCompleteSize1);
    fuzz_->CalComplete(calCompleteSize2);
    fuzz_->CalComplete(calCompleteSize3);

    fuzz_->AsyncInitVideoCodec();

    sptr<FrameRecord> frameRecord = CreateFrameRecord(fdp, timestamp);
    fuzz_->ProcessOverTimeFrame(frameRecord);

    function<void()> task = []() {};
    fuzz_->SubmitTask(task);

    CacheCbFunc cacheCallback = [](sptr<FrameRecord> frame, bool isEncodeSuccess) {};
    fuzz_->EncodeVideoBuffer(frameRecord, cacheCallback);

    vector<sptr<FrameRecord>> frameRecords = CreateFrameRecordVector(fdp, FRAME_RECORD_COUNT, timestamp);
    vector<sptr<FrameRecord>> extendFrameRecords =
        CreateFrameRecordVector(fdp, EXTEND_FRAME_RECORD_COUNT, timestamp);
    std::shared_ptr<AVBuffer> extendXpsBuffer = nullptr;
    vector<sptr<FrameRecord>> manualFrameRecords;
    std::shared_ptr<AVBuffer> XpsBuffer;
    fuzz_->DoMuxerVideo(
        frameRecords, taskName, captureRotation, captureId);
    vector<sptr<FrameRecord>> emptyExtendFrameRecords;
    fuzz_->DoMuxerVideo(
        frameRecords, taskName, captureRotation, captureId);
    vector<sptr<FrameRecord>> emptyFrameRecords;
    fuzz_->DoMuxerVideo(
        emptyFrameRecords, taskName, captureRotation, captureId);

    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = fdp.ConsumeIntegral<int64_t>();
    int64_t backTimestamp = 0;
    fuzz_->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId, backTimestamp);

    int64_t insertStartTime = fdp.ConsumeIntegral<int64_t>();
    int64_t insertEndTime = fdp.ConsumeIntegral<int64_t>();
    fuzz_->mPStartTimeMap_[captureId] = insertStartTime;
    fuzz_->mPEndTimeMap_[captureId] = insertEndTime;
    fuzz_->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId, backTimestamp);

    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    vector<sptr<FrameRecord>> audioChoosedBuffer;
    fuzz_->CollectAudioBuffer(audioChoosedBuffer, muxer, fdp.ConsumeBool());

    sptr<SurfaceBuffer> zeroVideoBuffer = SurfaceBuffer::Create();
    sptr<FrameRecord> zeroTimestampRecord = new FrameRecord(zeroVideoBuffer, 0, GRAPHIC_ROTATE_BUTT);
    vector<sptr<FrameRecord>> zeroChoosedBuffer = {zeroTimestampRecord};
    fuzz_->CollectAudioBuffer(zeroChoosedBuffer, nullptr, fdp.ConsumeBool());

    fuzz_->WaitForAudioRecordFinished(zeroChoosedBuffer);
    fuzz_->WaitForAudioRecordFinished(emptyFrameRecords);

    fuzz_->videoEncoder_ = nullptr;
    fuzz_->audioEncoder_ = make_unique<AudioEncoder>();
    fuzz_->Stop();
    fuzz_->ClearTaskResource();
    fuzz_->Release();
    fuzz_ = nullptr;
}

void AudioTaskManagerFuzzer::AudioTaskManagerFuzzTest(FuzzedDataProvider& fdp)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    audioTaskFuzz_ = new AudioTaskManager(session);
    CHECK_RETURN_ELOG(!audioTaskFuzz_, "Create audioTaskFuzz_ Error");

    audioTaskFuzz_->GetAudioTaskManager();
    audioTaskFuzz_->GetAudioProcessManager();

    function<void()> task = []() {};
    audioTaskFuzz_->SubmitTask(task);

    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    int32_t captureId2 = fdp.ConsumeIntegral<int32_t>();
    int64_t middleTimeStamp = fdp.ConsumeIntegral<int64_t>();
    audioTaskFuzz_->ProcessAudioBuffer(captureId, middleTimeStamp);

    int64_t prepareTimeStamp = fdp.ConsumeIntegral<int64_t>();
    audioTaskFuzz_->PrepareAudioBuffer(prepareTimeStamp);

    int64_t registerTimeStamp = fdp.ConsumeIntegral<int64_t>();
    audioTaskFuzz_->RegisterAudioBuffeArrivalCallback(registerTimeStamp);

    int64_t audioTimestamp = fdp.ConsumeIntegral<int64_t>();
    sptr<AudioRecord> audioRecord = new AudioRecord(audioTimestamp);
    bool isFinished = fdp.ConsumeBool();
    audioTaskFuzz_->OnAudioBufferArrival(audioRecord, isFinished);

    vector<sptr<AudioRecord>> audioRecords;
    vector<sptr<AudioRecord>> encodeAudioRecords;
    for (int32_t i = 0; i < AUDIO_RECORD_COUNT; i++) {
        int64_t ts = fdp.ConsumeIntegral<int64_t>();
        audioRecords.emplace_back(new AudioRecord(ts));
        encodeAudioRecords.emplace_back(new AudioRecord(ts));
    }
    audioTaskFuzz_->ProcessAudioBufferToMuted(audioRecords, encodeAudioRecords);

    audioTaskFuzz_->SetTimerForAudioDeferredProcess();
    audioTaskFuzz_->ProcessAudioFromAudioBufferQueue();

    int64_t mapTimestamp = fdp.ConsumeIntegral<int64_t>();
    auto &timeMap = audioTaskFuzz_->GetCurrentCaptureIdToTimeMap();
    timeMap[captureId] = mapTimestamp;
    timeMap[captureId2] = mapTimestamp + fdp.ConsumeIntegral<int32_t>();
    audioTaskFuzz_->ClearProcessedAudioCache(captureId);
    audioTaskFuzz_->ClearProcessedAudioCache(captureId2);
    audioTaskFuzz_->RemovePreviousCaptureForTimeMap(captureId);

    audioTaskFuzz_->Release();
    audioTaskFuzz_->ClearTaskResource();
    audioTaskFuzz_ = nullptr;
}

void AudioDeferredProcessSingleFuzzer::AudioDeferredProcessSingleFuzzTest(FuzzedDataProvider& fdp)
{
    AudioDeferredProcessSingle &instance = AudioDeferredProcessSingle::GetInstance();

    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    vector<sptr<AudioRecord>> audioRecords;
    vector<sptr<AudioRecord>> processedAudioRecords;
    vector<sptr<AudioRecord>> encodeAudioRecords;
    for (int32_t i = 0; i < AUDIO_RECORD_COUNT; i++) {
        int64_t ts = fdp.ConsumeIntegral<int64_t>();
        audioRecords.emplace_back(new AudioRecord(ts));
        processedAudioRecords.emplace_back(new AudioRecord(ts));
        encodeAudioRecords.emplace_back(new AudioRecord(ts));
    }

    instance.ConfigAndProcess(session, audioRecords, processedAudioRecords);
    instance.DestroyAudioDeferredProcess();
    instance.ProcessMutedAudioBufferForVecs(session, audioRecords, encodeAudioRecords);
    instance.DestroyAudioDeferredProcess();
    instance.CreateAudioDeferredProcess(session);
    instance.DestroyAudioDeferredProcess();
    instance.TimerDestroyAudioDeferredProcess();
    instance.DestroyAudioDeferredProcess();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    uint8_t testSelector = fdp.ConsumeIntegral<uint8_t>() % 4;
    if (testSelector == 0) {
        auto fuzzer = std::make_unique<AvcodecTaskManagerFuzzer>();
        if (fuzzer != nullptr) {
            fuzzer->AvcodecTaskManagerFuzzTest(fdp);
        }
    } else if (testSelector == 2) {
        auto fuzzer = std::make_unique<AudioTaskManagerFuzzer>();
        if (fuzzer != nullptr) {
            fuzzer->AudioTaskManagerFuzzTest(fdp);
        }
    } else {
        AudioDeferredProcessSingleFuzzer::AudioDeferredProcessSingleFuzzTest(fdp);
    }
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}