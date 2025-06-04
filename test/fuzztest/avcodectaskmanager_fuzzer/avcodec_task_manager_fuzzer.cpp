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

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 35;
const int32_t CONST_2 = 2;
std::shared_ptr<AvcodecTaskManager> AvcodecTaskManagerFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/

void AvcodecTaskManagerFuzzer::AvcodecTaskManagerFuzzTest(FuzzedDataProvider& fdp)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType mode = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>()
        % (VideoCodecType::VIDEO_ENCODE_TYPE_HEVC + CONST_2));
    ColorSpace color = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>()
        % (ColorSpace::H_LOG + CONST_2));
    fuzz_ = std::make_shared<AvcodecTaskManager>(session, mode, color);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetTaskManager();
    fuzz_->GetEncoderManager();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    GraphicTransformType formType = static_cast<GraphicTransformType>(fdp.ConsumeIntegral<uint8_t>()
        % (GraphicTransformType::GRAPHIC_ROTATE_BUTT + CONST_2));
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    sptr<FrameRecord> frameRecord =
    new(std::nothrow) FrameRecord(videoBuffer, timestamp, formType);
    function<void()> task = []() {};
    fuzz_->SubmitTask(task);
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = nullptr;
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    int32_t captureRotation = fdp.ConsumeIntegral<int32_t>();
    int64_t taskName = fdp.ConsumeIntegral<int64_t>();
    fuzz_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    vector<sptr<FrameRecord>> frameRecords;
    fuzz_->DoMuxerVideo(frameRecords, taskName, captureRotation, captureId);
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = fdp.ConsumeIntegral<int64_t>();
    fuzz_->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId);
    vector<sptr<AudioRecord>> audioRecordVec;
    sptr<AudioVideoMuxer> muxer;
    fuzz_->CollectAudioBuffer(audioRecordVec, muxer);
    fuzz_->videoEncoder_ = nullptr;
    fuzz_->audioEncoder_ = make_unique<AudioEncoder>();
    fuzz_->Stop();
}

void Test(uint8_t* data, size_t size)
{
    auto avcodecTaskManager = std::make_unique<AvcodecTaskManagerFuzzer>();
    if (avcodecTaskManager == nullptr) {
        MEDIA_INFO_LOG("avcodecTaskManager is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    avcodecTaskManager->AvcodecTaskManagerFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}