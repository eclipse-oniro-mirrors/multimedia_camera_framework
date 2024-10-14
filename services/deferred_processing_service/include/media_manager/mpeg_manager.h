/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_MPEG_MANAGER_H
#define OHOS_CAMERA_DPS_MPEG_MANAGER_H

#include "avcodec_video_encoder.h"
#include "ipc_file_descriptor.h"
#include "media_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class MpegManager : public std::enable_shared_from_this<MpegManager> {
public:
    MpegManager();
    ~MpegManager();
    MpegManager(const MpegManager&) =delete;
    MpegManager& operator=(const MpegManager&) = delete;
    MpegManager(MediaManager&&) = delete;
    MpegManager& operator=(MediaManager&&) = delete;

    MediaManagerError Init(const std::string& requestId, const sptr<IPCFileDescriptor>& inputFd);
    MediaManagerError UnInit(const MediaResult result);
    sptr<Surface> GetSurface();
    uint64_t GetProcessTimeStamp();
    MediaManagerError NotifyEnd();
    MediaManagerError ReleaseBuffer(uint32_t index);
    sptr<IPCFileDescriptor> GetResultFd();

private:
    class VideoCodecCallback;

    MediaManagerError InitVideoCodec();
    void UnInitVideoCodec();
    void OnBufferAvailable(uint32_t index, const std::shared_ptr<AVBuffer>& buffer);
    sptr<IPCFileDescriptor> GetFileFd(const std::string& requestId, int flags, const std::string& tag);

    std::unique_ptr<MediaManager> mediaManager_ {nullptr};
    sptr<Surface> codecSurface_ {nullptr};
    std::shared_ptr<AVCodecVideoEncoder> encoder_ {nullptr};
    std::atomic_bool isRunning_ {false};
    std::unique_ptr<std::thread> processThread_ {nullptr};
    std::shared_ptr<MediaInfo> mediaInfo_ {nullptr};
    std::string outPath_;
    std::string tempPath_;
    sptr<IPCFileDescriptor> outputFd_ {nullptr};
    sptr<IPCFileDescriptor> tempFd_ {nullptr};
    MediaResult result_ {FAIL};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MPEG_MANAGER_H