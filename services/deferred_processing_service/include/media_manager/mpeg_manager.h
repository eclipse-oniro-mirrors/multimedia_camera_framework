/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
    sptr<Surface> GetMakerSurface();
    uint64_t GetProcessTimeStamp();
    MediaManagerError NotifyEnd();
    sptr<IPCFileDescriptor> GetResultFd();

private:
    class VideoCodecCallback;
    class VideoMakerListener;

    MediaManagerError InitVideoCodec();
    void UnInitVideoCodec();
    MediaManagerError ReleaseBuffer(uint32_t index);
    MediaManagerError InitVideoMakerSurface();
    void UnInitVideoMaker();
    sptr<SurfaceBuffer> AcquireMakerBuffer(int64_t& timestamp);
    MediaManagerError ReleaseMakerBuffer(sptr<SurfaceBuffer>& buffer);
    void OnBufferAvailable(uint32_t index, const std::shared_ptr<AVBuffer>& buffer);
    void OnMakerBufferAvailable();
    sptr<IPCFileDescriptor> GetFileFd(const std::string& requestId, int flags, const std::string& tag);

    std::mutex makerMutex_;
    std::unique_ptr<MediaManager> mediaManager_ {nullptr};
    sptr<Surface> codecSurface_ {nullptr};
    sptr<Surface> makerSurface_ {nullptr};
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