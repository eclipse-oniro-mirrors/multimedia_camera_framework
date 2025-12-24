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
#include "dps_fd.h"
#include "media_manager.h"
#include "media_progress_notifier.h"
#include "pixel_map.h"

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

    MediaManagerError Init(const std::string& requestId, const DpsFdPtr& inputFd, int32_t width, int32_t height);
    MediaManagerError UnInit(const MediaResult result);
    sptr<Surface> GetSurface();
    sptr<Surface> GetMakerSurface();
    uint64_t GetProcessTimeStamp();
    uint32_t GetDuration();
    MediaManagerError NotifyEnd();
    DpsFdPtr GetResultFd();
    void AddUserMeta(std::unique_ptr<MediaUserInfo> userInfo);
    void SetProgressNotifer(std::unique_ptr<MediaProgressNotifier> processNotifer);

private:
    class VideoCodecCallback;
    class VideoMakerListener;

    MediaManagerError InitVideoCodec(int32_t width, int32_t height);
    MediaManagerError ConfigVideoCodec(const CodecInfo& codecInfo, int32_t width, int32_t height);
    bool UnInitVideoCodec();
    MediaManagerError ReleaseBuffer(uint32_t index);
    MediaManagerError InitVideoMakerSurface();
    void UnInitVideoMaker();
    sptr<SurfaceBuffer> AcquireMakerBuffer(int64_t& timestamp);
    MediaManagerError ReleaseMakerBuffer(sptr<SurfaceBuffer>& buffer);
    void OnBufferAvailable(uint32_t index, const std::shared_ptr<AVBuffer>& buffer);
    void OnMakerBufferAvailable();
    DpsFdPtr GetFileFd(const std::string& requestId, int flags, const std::string& tag);
    bool CheckFilePath(const std::string& path);
    std::shared_ptr<AVBuffer> CreateWatermarkBuffer(const std::string& infoParam);
    void ParseWatermarkConfigFromJson(WaterMarkInfo& waterMarkInfo, const std::string& infoParam);

    std::mutex mediaInfoMutex_;
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
    DpsFdPtr outputFd_ {nullptr};
    DpsFdPtr tempFd_ {nullptr};
    MediaResult result_ {FAIL};
    std::unique_ptr<MediaProgressNotifier> processNotifer_ {nullptr};
    std::mutex eosMutex_;
    std::condition_variable eosCondition_;
    bool eos_ {false};
    std::atomic_int32_t videoNum_ {0};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MPEG_MANAGER_H