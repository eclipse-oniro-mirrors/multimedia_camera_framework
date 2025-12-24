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

#ifndef OHOS_CAMERA_MOVIE_FILE_CONTROLLER_BASE_H
#define OHOS_CAMERA_MOVIE_FILE_CONTROLLER_BASE_H

#include <memory>
#include <mutex>

#include "camera_types.h"
#include "camera_util.h"
#include "istream_repeat_callback.h"
#include "surface.h"
#include "movie_file_common_const.h"


namespace OHOS {
namespace CameraStandard {
class MovieFileControllerBase : public std::enable_shared_from_this<MovieFileControllerBase> {
public:
    enum class ControllerStatus : int32_t {
        IDLE = 0,
        RUNNING,
        PAUSED,
        STOPED,
        STATUS_MAX,
    };

public:
    virtual ~MovieFileControllerBase() = default;

    virtual int32_t MuxMovieFileStart(int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition) = 0;
    virtual void MuxMovieFilePause(int64_t timestamp) = 0;
    virtual void MuxMovieFileResume() = 0;
    virtual std::string MuxMovieFileStop(int64_t timestamp) = 0;

    virtual bool WaitFirstFrame() = 0;

    virtual void ChangeCodecSettings(
        VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate) = 0;
    virtual void AddVideoFilter(const std::string& filterName, const std::string& filterParam) = 0;
    virtual void RemoveVideoFilter(const std::string& filterName) = 0;

    virtual sptr<IBufferProducer> GetVideoProducer() = 0;
    virtual sptr<IBufferProducer> GetRawVideoProducer() = 0;
    virtual sptr<IBufferProducer> GetMetaProducer() = 0;

    virtual void ReleaseConsumer() = 0;

    virtual sptr<IStreamRepeatCallback> GetVideoStreamCallback() = 0;

    void inline StatusTransfer(ControllerStatus nextStatus, std::function<void()> fun)
    {
        std::lock_guard<std::mutex> lock(controllerStatusMutex_);
        auto availableStatus = statusTransferMap_[static_cast<int32_t>(controllerStatus_)];
        if (std::find(availableStatus.begin(), availableStatus.end(), nextStatus) != availableStatus.end()) {
            if (fun) {
                fun();
            }
            controllerStatus_ = nextStatus;
        }
    }

private:
    std::mutex controllerStatusMutex_;
    ControllerStatus controllerStatus_ = ControllerStatus::IDLE;
    std::vector<ControllerStatus> statusTransferMap_[static_cast<int32_t>(ControllerStatus::STATUS_MAX)] = {
        { ControllerStatus::RUNNING, ControllerStatus::STOPED }, // IDLE
        { ControllerStatus::PAUSED, ControllerStatus::STOPED },  // RUNNING
        { ControllerStatus::RUNNING, ControllerStatus::STOPED }, // PAUSED
        { ControllerStatus::RUNNING }                            // STOPED
    };
};

} // namespace CameraStandard
} // namespace OHOS

#endif