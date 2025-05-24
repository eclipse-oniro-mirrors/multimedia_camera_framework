/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_DEPTH_DATA_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_DEPTH_DATA_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"

#include "camera_worker_queue_keeper_taihe.h"

#include "camera_output_capability.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
class DepthDataImpl : public std::enable_shared_from_this<DepthDataImpl> {
public:
    DepthDataImpl(OHOS::CameraStandard::CameraFormat format, OHOS::CameraStandard::DepthDataAccuracy dataAccuracy,
        int32_t qualityLevel) : format_(format), dataAccuracy_(dataAccuracy), qualityLevel_(qualityLevel) {}
    DepthDataImpl() = delete;

    ~DepthDataImpl() {}
    CameraFormat GetFormat();
    DepthDataQualityLevel GetQualityLevel();
    DepthDataAccuracy GetDataAccuracy();

    inline int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<uintptr_t>(this);
    }

    static uint32_t depthDataTaskId_;
private:
    OHOS::CameraStandard::CameraFormat format_ = OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_INVALID;
    OHOS::CameraStandard::DepthDataAccuracy dataAccuracy_ =
        OHOS::CameraStandard::DepthDataAccuracy::DEPTH_DATA_ACCURACY_INVALID;
    int32_t qualityLevel_ = 0;
};

struct DepthDataTaiheAsyncContext : public TaiheAsyncContext {
    DepthDataTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    std::shared_ptr<DepthDataImpl> objectInfo = nullptr;

    ~DepthDataTaiheAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace Camera
} // namespace Ani
#endif // FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_DEPTH_DATA_TAIHE_H