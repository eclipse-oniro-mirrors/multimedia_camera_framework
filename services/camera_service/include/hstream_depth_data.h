/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_STREAM_DEPTH_DATA_H
#define OHOS_CAMERA_H_STREAM_DEPTH_DATA_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <refbase.h>

#include "camera_metadata_info.h"
#include "hstream_common.h"
#include "hstream_depth_data_stub.h"
#include "istream_depth_data_callback.h"
#include "v1_0/istream_operator.h"

namespace OHOS {
namespace CameraStandard {

enum class DepthDataStreamStatus {
    STOPED,
    STARTED
};

class HStreamDepthData : public HStreamDepthDataStub, public HStreamCommon {
public:
    HStreamDepthData(
        sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height);
    ~HStreamDepthData();

    int32_t LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_1& streamInfo) override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t SetCallback(sptr<IStreamDepthDataCallback>& callback) override;
    int32_t OnDepthDataError(int32_t errorType);
    int32_t SetDataAccuracy(int32_t accuracy) override;
    void DumpStreamInfo(CameraInfoDumper& infoDumper) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;

private:
    sptr<IStreamDepthDataCallback> streamDepthDataCallback_;
    std::mutex callbackLock_;
    std::mutex streamStartStopLock_;
    wptr<HStreamDepthData> parentStreamDepthData_;
    DepthDataStreamStatus depthDataStreamStatus_ = DepthDataStreamStatus::STOPED;
    sptr<OHOS::IBufferProducer> metaProducer_;
    std::vector<int32_t> streamDepthDataAccuracy_ = {};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_DEPTH_DATA_H