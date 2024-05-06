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

#ifndef OHOS_CAMERA_H_STREAM_REPEAT_H
#define OHOS_CAMERA_H_STREAM_REPEAT_H

#include <cstdint>
#include <iostream>
#include <refbase.h>

#include "camera_metadata_info.h"
#include "hstream_common.h"
#include "hstream_repeat_stub.h"
#include "istream_repeat_callback.h"
#include "v1_0/istream_operator.h"

namespace OHOS {
namespace CameraStandard {
enum class RepeatStreamType {
    PREVIEW,
    VIDEO,
    SKETCH
};

enum class RepeatStreamStatus {
    STOPED,
    STARTED
};

class HStreamRepeat : public HStreamRepeatStub, public HStreamCommon {
public:
    HStreamRepeat(
        sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height, RepeatStreamType type);
    ~HStreamRepeat();

    int32_t LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_1& streamInfo) override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t Start() override;
    int32_t Start(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    int32_t Stop() override;
    int32_t SetCallback(sptr<IStreamRepeatCallback>& callback) override;
    int32_t OnFrameStarted();
    int32_t OnFrameEnded(int32_t frameCount);
    int32_t OnFrameError(int32_t errorType);
    int32_t OnSketchStatusChanged(SketchStatus status);
    int32_t AddDeferredSurface(const sptr<OHOS::IBufferProducer>& producer) override;
    int32_t ForkSketchStreamRepeat(
        int32_t width, int32_t height, sptr<IStreamRepeat>& sketchStream, float sketchRatio) override;
    int32_t RemoveSketchStreamRepeat() override;
    int32_t EnableSecure(bool isEnable = false) override;
    int32_t UpdateSketchRatio(float sketchRatio) override;
    sptr<HStreamRepeat> GetSketchStream();
    RepeatStreamType GetRepeatStreamType();
    void DumpStreamInfo(std::string& dumpString) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate) override;

private:
    void OpenVideoDfxSwitch(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void SetStreamTransform();
    void StartSketchStream(std::shared_ptr<OHOS::Camera::CameraMetadata> settings);
    void UpdateSketchStatus(SketchStatus status);
    void ProcessCameraPosition(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition);

    RepeatStreamType repeatStreamType_;
    sptr<IStreamRepeatCallback> streamRepeatCallback_;
    std::mutex callbackLock_;
    std::mutex sketchStreamLock_; // Guard sketchStreamRepeat_
    std::mutex streamStartStopLock_;
    sptr<HStreamRepeat> sketchStreamRepeat_;
    wptr<HStreamRepeat> parentStreamRepeat_;
    float sketchRatio_ = -1.0f;
    SketchStatus sketchStatus_ = SketchStatus::STOPED;
    RepeatStreamStatus repeatStreamStatus_ = RepeatStreamStatus::STOPED;
    bool mEnableSecure = false;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_REPEAT_H
