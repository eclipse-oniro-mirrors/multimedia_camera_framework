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

#ifndef OHOS_CAMERA_DEPTH_DATA_OUTPUT_H
#define OHOS_CAMERA_DEPTH_DATA_OUTPUT_H

#include <cstdint>
#include "camera_output_capability.h"
#include "capture_output.h"
#include "hstream_depth_data_callback_stub.h"
#include "icamera_service.h"
#include "istream_depth_data.h"
#include "istream_depth_data_callback.h"

namespace OHOS {
namespace CameraStandard {

class DepthDataStateCallback {
public:
    DepthDataStateCallback() = default;
    virtual ~DepthDataStateCallback() = default;

    /**
     * @brief Called when error occured during depth data rendering.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for depth data callback error.
     */
    virtual void OnDepthDataError(const int32_t errorCode) const = 0;
};

class DepthDataOutput : public CaptureOutput {
public:
    explicit DepthDataOutput(sptr<IBufferProducer> bufferProducer);
    virtual ~DepthDataOutput();

    /**
     * @brief Start depth data stream.
     */
    int32_t Start();

    /**
     * @brief stop depth data stream.
     */
    int32_t Stop();

    /**
     * @brief set depth data accuracy.
     */
    int32_t SetDataAccuracy(int32_t dataAccuracy);

    /**
     * @brief Create Stream.
     */
    int32_t CreateStream() override;

    /**
     * @brief Releases a instance of the depth data output.
     */
    int32_t Release() override;

    /**
     * @brief Set the depth data callback for the depth data output.
     *
     * @param DepthDataStateCallback to be triggered.
     */
    void SetCallback(std::shared_ptr<DepthDataStateCallback> callback);

    /**
     * @brief Get the application callback information.
     *
     * @return Returns the pointer application callback.
     */
    std::shared_ptr<DepthDataStateCallback> GetApplicationCallback();

    void OnNativeRegisterCallback(const std::string& eventString);
    void OnNativeUnregisterCallback(const std::string& eventString);
private:
    int32_t DepthDataFormat_;
    Size DepthDataSize_;
    std::shared_ptr<DepthDataStateCallback> appCallback_;
    sptr<IStreamDepthDataCallback> svcCallback_;
    void CameraServerDied(pid_t pid) override;
};

class DepthDataOutputCallbackImpl : public HStreamDepthDataCallbackStub {
public:
    wptr<DepthDataOutput> depthDataOutput_ = nullptr;
    DepthDataOutputCallbackImpl() : depthDataOutput_(nullptr) {}
 
    explicit DepthDataOutputCallbackImpl(DepthDataOutput* depthDataOutput) : depthDataOutput_(depthDataOutput) {}
 
    /**
     * @brief Called when error occured during depth data rendering.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for depth data callback error.
     */
    int32_t OnDepthDataError(int32_t errorCode) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEPTH_DATA_OUTPUT_H