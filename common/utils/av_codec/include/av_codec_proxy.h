/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef AV_CODEC_PROXY_H
#define AV_CODEC_PROXY_H
#include "av_codec_interface.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {
class AVCodecProxy : public AVCodecIntf {
public:
    explicit AVCodecProxy(
        std::shared_ptr<Dynamiclib> avcodecLib, std::shared_ptr<AVCodecIntf> avcodecIntf);
    static std::shared_ptr<AVCodecProxy> CreateAVCodecProxy();
    ~AVCodecProxy();
    bool IsBframeSupported(int32_t videoCodecType) override;
    int32_t GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes) override;
private:
    std::shared_ptr<Dynamiclib> avcodecLib_ = {nullptr};
    std::shared_ptr<AVCodecIntf> avcodecIntf_ = {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // AV_CODEC_PROXY_H