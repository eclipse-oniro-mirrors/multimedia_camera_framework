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
#ifndef AV_CODEC_INTERFACE_H
#define AV_CODEC_INTERFACE_H

#include <cstdint>
#include <vector>

/**
 * @brief Internal usage only, for camera framework interacts with av_codec related interfaces.
 * @since 12
 */
namespace OHOS::CameraStandard {
class AVCodecIntf {
public:
    virtual ~AVCodecIntf() = default;
    virtual bool IsBframeSupported(int32_t videoCodecType) = 0;
    virtual int32_t GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes) = 0;
};
}  // namespace OHOS::CameraStandard
#endif // AV_CODEC_INTERFACE_H