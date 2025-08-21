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

#ifndef STREAM_DEPTH_DATA_PROXY_FUZZER_H
#define STREAM_DEPTH_DATA_PROXY_FUZZER_H

#include "stream_depth_data_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class StreamDepthDataProxyFuzz {
public:
    static std::shared_ptr<StreamDepthDataProxy> fuzz_;
    static void StreamDepthDataProxyTest1();
    static void StreamDepthDataProxyTest2(FuzzedDataProvider &fdp);
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // STREAM_DEPTH_DATA_PROXY_FUZZER_H