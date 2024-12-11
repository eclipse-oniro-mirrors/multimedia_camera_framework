 /*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HSTREAM_METADATA_CALLBACK_PROXY_FUZZER_H
#define HSTREAM_METADATA_CALLBACK_PROXY_FUZZER_H

#include "hstream_metadata_callback_proxy.h"

namespace OHOS {
namespace CameraStandard {

class HStreamMetadataCallbackProxyFuzzer {
public:
static HStreamMetadataCallbackProxy *fuzz_;
static void HStreamMetadataCallbackProxyFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //HSTREAM_METADATA_CALLBACK_PROXY_FUZZER_H