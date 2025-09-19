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

#ifndef MEDIA_MANAGER_PROXY_FUZZER_H
#define MEDIA_MANAGER_PROXY_FUZZER_H

#include "media_manager_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::CameraStandard::DeferredProcessing;

class MediaManagerProxyFuzzer {
public:
    static void MediaManagerProxyFuzzerTest(FuzzedDataProvider& fdp);
    static void MpegGetDurationFuzzerTest(FuzzedDataProvider& fdp);
    static std::shared_ptr<MediaManagerProxy> mediaManagerProxyFuzz_;
};

} // CameraStandard
} // OHOS
#endif // MEDIA_MANAGER_PROXY_FUZZER_H