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

#ifndef MOVING_PHOTO_PROXY_FUZZER_H
#define MOVING_PHOTO_PROXY_FUZZER_H

#include "moving_photo_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {

class MovingPhotoProxyFuzzer {
public:
    static sptr<AvcodecTaskManagerIntf> taskManagerfuzz_;
    static sptr<AudioCapturerSessionIntf> capturerSessionfuzz_;
    static sptr<MovingPhotoVideoCacheIntf> videoCachefuzz_;
    static void MovingPhotoProxyFuzzTest(FuzzedDataProvider& fdp);
    static void SetVideoIdFuzzTest(FuzzedDataProvider& fdp);
    static void SetDeferredVideoEnhanceFlagFuzzTest(FuzzedDataProvider& fdp);
    static void RecordVideoTypeFuzzTest(FuzzedDataProvider& fdp);
};

} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_PROXY_FUZZER_H
