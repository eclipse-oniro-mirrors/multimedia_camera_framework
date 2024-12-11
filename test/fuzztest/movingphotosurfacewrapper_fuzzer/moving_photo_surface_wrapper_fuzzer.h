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

#ifndef MOVING_PHOTO_SURFACE_WRAPPER_FUZZER_H
#define MOVING_PHOTO_SURFACE_WRAPPER_FUZZER_H

#include "moving_photo_surface_wrapper.h"

namespace OHOS {
namespace CameraStandard {

class MovingPhotoSurfaceWrapperFuzzer {
public:
static MovingPhotoSurfaceWrapper *fuzz_;
static MovingPhotoSurfaceWrapper::BufferConsumerListener *listener_;
static void MovingPhotoSurfaceWrapperFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //MOVING_PHOTO_SURFACE_WRAPPER_FUZZER_H