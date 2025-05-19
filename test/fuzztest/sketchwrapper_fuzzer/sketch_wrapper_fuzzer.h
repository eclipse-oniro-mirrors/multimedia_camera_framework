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

#ifndef SKETCHWRAPPER_FUZZER_H
#define SKETCHWRAPPER_FUZZER_H

#include "sketch_wrapper.h"
#include <memory>

namespace OHOS {
namespace CameraStandard {
class SketchWrapperFuzzer {
public:
static std::shared_ptr<SketchWrapper> fuzz_;
static void SketchWrapperFuzzTest1();
static void SketchWrapperFuzzTest2();
};
} //CameraStandard
} //OHOS
#endif //SKETCHWRAPPER_FUZZER_H

