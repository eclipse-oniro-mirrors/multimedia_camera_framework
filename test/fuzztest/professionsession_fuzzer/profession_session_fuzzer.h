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

#ifndef PROFESSION_SESSION_FUZZER_H
#define PROFESSION_SESSION_FUZZER_H

#include "session/profession_session.h"
#include "input/camera_manager.h"
namespace OHOS {
namespace CameraStandard {

class ProfessionSessionFuzzer {
public:
static ProfessionSession *fuzz_;

static void ProfessionSessionFuzzTest1();
static void ProfessionSessionFuzzTest2();
};
} //CameraStandard
} //OHOS
#endif //PROFESSION_SESSION_FUZZER_H