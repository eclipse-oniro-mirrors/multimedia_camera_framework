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

#ifndef COMMAND_SERVER_IMPL_FUZZER_H
#define COMMAND_SERVER_IMPL_FUZZER_H

#include "command_server_impl.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
class CommandServerImplFuzzer {
public:
static CommandServerImpl *fuzz_;
static void CommandServerImplFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //COMMAND_SERVER_IMPL_FUZZER_H