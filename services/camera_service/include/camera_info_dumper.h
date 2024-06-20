/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_INFO_DUMPER_H
#define OHOS_CAMERA_INFO_DUMPER_H

#include <list>
#include <stdint.h>
#include <string>

namespace OHOS {
namespace CameraStandard {
class CameraInfoDumper {
public:
    explicit CameraInfoDumper(int outFd) : outFd_(outFd) {}
    void Title(const char* msg);
    void Title(const std::string msg);
    void Msg(const char* msg);
    void Msg(const std::string msg);
    void Tip(const char* msg);
    void Tip(const std::string msg);

    void Push();
    void Pop();
    void Print();

private:
    std::string dumperString_;
    int outFd_;
    int32_t depth_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_INFO_DUMPER_H
