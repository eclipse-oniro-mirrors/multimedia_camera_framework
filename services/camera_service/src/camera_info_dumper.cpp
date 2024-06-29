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

#include "camera_info_dumper.h"

#include <cstdint>
#include <unistd.h>

namespace OHOS {
namespace CameraStandard {
void CameraInfoDumper::Title(const char* msg)
{
    for (int32_t i = 0; i < depth_; i++) {
        dumperString_.append("    ");
    };
    for (int32_t i = 0; i < depth_; i++) {
        dumperString_.append("#");
    };
    dumperString_.append("# ");
    dumperString_.append(msg);
    dumperString_.append("\n");
}
void CameraInfoDumper::Title(const std::string msg)
{
    Title(msg.c_str());
}
void CameraInfoDumper::Msg(const char* msg)
{
    for (int32_t i = 0; i < depth_; i++) {
        dumperString_.append("    ");
    };
    for (int32_t i = 0; i < depth_; i++) {
        dumperString_.append(" ");
    };
    dumperString_.append("  ");
    dumperString_.append(msg);
    dumperString_.append("\n");
}

void CameraInfoDumper::Msg(const std::string msg)
{
    Msg(msg.c_str());
}

void CameraInfoDumper::Tip(const char* msg)
{
    dumperString_.append(msg);
    dumperString_.append("\n");
}

void CameraInfoDumper::Tip(const std::string msg)
{
    Tip(msg.c_str());
}

void CameraInfoDumper::Push()
{
    depth_++;
}

void CameraInfoDumper::Pop()
{
    depth_--;
    if (depth_ < 0) {
        depth_ = 0;
    }
}

void CameraInfoDumper::Print()
{
    if (dumperString_.empty()) {
        return;
    }
    (void)write(outFd_, dumperString_.c_str(), dumperString_.size());
}
} // namespace CameraStandard
} // namespace OHOS
