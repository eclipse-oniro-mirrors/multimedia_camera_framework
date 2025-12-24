/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_THREAD_PRIORITY_UTIL_H
#define OHOS_CAMERA_THREAD_PRIORITY_UTIL_H
 
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include "camera_log.h"

namespace OHOS::CameraStandard {
// vip_prio node priority define
enum VipPrioLevel {
    VIP_PRIO_LEVEL_0 = 0, // 0 is invalid
    VIP_PRIO_LEVEL_1 = 1, // lowest priority
    VIP_PRIO_LEVEL_2 = 2,
    VIP_PRIO_LEVEL_3 = 3,
    VIP_PRIO_LEVEL_4 = 4,
    VIP_PRIO_LEVEL_5 = 5,
    VIP_PRIO_LEVEL_6 = 6,
    VIP_PRIO_LEVEL_7 = 7,
    VIP_PRIO_LEVEL_8 = 8,
    VIP_PRIO_LEVEL_9 = 9,
    VIP_PRIO_LEVEL_10 = 10 // highest priority
};
 
static void WriteContent(const char *filePath, const char *content)
{
    if (content == nullptr || filePath == nullptr) {
        MEDIA_ERR_LOG("%s(%d): invalid params!\n", __FUNCTION__, __LINE__);
        return;
    }
 
    size_t len = strlen(content);
    if (len == 0) {
        MEDIA_ERR_LOG("%s(%d): len is less zero, len=%zu\n", __FUNCTION__, __LINE__, len);
        return;
    }
 
    int fd = open(filePath, O_WRONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("%s(%d): open %s fail errno(%d)!\n", __FUNCTION__, __LINE__, filePath, errno);
        return;
    }
 
    if (static_cast<size_t>(write(fd, content, len)) != len) {
        MEDIA_ERR_LOG("%s(%d): write %s to %s fail errno(%d)!\n", __FUNCTION__, __LINE__, content, filePath, errno);
    }
    close(fd);
}
 
static void SetVipPrioThread(VipPrioLevel level)
{
    pid_t pid = getpid();
    pid_t tid = gettid();
    // vip_prio 1~10, static_vip 1
    std::string path = "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/vip_prio";
    MEDIA_DEBUG_LOG("%s path = %s, level = %d\n", __FUNCTION__, path.c_str(), level);
    WriteContent(path.c_str(), std::to_string(level).c_str());
}
}
#endif