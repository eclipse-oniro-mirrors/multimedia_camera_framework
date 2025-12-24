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
#ifndef OHOS_CAMERA_DPS_MEDIA_MANAGER_INTERFACE_H
#define OHOS_CAMERA_DPS_MEDIA_MANAGER_INTERFACE_H

#include "dps_fd.h"
#include "media_progress_notifier.h"
#include "refbase.h"
#include "surface.h"
#include "media_format_info.h"

namespace OHOS {
class IPCFileDescriptor;
namespace CameraStandard {
namespace DeferredProcessing {
class MediaManagerIntf : public RefBase {
public:
    virtual ~MediaManagerIntf() = default;
    virtual int32_t MpegAcquire(const std::string& requestId, const DpsFdPtr& inputFd,
        int32_t width, int32_t height) = 0;
    virtual int32_t MpegUnInit(const int32_t result) = 0;
    virtual DpsFdPtr MpegGetResultFd() = 0;
    virtual void MpegAddUserMeta(std::unique_ptr<MediaUserInfo> userInfo) = 0;
    virtual uint64_t MpegGetProcessTimeStamp() = 0;
    virtual sptr<Surface> MpegGetSurface() = 0;
    virtual sptr<Surface> MpegGetMakerSurface() = 0;
    virtual int32_t MpegRelease() = 0;
    virtual uint32_t MpegGetDuration() = 0;
    virtual int32_t MpegSetProgressNotifer(std::unique_ptr<MediaProgressNotifier> processNotifer) = 0;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MEDIA_MANAGER_INTERFACE_H