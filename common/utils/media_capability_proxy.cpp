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

#include "media_capability_proxy.h"
#include "camera_log.h"

namespace OHOS::CameraStandard {
    
MediaCapabilityProxy::MediaCapabilityProxy()
{
    MEDIA_DEBUG_LOG("entered.");
}

bool MediaCapabilityProxy::Marshalling(Parcel& data) const
{
    auto ret = data.WriteBool(isBFrame_);
    CHECK_RETURN_RET_ELOG(!ret, false, "Write BFrame filed.");
    return ret;
}

MediaCapabilityProxy* MediaCapabilityProxy::Unmarshalling(Parcel& parcel)
{
    MediaCapabilityProxy* mediaCapabilityProxy = new (std::nothrow) MediaCapabilityProxy();
    CHECK_RETURN_RET(mediaCapabilityProxy == nullptr, nullptr);

    auto isBFrame = parcel.ReadBool();
    mediaCapabilityProxy->SetBFrameSupported(isBFrame);
    return mediaCapabilityProxy;
}

bool MediaCapabilityProxy::GetBFrameSupported() const
{
    return isBFrame_;
}

void MediaCapabilityProxy::SetBFrameSupported(bool isBFrame)
{
    MEDIA_DEBUG_LOG("SetBFrameSupported: %{public}d", isBFrame);
    isBFrame_ = isBFrame;
}
} // namespace OHOS::CameraStandard