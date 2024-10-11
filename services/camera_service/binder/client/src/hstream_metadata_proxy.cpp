/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hstream_metadata_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
HStreamMetadataProxy::HStreamMetadataProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStreamMetadata>(impl) { }

int32_t HStreamMetadataProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamMetadataInterfaceCode::CAMERA_STREAM_META_START), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamMetadataProxy::Start failed, error: %{public}d", error);
    }

    return error;
}

int32_t HStreamMetadataProxy::Stop()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamMetadataInterfaceCode::CAMERA_STREAM_META_STOP), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamMetadataProxy::Stop failed, error: %{public}d", error);
    }

    return error;
}

int32_t HStreamMetadataProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamMetadataInterfaceCode::CAMERA_STREAM_META_RELEASE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamMetadataProxy::Release failed, error: %{public}d", error);
    }

    return error;
}
} // namespace CameraStandard
} // namespace OHOS
