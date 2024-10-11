/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hstream_depth_data_proxy.h"

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {

HStreamDepthDataProxy::HStreamDepthDataProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IStreamDepthData>(impl) {}

HStreamDepthDataProxy::~HStreamDepthDataProxy()
{
    MEDIA_INFO_LOG("~HStreamDepthDataProxy is called");
}

int32_t HStreamDepthDataProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_START), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamDepthDataProxy Start failed, error: %{public}d", error);
    }

    return error;
}

int32_t HStreamDepthDataProxy::Stop()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_STOP), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamDepthDataProxy Stop failed, error: %{public}d", error);
    }

    return error;
}

int32_t HStreamDepthDataProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_RELEASE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamDepthDataProxy Stop failed, error: %{public}d", error);
    }
    return error;
}

int32_t HStreamDepthDataProxy::SetCallback(sptr<IStreamDepthDataCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamDepthDataProxy SetCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(static_cast<uint32_t>(
        StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_SET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamDepthDataProxy SetCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HStreamDepthDataProxy::SetDataAccuracy(int32_t dataAccuracy)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(dataAccuracy);

    int error = Remote()->SendRequest(static_cast<uint32_t>(
        StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_ACCURACY_SET), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamDepthDataProxy SetDataAccuracy failed, error: %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS