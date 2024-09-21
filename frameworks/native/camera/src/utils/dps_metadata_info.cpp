/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "dps_metadata_info.h"
#include <message_parcel.h>

#define DPS_MAX_USER_DATA_COUNT 1000

namespace OHOS {
namespace CameraStandard {

DpsMetadataError DpsMetadata::ReadFromParcel(MessageParcel &parcel)
{
    int32_t size = parcel.ReadInt32();
    if (size > DPS_MAX_USER_DATA_COUNT) {
        return DPS_METADATA_INTERNAL_ERROR;
    }

    DpsMetadataError ret = DPS_METADATA_OK;
    for (int32_t i = 0; i < size; i++) {
        auto key = parcel.ReadString();
        auto type = static_cast<DpsDataType>(parcel.ReadInt32());
        switch (type) {
            case DpsDataType::i32: {
                ret = Set(key, type, parcel.ReadInt32());
                break;
            }
            case DpsDataType::i64: {
                ret = Set(key, type, parcel.ReadInt64());
                break;
            }
            case DpsDataType::f64: {
                ret = Set(key, type, parcel.ReadDouble());
                break;
            }
            case DpsDataType::string: {
                ret = Set(key, type, parcel.ReadString());
                break;
            }
            default: break;
        }

        if (ret != DPS_METADATA_OK) {
            break;
        }
    }
    return ret;
}

DpsMetadataError DpsMetadata::WriteToParcel(MessageParcel &parcel)
{
    parcel.WriteInt32(datas.size());
    for (const auto &[key, data] : datas) {
        parcel.WriteString(key);
        parcel.WriteInt32(static_cast<int32_t>(data.type));
        switch (data.type) {
            case DpsDataType::i32: {
                int32_t i32 = -1;
                auto dpVal = std::any_cast<int32_t>(&data.val);
                if (dpVal != nullptr) {
                    i32 = *dpVal;
                }
                parcel.WriteInt32(i32);
                break;
            }
            case DpsDataType::i64: {
                int64_t i64 = -1;
                auto dpVal = std::any_cast<int64_t>(&data.val);
                if (dpVal != nullptr) {
                    i64 = *dpVal;
                }
                parcel.WriteInt64(i64);
                break;
            }
            case DpsDataType::f64: {
                double f64 = -1;
                auto dpVal = std::any_cast<double>(&data.val);
                if (dpVal != nullptr) {
                    f64 = *dpVal;
                }
                parcel.WriteDouble(f64);
                break;
            }
            case DpsDataType::string: {
                std::string string = "-1";
                auto dpVal = std::any_cast<std::string>(&data.val);
                if (dpVal != nullptr) {
                    string = *dpVal;
                }
                parcel.WriteString(string);
                break;
            }
            default:
                break;
        }
    }
    return DPS_METADATA_OK;
}

DpsMetadataError DpsMetadata::Get(const std::string &key, int32_t &value) const
{
    return Get<int32_t>(key, DpsDataType::i32, value);
}

DpsMetadataError DpsMetadata::Get(const std::string &key, int64_t &value) const
{
    return Get<int64_t>(key, DpsDataType::i64, value);
}

DpsMetadataError DpsMetadata::Get(const std::string &key, double &value) const
{
    return Get<double>(key, DpsDataType::f64, value);
}

DpsMetadataError DpsMetadata::Get(const std::string &key, std::string &value) const
{
    return Get<std::string>(key, DpsDataType::string, value);
}

DpsMetadataError DpsMetadata::Set(const std::string &key, int32_t value)
{
    return Set(key, DpsDataType::i32, value);
}

DpsMetadataError DpsMetadata::Set(const std::string &key, int64_t value)
{
    return Set(key, DpsDataType::i64, value);
}

DpsMetadataError DpsMetadata::Set(const std::string &key, double value)
{
    return Set(key, DpsDataType::f64, value);
}

DpsMetadataError DpsMetadata::Set(const std::string &key, const std::string& value)
{
    return Set(key, DpsDataType::string, value);
}

template<class T>
DpsMetadataError DpsMetadata::Get(const std::string &key, DpsDataType type, T &value) const
{
    auto it = datas.find(key);
    if (it == datas.end()) {
        return DPS_METADATA_ERROR_NO_ENTRY;
    }
    if (it->second.type != type) {
        return DPS_METADATA_ERROR_TYPE_ERROR;
    }
    auto dpVal = std::any_cast<T>(&it->second.val);
    if (dpVal == nullptr) {
        return DPS_METADATA_ERROR_TYPE_ERROR;
    }
    value = *dpVal;
    return DPS_METADATA_OK;
}

DpsMetadataError DpsMetadata::Set(const std::string &key, DpsDataType type, const std::any& val)
{
    auto it = datas.find(key);
    if (it == datas.end() && datas.size() > DPS_MAX_USER_DATA_COUNT) {
        return DPS_METADATA_ERROR_OUT_OF_RANGE;
    }
    datas[key].type = type;
    datas[key].val = val;
    return DPS_METADATA_OK;
}

} // namespace CameraStandard
} // namespace OHOS
