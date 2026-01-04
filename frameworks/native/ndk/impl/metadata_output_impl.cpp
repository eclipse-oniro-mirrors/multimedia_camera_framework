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

#include "metadata_output_impl.h"
#include "camera_log.h"
#include "camera_util.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

class InnerMetadataOutputCallback : public MetadataStateCallback {
public:
    InnerMetadataOutputCallback(Camera_MetadataOutput* metadataOutput, MetadataOutput_Callbacks* callback)
        : metadataOutput_(metadataOutput), callback_(*callback) {}
    ~InnerMetadataOutputCallback() = default;

    void OnError(const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorCode: %{public}d", errorCode);
        CHECK_RETURN(metadataOutput_ == nullptr || callback_.onError == nullptr);
        callback_.onError(metadataOutput_, FrameworkToNdkCameraError(errorCode));
    }

private:
    Camera_MetadataOutput* metadataOutput_;
    MetadataOutput_Callbacks callback_;
};

// need fix
class InnerMetadataObjectCallback : public MetadataObjectCallback {
public:
    InnerMetadataObjectCallback(Camera_MetadataOutput* metadataOutput, MetadataOutput_Callbacks* callback)
        : metadataOutput_(metadataOutput), callback_(*callback) {}
    ~InnerMetadataObjectCallback() = default;

    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const override
    {
        MEDIA_DEBUG_LOG("InnerMetadataObjectCallback::OnMetadataObjectsAvailable");
        CHECK_RETURN_ELOG(metaObjects.empty(), "OnMetadataObjectsAvailable: metaObjects is empty");
        size_t size = metaObjects.size();
        CHECK_RETURN(metadataOutput_ == nullptr || callback_.onMetadataObjectAvailable == nullptr);
        Camera_MetadataObject* object = new Camera_MetadataObject[size];
        Camera_Rect boundingBox;
        for (size_t index = 0; index < size; index++) {
            CHECK_EXECUTE(MetadataObjectType::FACE == metaObjects[index]->GetType(),
                object[index].type = Camera_MetadataObjectType::FACE_DETECTION;);
            CHECK_EXECUTE(MetadataObjectType::HUMAN_BODY == metaObjects[index]->GetType(),
                object[index].type = Camera_MetadataObjectType::CAMERA_METADATA_OBJECT_TYPE_HUMAN_BODY;);
            auto metaObject = metaObjects[index];
            object[index].timestamp = metaObjects[index]->GetTimestamp();
            boundingBox.topLeftX = metaObjects[index]->GetBoundingBox().topLeftX * metaObject->GetSize().width;
            boundingBox.topLeftY = metaObjects[index]->GetBoundingBox().topLeftY * metaObject->GetSize().height;
            boundingBox.width = metaObjects[index]->GetBoundingBox().width * metaObject->GetSize().width;
            boundingBox.height = metaObjects[index]->GetBoundingBox().height * metaObject->GetSize().height;
            object[index].boundingBox = &boundingBox;
        }
        callback_.onMetadataObjectAvailable(metadataOutput_, object, size);
    }

private:
    Camera_MetadataOutput* metadataOutput_;
    MetadataOutput_Callbacks callback_;
};

Camera_MetadataOutput::Camera_MetadataOutput(sptr<MetadataOutput> &innerMetadataOutput)
    : innerMetadataOutput_(innerMetadataOutput)
{
    MEDIA_DEBUG_LOG("Camera_MetadataOutput Constructor is called");
}

Camera_MetadataOutput::~Camera_MetadataOutput()
{
    MEDIA_DEBUG_LOG("~Camera_MetadataOutput is called");
    innerMetadataOutput_ = nullptr;
}

Camera_ErrorCode Camera_MetadataOutput::RegisterCallback(MetadataOutput_Callbacks* callback)
{
    shared_ptr<InnerMetadataOutputCallback> innerMetadataOutputCallback =
                make_shared<InnerMetadataOutputCallback>(this, callback);
    innerMetadataOutput_->SetCallback(innerMetadataOutputCallback);

    shared_ptr<InnerMetadataObjectCallback> innerMetadataObjectCallback =
                make_shared<InnerMetadataObjectCallback>(this, callback);
    innerMetadataOutput_->SetCallback(innerMetadataObjectCallback);

    return CAMERA_OK;
}

Camera_ErrorCode Camera_MetadataOutput::UnregisterCallback(MetadataOutput_Callbacks* callback)
{
    shared_ptr<InnerMetadataOutputCallback> innerMetadataOutputCallback = nullptr;
    innerMetadataOutput_->SetCallback(innerMetadataOutputCallback);
    shared_ptr<InnerMetadataObjectCallback> innerMetadataObjectCallback = nullptr;
    innerMetadataOutput_->SetCallback(innerMetadataObjectCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_MetadataOutput::Start()
{
    int32_t ret = innerMetadataOutput_->Start();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_MetadataOutput::Stop()
{
    int32_t ret = innerMetadataOutput_->Stop();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_MetadataOutput::Release()
{
    int32_t ret = innerMetadataOutput_->Release();
    return FrameworkToNdkCameraError(ret);
}

sptr<MetadataOutput> Camera_MetadataOutput::GetInnerMetadataOutput()
{
    return innerMetadataOutput_;
}

Camera_ErrorCode Camera_MetadataOutput::AddMetadataObjectTypes(Camera_MetadataObjectType* types, uint32_t size)
{
    std::vector<MetadataObjectType> temp;
    for (int i = 0 ; i < size ; i++) {
        temp.push_back(convert(types[i]));
    }
    MEDIA_DEBUG_LOG("Camera_MetadataOutput::AddMetadataObjectTypes");
    int32_t ret = innerMetadataOutput_->AddMetadataObjectTypes(temp);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_MetadataOutput::RemoveMetadataObjectTypes(Camera_MetadataObjectType* types, uint32_t size)
{
    std::vector<MetadataObjectType> temp;
    for (int i = 0 ; i < size ; i++) {
        temp.push_back(convert(types[i]));
    }
    MEDIA_DEBUG_LOG("Camera_MetadataOutput::RemoveMetadataObjectTypes");
    int32_t ret = innerMetadataOutput_->RemoveMetadataObjectTypes(temp);
    return FrameworkToNdkCameraError(ret);
}

MetadataObjectType Camera_MetadataOutput::convert(Camera_MetadataObjectType type)
{
    unordered_map<Camera_MetadataObjectType, MetadataObjectType> convertMap = {
        {Camera_MetadataObjectType::CAMERA_METADATA_OBJECT_TYPE_FACE_DETECTION, MetadataObjectType::FACE},
        {Camera_MetadataObjectType::CAMERA_METADATA_OBJECT_TYPE_HUMAN_BODY, MetadataObjectType::HUMAN_BODY},
        {Camera_MetadataObjectType::FACE_DETECTION, MetadataObjectType::FACE}};
    return convertMap[type];
}