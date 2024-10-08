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

#ifndef OHOS_CAMERA_METADATA_OUTPUT_H
#define OHOS_CAMERA_METADATA_OUTPUT_H

#include <iostream>
#include <mutex>

#include "camera_metadata_info.h"
#include "camera_metadata_operator.h"
#include "capture_output.h"
#include "iconsumer_surface.h"
#include "istream_metadata.h"
#include "metadata_type.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
enum MetadataOutputErrorCode : int32_t {
    ERROR_UNKNOWN = 1,
    ERROR_INSUFFICIENT_RESOURCES,
};

struct Rect {
    double topLeftX;
    double topLeftY;
    double width;
    double height;
};

class MetadataObject : public RefBase {
public:
    MetadataObject(MetadataObjectType type, double timestamp, Rect rect);
    virtual ~MetadataObject() = default;
    MetadataObjectType GetType();
    double GetTimestamp();
    Rect GetBoundingBox();

private:
    MetadataObjectType type_;
    double timestamp_;
    Rect box_;
};

class MetadataFaceObject : public MetadataObject {
public:
    MetadataFaceObject(double timestamp, Rect rect);
    ~MetadataFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
    };
    inline Emotion GetEmotion()
    {
        return emotion_;
    };
    inline int32_t GetEmotionConfidence()
    {
        return emotionConfidence_;
    };
    inline int32_t GetPitchAngle()
    {
        return pitchAngle_;
    };
    inline int32_t GetYawAngle()
    {
        return yawAngle_;
    };
    inline int32_t GetRollAngle()
    {
        return rollAngle_;
    };

private:
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
    Emotion emotion_;
    int32_t emotionConfidence_;
    int32_t pitchAngle_;
    int32_t yawAngle_;
    int32_t rollAngle_;
};

class MetadataHumanBodyObject : public MetadataObject {
public:
    MetadataHumanBodyObject(const MetaObjectParms& parms);
    ~MetadataHumanBodyObject() = default;
};

class MetadataCatFaceObject : public MetadataObject {
public:
    MetadataCatFaceObject(const MetaObjectParms& parms, const Rect leftEyeBoundingBox, const Rect rightEyeBoundingBox);
    ~MetadataCatFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
    };

private:
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
};

class MetadataCatBodyObject : public MetadataObject {
public:
    MetadataCatBodyObject(const MetaObjectParms& parms);
    ~MetadataCatBodyObject() = default;
};

class MetadataDogFaceObject : public MetadataObject {
public:
    MetadataDogFaceObject(const MetaObjectParms& parms, const Rect leftEyeBoundingBox, const Rect rightEyeBoundingBox);
    ~MetadataDogFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
    };

private:
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
};

class MetadataDogBodyObject : public MetadataObject {
public:
    MetadataDogBodyObject(const MetaObjectParms& parms);
    ~MetadataDogBodyObject() = default;
};

class MetadataSalientDetectionObject : public MetadataObject {
public:
    MetadataSalientDetectionObject(const MetaObjectParms& parms);
    ~MetadataSalientDetectionObject() = default;
};

class MetadataBarCodeDetectionObject : public MetadataObject {
public:
    MetadataBarCodeDetectionObject(const MetaObjectParms& parms);
    ~MetadataBarCodeDetectionObject() = default;
};

class MetadataObjectFactory : public RefBase {
public:
    virtual ~MetadataObjectFactory() = default;

    static sptr<MetadataObjectFactory> &GetInstance();
    inline sptr<MetadataObjectFactory> SetType(MetadataObjectType type)
    {
        type_ = type;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetTimestamp(int32_t timestamp)
    {
        timestamp_ = timestamp;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetBox(Rect box)
    {
        box_ = box;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetObjectId(int32_t objectId)
    {
        objectId_ = objectId;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetConfidence(int32_t confidence)
    {
        confidence_ = confidence;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetLeftEyeBoundingBox(Rect leftEyeBoundingBox)
    {
        leftEyeBoundingBox_ = leftEyeBoundingBox;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetRightEyeBoundingBoxd(Rect rightEyeBoundingBox)
    {
        rightEyeBoundingBox_ = rightEyeBoundingBox;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetEmotion(Emotion emotion)
    {
        emotion_ = emotion;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetEmotionConfidence(int32_t emotionConfidence)
    {
        emotionConfidence_ = emotionConfidence;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetPitchAngle(int32_t pitchAngle)
    {
        pitchAngle_ = pitchAngle;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetYawAngle(int32_t yawAngle)
    {
        yawAngle_ = yawAngle;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetRollAngle(int32_t rollAngle)
    {
        rollAngle_ = rollAngle;
        return this;
    }

    sptr<MetadataObject> createMetadataObject(MetadataObjectType type);

private:
    MetadataObjectFactory();
    static sptr<MetadataObjectFactory> metaFactoryInstance_;
    static std::mutex instanceMutex_;
    // Parameters of metadataObject
    MetadataObjectType type_;
    int32_t timestamp_ = 0;
    Rect box_ = {0.0, 0.0, 0.0, 0.0};
    int32_t objectId_ = 0;
    int32_t confidence_ = 0;
    // Parameters of All face metadata
    Rect leftEyeBoundingBox_ = {0.0, 0.0, 0.0, 0.0};;
    Rect rightEyeBoundingBox_ = {0.0, 0.0, 0.0, 0.0};;
    // Parameters of human face metadata
    Emotion emotion_ = NEUTRAL;
    int32_t emotionConfidence_ = 0;
    int32_t pitchAngle_ = 0;
    int32_t yawAngle_ = 0;
    int32_t rollAngle_ = 0;

    void ResetParameters();
};

class MetadataObjectCallback {
public:
    MetadataObjectCallback() = default;
    virtual ~MetadataObjectCallback() = default;
    virtual void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const = 0;
};

class MetadataStateCallback {
public:
    MetadataStateCallback() = default;
    virtual ~MetadataStateCallback() = default;
    virtual void OnError(int32_t errorCode) const = 0;
};

class MetadataOutput : public CaptureOutput {
public:
    MetadataOutput(sptr<IConsumerSurface> surface, sptr<IStreamMetadata>& streamMetadata);
    ~MetadataOutput();

    /**
     * @brief Get the supported metadata object types.
     *
     * @return Returns vector of MetadataObjectType.
     */
    std::vector<MetadataObjectType> GetSupportedMetadataObjectTypes();

    /**
     * @brief Set the metadata object types
     *
     * @param Vector of MetadataObjectType
     */
    void SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> objectTypes);

    /**
     * @brief Set the metadata object callback for the metadata output.
     *
     * @param MetadataObjectCallback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<MetadataObjectCallback> metadataObjectCallback);

    /**
     * @brief Set the metadata state callback for the metadata output.
     *
     * @param MetadataStateCallback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<MetadataStateCallback> metadataStateCallback);

    int32_t CreateStream() override;

    /**
     * @brief Start the metadata capture.
     */
    int32_t Start();

    /**
     * @brief Stop the metadata capture.
     */
    int32_t Stop();

    /**
     * @brief Releases a instance of the MetadataOutput.
     */
    int32_t Release() override;
    bool reportFaceResults_ = false;
    bool reportLastFaceResults_ = false;
    void ProcessFaceRectangles(int64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result,
        std::vector<sptr<MetadataObject>>& metaObjects, bool isNeedMirror);
    int32_t ProcessMetaObjects(int64_t timestamp, std::vector<sptr<MetadataObject>>& metaObjects,
        camera_metadata_item_t& metadataItem, common_metadata_header_t* metadata, bool isNeedMirror);
    std::shared_ptr<MetadataObjectCallback> GetAppObjectCallback();
    std::shared_ptr<MetadataStateCallback> GetAppStateCallback();

    friend class MetadataObjectListener;
private:
    void CameraServerDied(pid_t pid) override;
    void ReleaseSurface();
    sptr<IConsumerSurface> GetSurface();

    std::mutex surfaceMutex_;
    sptr<IConsumerSurface> surface_;
    std::shared_ptr<MetadataObjectCallback> appObjectCallback_;
    std::shared_ptr<MetadataStateCallback> appStateCallback_;
};

class MetadataObjectListener : public IBufferConsumerListener {
public:
    MetadataObjectListener(sptr<MetadataOutput> metadata);
    void OnBufferAvailable() override;

private:
    int32_t ProcessMetadataBuffer(void* buffer, int64_t timestamp);
    wptr<MetadataOutput> metadata_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_METADATA_OUTPUT_H
