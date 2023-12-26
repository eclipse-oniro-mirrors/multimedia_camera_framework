/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import type Context from './application/Context';
import type camera from './@ohos.multimedia.camera';

/**
 * @namespace cameraPicker
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @since 11
 */
declare namespace cameraPicker {

  /**
   * Photo profile for camera picker.
   *
   * @typedef PhotoProfileForPicker
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  class PhotoProfileForPicker {
    /**
     * The camera position to be used.
     *
     * @type { camera.CameraPosition }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    cameraPosition: camera.CameraPosition;

    /**
     * The uri of the result to be saved.
     *
     * @type { ?string }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    saveUri?: string;
  }

  /**
   * Video profile for camera picker.
   *
   * @typedef VideoProfileForPicker
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  class VideoProfileForPicker {
    /**
     * The camera position to be used.
     *
     * @type { camera.CameraPosition }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    cameraPosition: camera.CameraPosition;

    /**
     * The uri of the result to be saved.
     *
     * @type { ?string }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    saveUri?: string;

    /**
     * The max duration of the video.
     *
     * @type { ?number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    videoDuration?: number;
  }


  class PickerResult {
    /**
     * The result code.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    resultCode: number;

    /**
     * The result saved uri.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    resultUri: string;
  }

  /**
   * takePhoto
   *
   * @param { Context } context From UIExtensionAbility.
   * @param { PhotoProfileForPicker } photoProfile Photo input Profile.
   * @returns { number } takePhoto result.
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  function takePhoto(context: Context, photoProfile: PhotoProfileForPicker): Promise<PickerResult>;

  /**
   * recordVideo
   *
   * @param { Context } context From UIExtensionAbility.
   * @param { VideoProfileForPicker } videoProfile Video input Profile.
   * @returns { number } recordVideo result.
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  function recordVideo(context: Context, videoProfile: VideoProfileForPicker): Promise<PickerResult>;
}

export default cameraPicker;