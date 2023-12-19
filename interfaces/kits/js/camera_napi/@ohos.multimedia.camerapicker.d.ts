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
import type _Context from './application/Context';
import camera from './@ohos.multimedia.camera';

/**
 * @namespace camerapicker
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @since 10
 */
declare namespace cameraPicker {
  /**
   * Creates a CameraPicker instance.
   * @param context Current application context.
   * @return Promise used to return the CameraPicker instance.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  function getCameraPicker(context: _Context): CameraPicker;

  /**
   * Photo profile for camera picker.
   *
   * @typedef PhotoProfileForPicker
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface PhotoProfileForPicker {
    cameraPosition: camera.CameraPosition;
    saveUri: string;
  }
  /**
   * Video profile for camera picker.
   *
   * @typedef VideoProfileForPicker
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface VideoProfileForPicker {
    cameraPosition: camera.CameraPosition;
    saveUri: string;
    videoDuration: number;
  }
  /**
   * Camera picker object.
   *
   * @interface CameraPicker
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraPicker {
    /**
     * takePhoto
     *
     * @param { _Context } context From UIExtensionAbility.
     * @param { PhotoProfileForPicker } photoProfile Photo input Profile.
     * @returns { number } takePhoto result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    takePhoto(context: _Context, photoProfile: PhotoProfileForPicker): number;
    /**
     * recordVideo
     *
     * @param { _Context } context From UIExtensionAbility.
     * @param { VideoProfileForPicker } videoProfile Video input Profile.
     * @returns { number } recordVideo result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    recordVideo(context: _Context, videoProfile: VideoProfileForPicker): number;
  }
}

export default cameraPicker;