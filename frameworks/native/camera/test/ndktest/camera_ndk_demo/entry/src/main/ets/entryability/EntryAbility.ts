import UIAbility from '@ohos.app.ability.UIAbility';
import prompt from '@system.prompt'
import window from '@ohos.window';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import { Permissions } from '@ohos.abilityAccessCtrl';
import hilog from '@ohos.hilog';

const TAG: string = "EntryAbility";

export default class EntryAbility extends UIAbility {

  onCreate(want, launchParam) {
    hilog.isLoggable(0x0000, 'testTag', hilog.LogLevel.INFO);
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onCreate');
    hilog.info(0x0000, 'testTag', '%{public}s', 'want param:' + JSON.stringify(want) ?? '');
    hilog.info(0x0000, 'testTag', '%{public}s', 'launchParam:' + JSON.stringify(launchParam) ?? '');
    // @ts-ignore
    globalThis.abilityContext = this.context
  }

  onDestroy() {
    hilog.isLoggable(0x0000, 'testTag', hilog.LogLevel.INFO);
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    console.log("[Demo] MainAbility onWindowStageCreate")
    windowStage.loadContent("pages/tableIndex", (err, data) => {
      if (err.code) {
        console.error('Failed to load the content. Cause:' + JSON.stringify(err));
        return;
      }
      console.info('Succeeded in loading the content. Data: ' + JSON.stringify(data))
    });
  }
}
