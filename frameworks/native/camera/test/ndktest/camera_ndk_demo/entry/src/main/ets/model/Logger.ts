
import hiLog from '@ohos.hilog'

class Logger {
    private domain: number
    private prefix: string
    private format: string = "%{public}s, %{public}s"

    constructor(prefix: string) {
        this.prefix = prefix
        this.domain = 0xFF00
    }

    debug(...args: any[]) {
        hiLog.debug(this.domain, this.prefix, this.format, args)
    }

    info(...args: any[]) {
        hiLog.info(this.domain, this.prefix, this.format, args)
    }

    warn(...args: any[]) {
        hiLog.warn(this.domain, this.prefix, this.format, args)
    }

    error(...args: any[]) {
        hiLog.error(this.domain, this.prefix, this.format, args)
    }
}

export default new Logger('[CameraZyk]')