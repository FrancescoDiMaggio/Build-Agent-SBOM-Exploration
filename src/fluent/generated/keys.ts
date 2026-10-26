import '@servicenow/sdk/global'

declare global {
    namespace Now {
        namespace Internal {
            interface Keys extends KeysRegistry {
                explicit: {
                    bom_json: {
                        table: 'sys_module'
                        id: '44b7c720754841c097b686e9fe26da7d'
                    }
                    package_json: {
                        table: 'sys_module'
                        id: '00a8365555c143eaa97f7b57f15d7a2b'
                    }
                }
            }
        }
    }
}
