@{
    RootModule        = 'PsrootNet.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b3f7a2d1-4e6c-4a8b-9f01-2c3d4e5f6a7b'
    Author            = 'Psroot'
    Description       = 'Networking tools for Psroot sandboxes — TCP ping and DNS resolution that work inside AppContainer.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Invoke-Ping',
        'Resolve-Dns',
        'Test-Port'
    )
    AliasesToExport   = @('ping', 'nslookup', 'dig')
}
