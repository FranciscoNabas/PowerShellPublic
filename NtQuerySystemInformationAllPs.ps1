# All the reflection sorcery was inspired by this repo:
# https://github.com/mattifestation/PSReflect/blob/master/PSReflect.psm1

class TypeField {
    [string]$Name
    [int]$Position
    [Type]$Type
    [int]$Offset
    [MarshalAsHelper]$MarshalAs

    static [TypeField[]] SortByPosition([TypeField[]] $collection) {
        $collection = [Linq.Enumerable]::OrderBy($collection, [Func[TypeField, int]] { $args[0].Position })
        return $collection
    }
}

class MarshalAsHelper {
    [System.Runtime.InteropServices.UnmanagedType]$Value

    [System.Runtime.InteropServices.UnmanagedType]$ArraySubType
    [int]$IidParameterIndex
    [string]$MarshalCookie
    [string]$MarshalType
    [Type]$MarshalTypeRef
    [System.Runtime.InteropServices.VarEnum]$SafeArraySubType
    [Type]$SafeArrayUserDefinedSubType
    [int]$SizeConst
    [short]$SizeParamIndex

    MarshalAsHelper([System.Runtime.InteropServices.UnmanagedType]$unmanaged_type) {
        $this.Value = $unmanaged_type
    }

    [System.Reflection.Emit.CustomAttributeBuilder] GetAttributeBuilder() {
        $constructor_info = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructor(@([System.Runtime.InteropServices.UnmanagedType]))
        $field_info = [Linq.Enumerable]::OrderBy([System.Runtime.InteropServices.MarshalAsAttribute].GetFields(), [Func[System.Reflection.FieldInfo, string]] { $args[0].Name })
        
        return [System.Reflection.Emit.CustomAttributeBuilder]::new(
            $constructor_info,
            [object[]] @($this.Value),
            $field_info,
            [object[]] @(
                $this.ArraySubType
                $this.IidParameterIndex
                $this.MarshalCookie
                $this.MarshalType
                $this.MarshalTypeRef
                $this.SafeArraySubType
                $this.SafeArrayUserDefinedSubType
                $this.SizeConst
                $this.SizeParamIndex
            )
        )
    }
}

function New-Struct {

    [CmdletBinding()]
    [OutputType([Type])]
    param (
        [Parameter(mandatory, Position = 0)]
        [ValidateNotNull()]
        [Reflection.Emit.ModuleBuilder]$ModuleBuilder,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [TypeField[]]$Fields,
        
        [Parameter()]
        [ValidateSet([Reflection.TypeAttributes]::SequentialLayout, [Reflection.TypeAttributes]::ExplicitLayout)]
        [Reflection.TypeAttributes]$StructLayout = [Reflection.TypeAttributes]::SequentialLayout,

        [Parameter()]
        [System.Runtime.InteropServices.CharSet]$CharSet = [System.Runtime.InteropServices.CharSet]::Ansi,

        [Parameter()]
        [Reflection.Emit.PackingSize]$PackingSize = [System.Reflection.Emit.PackingSize]::Unspecified
    )

    [Reflection.TypeAttributes]$attributes = 'Class, Public, Sealed, BeforeFieldInit'
    $attributes = $attributes -bor $StructLayout -bor {
        switch ($CharSet) {
            Ansi { [Reflection.TypeAttributes]::AnsiClass }
            Auto { [Reflection.TypeAttributes]::AutoClass }
            Unicode { [Reflection.TypeAttributes]::UnicodeClass }
        }
    }.Invoke()[0]

    $type_builder = $ModuleBuilder.DefineType($Name, $attributes, [ValueType], $PackingSize)
    foreach ($field_info in [TypeField]::SortByPosition($Fields)) {
        $field = $type_builder.DefineField($field_info.Name, $field_info.Type, 'Public')
        if ($field_info.MarshalAs) {
            $field.SetCustomAttribute($field_info.MarshalAs.GetAttributeBuilder())
        }
        if ($StructLayout -eq 'ExplicitLayout') {
            $field.SetOffset($field_info.Offset)
        }
    }

    # TODO: Implement GetSize
    # $type_builder.DefineMethod('op_Implicit',
    # 'PrivateScope, Public, Static, HideBySig, SpecialName',
    # $type_builder,
    # [Type[]] @([IntPtr]))
    # $il_generator = $type_builder.GetILGenerator()
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Nop)
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $type_builder)
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Call,
    #     [Type].GetMethod('GetTypeFromHandle'))
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Call,
    #     [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $type_builder)
    # $il_generator.Emit([Reflection.Emit.OpCodes]::Ret)

    $type_builder.CreateType()
}

enum SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation # q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation # q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation # q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation # q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation # not implemented
    SystemProcessInformation # q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation # q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation # q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation # q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation # q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation # not implemented # SYSTEM_CALL_TIME_INFORMATION # 10
    SystemModuleInformation # q: RTL_PROCESS_MODULES
    SystemLocksInformation # q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation # q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation # not implemented
    SystemNonPagedPoolInformation # not implemented
    SystemHandleInformation # q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation # q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation # q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation # q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation # not implemented # 20
    SystemFileCacheInformation # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation # q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation # q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation # q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation # not implemented # SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation # s (kernel-mode only)
    SystemUnloadGdiDriverInformation # s (kernel-mode only)
    SystemTimeAdjustmentInformation # q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation # not implemented # SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation # s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) # 30
    SystemPerformanceTraceInformation # q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0 # not implemented
    SystemExceptionInformation # q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation # s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation # q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation # q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation # q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation # s (requires SeLoadDriverPrivilege) # loads win32k only
    SystemPrioritySeperation # s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation # s (requires SeDebugPrivilege) # 40
    SystemVerifierRemoveDriverInformation # s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation # q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation # q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation # q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation # q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification # s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate # not implemented
    SystemSessionDetach # not implemented
    SystemSessionInformation # not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation # q: SYSTEM_RANGE_START_INFORMATION # 50
    SystemVerifierInformation # q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend # s (kernel-mode only)
    SystemSessionProcessInformation # q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace # s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap # q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation # q; s: PREFETCHER_INFORMATION # PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation # q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment # q: ULONG # KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage # q; s: ULONG
    SystemNumaAvailableMemory # q: SYSTEM_NUMA_INFORMATION # 60
    SystemProcessorPowerInformation # q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation # q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation # q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation # q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation # q: ULONG
    SystemBigPoolInformation # q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation # q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation # q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation # q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode # q: ULONG # 70
    SystemWatchdogTimerHandler # s: SYSTEM_WATCHDOG_HANDLER_INFORMATION # (kernel-mode only)
    SystemWatchdogTimerInformation # q: SYSTEM_WATCHDOG_TIMER_INFORMATION # (kernel-mode only)
    SystemLogicalProcessorInformation # q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete # not implemented
    SystemRegisterFirmwareTableInformationHandler # s: SYSTEM_FIRMWARE_TABLE_HANDLER # (kernel-mode only)
    SystemFirmwareTableInformation # SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx # q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation # not implemented
    SystemSuperfetchInformation # q; s: SUPERFETCH_INFORMATION # PfQuerySuperfetchInformation
    SystemMemoryListInformation # q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) # 80
    SystemFileCacheInformationEx # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation # s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation # q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation # SYSTEM_VERIFIER_CANCELLATION_INFORMATION # name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx # not implemented
    SystemRefTraceInformation # q; s: SYSTEM_REF_TRACE_INFORMATION # ObQueryRefTraceInformation
    SystemSpecialPoolInformation # q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) # MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation # q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation # s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation # q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION # 90
    SystemHypervisorInformation # q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx # q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation # q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation # s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation # q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST # ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation # SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation # s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation # q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation # q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution # q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) # 100
    SystemNumaProximityNodeInformation # q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation # q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation # q: SYSTEM_CODEINTEGRITY_INFORMATION # SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation # s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString # q: CHAR[] # HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation # q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) # MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation # q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) # since WIN7 # KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation # q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation # q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) # SmQueryStoreInformation
    SystemRegistryAppendString # s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS # 110
    SystemAitSamplingValue # s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation # q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation # q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation # q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts # SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation # q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation # q: TPM_BOOT_ENTROPY_NT_RESULT # ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation # q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) # 120
    SystemNodeDistanceInformation # q: USHORT[4*NumaNodes] # (EX in: USHORT NodeNumber)
    SystemAcpiAuditInformation # q: SYSTEM_ACPI_AUDIT_INFORMATION # HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation # q: SYSTEM_BASIC_PERFORMANCE_INFORMATION # name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation # q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION # since WIN7 SP1
    SystemSessionBigPoolInformation # q: SYSTEM_SESSION_POOLTAG_INFORMATION # since WIN8
    SystemBootGraphicsInformation # q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation # q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation
    SystemProcessorProfileControlArea # q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation # s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 # 130
    SystemEntropyInterruptTimingInformation # q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation # q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation # q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation # q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation # q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation # q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation # q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation # q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation # q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation # q: SYSTEM_BOOT_LOGO_INFORMATION # 140
    SystemProcessorPerformanceInformationEx # q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX # (EX in: USHORT ProcessorGroup) # since WINBLUE
    SystemCriticalProcessErrorLogInformation
    SystemSecureBootPolicyInformation # q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx # q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation # q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation
    SystemPortableWorkspaceEfiLauncherInformation # q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation # q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx # q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation # 150
    SystemSoftRebootInformation # q: ULONG
    SystemElamCertificateInformation # s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation # q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation # q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation # s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation # q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation # q: SYSTEM_MANUFACTURING_INFORMATION # since THRESHOLD
    SystemEnergyEstimationConfigInformation # q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation # q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation # q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) # 160
    SystemVmGenerationCountInformation
    SystemTrustedPlatformModuleInformation # q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags # SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation # q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation # q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation
    SystemSingleModuleInformation # q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation # s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation # q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation # q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION # 170
    SystemSecureBootPolicyFullInformation # q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation
    SystemAffinitizedInterruptProcessorInformation # (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation # q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation # q: SYSTEM_CPU_SET_INFORMATION # since THRESHOLD2
    SystemCpuSetTagInformation # q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout
    SystemSecureKernelProfileInformation # q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation # q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION # since REDSTONE
    SystemInterruptSteeringInformation # q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT # NtQuerySystemInformationEx # 180
    SystemSupportedProcessorArchitectures # p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] # NtQuerySystemInformationEx
    SystemMemoryUsageInformation # q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation # q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation # q: SYSTEM_PHYSICAL_MEMORY_INFORMATION # since REDSTONE2
    SystemControlFlowTransition # (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed # s: ULONG
    SystemActivityModerationExeState # SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings # SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation
    SystemCodeIntegrityUnlockInformation # SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION # 190
    SystemIntegrityQuotaInformation
    SystemFlushInformation # q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation # q: ULONG_PTR[ActiveGroupCount] # since REDSTONE3
    SystemSecureDumpEncryptionInformation
    SystemWriteConstraintInformation # SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation # SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation # SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION # since REDSTONE4
    SystemFirmwareBootPerformanceInformation
    SystemCodeIntegrityVerificationInformation # SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation # SYSTEM_FIRMWARE_PARTITION_INFORMATION # 200
    SystemSpeculationControlInformation # SYSTEM_SPECULATION_CONTROL_INFORMATION # (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation # SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation # SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation # SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION # since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation # SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation # SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information # q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation # SYSTEM_SECURITY_MODEL_INFORMATION # since 19H1
    SystemCodeIntegritySyntheticCacheInformation
    SystemFeatureConfigurationInformation # SYSTEM_FEATURE_CONFIGURATION_INFORMATION # since 20H1 # 210
    SystemFeatureConfigurationSectionInformation # SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation # SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation # SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation # since 20H2
    SystemFwRamdiskInformation # SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation
    SystemDifSetRuleClassInformation # SYSTEM_DIF_VOLATILE_INFORMATION
    SystemDifClearRuleClassInformation
    SystemDifApplyPluginVerificationOnDriver # SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
    SystemDifRemovePluginVerificationOnDriver # SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION # 220
    SystemShadowStackInformation # SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation # q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION # NtQuerySystemInformationEx # 222
    SystemPoolLimitInformation # SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
    SystemCodeIntegrityAddDynamicStore
    SystemCodeIntegrityClearDynamicStores
    SystemDifPoolTrackingInformation
    SystemPoolZeroingInformation # q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation # q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2 # q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2 # q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] # NtQuerySystemInformationEx # 230
    SystemSingleProcessorRelationshipInformation # q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX # (EX in: PROCESSOR_NUMBER Processor)
    SystemXfgCheckFailureInformation # q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation # SYSTEM_IOMMU_STATE_INFORMATION # since 22H1
    SystemHypervisorMinrootInformation # SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation # SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation # SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation
    SystemOriginalImageFeatureInformation # q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT # NtQuerySystemInformationEx
    MaxSystemInfoClass
}

<#
    Assembly and module
#>
# Module builder.
$dyn_ass = [Reflection.AssemblyName]::new('ntdll')

# Needs to be 'RunAndCollect' otherwise 'DefinePInvokeMethod' will throw an 'InvalidOperationException'.
$ass_builder = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($dyn_ass, 'RunAndCollect')
$mod_builder = $ass_builder.DefineDynamicModule('ntdll.dll')

# Type that will host our pinvoke method.
$type_builder = $mod_builder.DefineType('ntdll', 'Public, BeforeFieldInit')

# The method.
$method = $type_builder.DefinePInvokeMethod(
    'NtQuerySystemInformation',
    'ntdll.dll',
    'Public, Static, PinvokeImpl',
    [System.Reflection.CallingConventions]::Standard,
    [int],
    [Type[]] @(
        [SYSTEM_INFORMATION_CLASS],
        [IntPtr],
        [uint],
        [Type]::GetType('System.UInt32&')
    ),
    [System.Runtime.InteropServices.CallingConvention]::Winapi,
    [System.Runtime.InteropServices.CharSet]::Unicode
)

# Add PreserveSig to the method implementation flags. NOTE: If this line
# is commented out, the return value will be zero when the method is
# invoked.
$method.SetImplementationFlags($method.GetMethodImplementationFlags() -bor [System.Reflection.MethodImplAttributes]::PreserveSig)
$ntdll = $type_builder.CreateType()

<#
    Structs
#>
$field_info = @(
    [TypeField]@{ Name = 'LowPart'; Position = 0; Type = [int]; Offset = 0 }
    [TypeField]@{ Name = 'HighPart'; Position = 1; Type = [int]; Offset = 4 }
    [TypeField]@{ Name = 'LowPart'; Position = 2; Type = [long]; Offset = 0 }
)
$large_integer = New-Struct $mod_builder 'LARGE_INTEGER' $field_info -StructLayout 'ExplicitLayout'

$field_info = @(
    [TypeField]@{ Name = 'Length'; Position = 0; Type = [short] }
    [TypeField]@{ Name = 'MaximumLength'; Position = 1; Type = [short] }
    [TypeField]@{ Name = 'Buffer'; Position = 2; Type = [IntPtr] }
)
$unicode_string = New-Struct $mod_builder 'UNICODE_STRING' $field_info

$field_info = @(
    [TypeField]@{ Name = 'NextEntryOffset'; Position = 0; Type = [uint] }
    [TypeField]@{ Name = 'NumberOfThreads'; Position = 1; Type = [uint] }
    [TypeField]@{ Name = 'WorkingSetPrivateSize'; Position = 2; Type = $large_integer }
    [TypeField]@{ Name = 'HardFaultCount'; Position = 3; Type = [uint] }
    [TypeField]@{ Name = 'NumberOfThreadsHighWatermark'; Position = 4; Type = [uint] }
    [TypeField]@{ Name = 'CycleTime'; Position = 5; Type = [ulong] }
    [TypeField]@{ Name = 'CreateTime'; Position = 6; Type = $large_integer }
    [TypeField]@{ Name = 'UserTime'; Position = 7; Type = $large_integer }
    [TypeField]@{ Name = 'KernelTime'; Position = 8; Type = $large_integer }
    [TypeField]@{ Name = 'ImageName'; Position = 9; Type = $unicode_string }
    [TypeField]@{ Name = 'BasePriority'; Position = 10; Type = [int] }
    [TypeField]@{ Name = 'UniqueProcessId'; Position = 11; Type = [ulong] }
    [TypeField]@{ Name = 'InheritedFromUniqueProcessId'; Position = 12; Type = [ulong] }
    [TypeField]@{ Name = 'HandleCount'; Position = 13; Type = [uint] }
    [TypeField]@{ Name = 'SessionId'; Position = 14; Type = [uint] }
    [TypeField]@{ Name = 'UniqueProcessKey'; Position = 15; Type = [ulong] }
    [TypeField]@{ Name = 'PeakVirtualSize'; Position = 16; Type = [ulong] }
    [TypeField]@{ Name = 'VirtualSize'; Position = 16; Type = [ulong] }
    [TypeField]@{ Name = 'PageFaultCount'; Position = 17; Type = [uint] }
    [TypeField]@{ Name = 'PeakWorkingSetSize'; Position = 18; Type = [ulong] }
    [TypeField]@{ Name = 'WorkingSetSize'; Position = 19; Type = [ulong] }
    [TypeField]@{ Name = 'QuotaPeakPagedPoolUsage'; Position = 20; Type = [ulong] }
    [TypeField]@{ Name = 'QuotaPagedPoolUsage'; Position = 21; Type = [ulong] }
    [TypeField]@{ Name = 'QuotaPeakNonPagedPoolUsage'; Position = 22; Type = [ulong] }
    [TypeField]@{ Name = 'QuotaNonPagedPoolUsage'; Position = 23; Type = [ulong] }
    [TypeField]@{ Name = 'PagefileUsage'; Position = 24; Type = [ulong] }
    [TypeField]@{ Name = 'PeakPagefileUsage'; Position = 25; Type = [ulong] }
    [TypeField]@{ Name = 'PrivatePageCount'; Position = 26; Type = [ulong] }
    [TypeField]@{ Name = 'ReadOperationCount'; Position = 27; Type = $large_integer }
    [TypeField]@{ Name = 'WriteOperationCount'; Position = 28; Type = $large_integer }
    [TypeField]@{ Name = 'OtherOperationCount'; Position = 29; Type = $large_integer }
    [TypeField]@{ Name = 'ReadTransferCount'; Position = 30; Type = $large_integer }
    [TypeField]@{ Name = 'WriteTransferCount'; Position = 31; Type = $large_integer }
    [TypeField]@{ Name = 'OtherTransferCount'; Position = 32; Type = $large_integer }
    [TypeField]@{ Name = 'Threads'; Position = 33; Type = [IntPtr] }
)
$system_process_information = New-Struct $mod_builder 'SYSTEM_PROCESS_INFORMATION' $field_info

# Initializing some constants.
$bytes_needed = 0
$STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
[System.Collections.Generic.List[object]]$process_information = @()

# Getting required buffer size.
$status = $ntdll::NtQuerySystemInformation('SystemProcessInformation', [IntPtr]::Zero, 0, [ref]$bytes_needed)
if ($status -ne 0 -and $status -ne $STATUS_INFO_LENGTH_MISMATCH) {
    throw $status
}

do {
    # By the time we call 'NtQuerySystemInformation' again, new processes might have
    # been created, so we add a little more to avoid looping too much.
    $bytes_needed += 2048
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes_needed)
    
    # Attempting to get system process information.
    $status = $ntdll::NtQuerySystemInformation('SystemProcessInformation', $buffer, $bytes_needed, [ref]$bytes_needed)
    if ($status -eq 0) {
        break
    }
    if ($status -ne 0 -and $status -ne $STATUS_INFO_LENGTH_MISMATCH) {
        throw $status
    }

    # Size is not enough, so we free the buffer and try again.
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

} while ($status -eq $STATUS_INFO_LENGTH_MISMATCH)

# Looping through each 'SYSTEM_PROCESS_INFORMATION' structure.
do {
    # Getting the structure for the current offset.
    $current_info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [type]$system_process_information)
    $process_information.Add($current_info)

    if ($current_info.NextEntryOffset -eq 0) {
        break
    }

    # Mooving the pointer offset.
    $buffer = [IntPtr]::Add($buffer, $current_info.NextEntryOffset)
    
} while ($current_info.NextEntryOffset -ne 0)

foreach ($info in $process_information) {
    Write-Host ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($info.ImageName.Buffer))
}

return $process_information
