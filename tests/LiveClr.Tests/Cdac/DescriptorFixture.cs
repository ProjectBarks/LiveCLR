namespace LiveClr.Tests.Cdac;

/// <summary>
/// The real cDAC contract descriptor from a shipping runtime — coreclr.dll build
/// 9.0.725.31616, extracted at export RVA 0x461D30 (analysis doc §5.1, §5.2), and
/// checked in at docs/reference/sts2-coreclr-contract-descriptor.json in the consuming
/// repo.
/// </summary>
/// <remarks>
/// Embedded as source rather than as a content file on purpose: the fixture then needs
/// no csproj item, no copy-to-output, and no working directory, so §8.8's "CI without a
/// game" requirement holds even when the tests run from an arbitrary directory.
/// The text below is the checked-in blob verbatim (pretty-printed; the runtime's own
/// blob is the same JSON compacted to 3201 bytes).
/// </remarks>
internal static class DescriptorFixture
{
    public const string Json = """
        {
          "version": 0,
          "baseline": "empty",
          "types": {
            "Thread": {
              "Id": 16,
              "OSId": 304,
              "State": 0,
              "PreemptiveGCDisabled": 4,
              "RuntimeThreadLocals": 32,
              "Frame": 8,
              "ExceptionTracker": 360,
              "GCHandle": [
                312,
                "GCHandle"
              ],
              "LastThrownObject": [
                344,
                "GCHandle"
              ],
              "LinkNext": [
                120,
                "pointer"
              ],
              "TEB": 48
            },
            "ThreadStore": {
              "FirstThreadLink": 64,
              "ThreadCount": 88,
              "UnstartedCount": 92,
              "BackgroundCount": 96,
              "PendingCount": 100,
              "DeadCount": 104
            },
            "RuntimeThreadLocals": {
              "AllocContext": [
                0,
                "AllocContext"
              ]
            },
            "GCAllocContext": {
              "Pointer": 0,
              "Limit": 8
            },
            "Exception": {
              "_message": 16,
              "_innerException": 32,
              "_stackTrace": 48,
              "_watsonBuckets": 56,
              "_stackTraceString": 64,
              "_remoteStackTraceString": 72,
              "_HResult": 108,
              "_xcode": 104
            },
            "ExceptionInfo": {
              "ThrownObject": 8,
              "PreviousNestedInfo": 0
            },
            "GCHandle": {
              "!": 8
            },
            "Object": {
              "m_pMethTab": 0
            },
            "String": {
              "m_FirstChar": 12,
              "m_StringLength": 8
            },
            "Array": {
              "!": 16,
              "m_NumComponents": 8
            },
            "InteropSyncBlockInfo": {
              "CCW": 8,
              "RCW": 24
            },
            "SyncBlock": {
              "InteropInfo": 56
            },
            "SyncTableEntry": {
              "!": 16,
              "SyncBlock": 0
            },
            "Module": {
              "Assembly": 216,
              "Base": 192,
              "Flags": 200,
              "LoaderAllocator": 152,
              "ThunkHeap": 648,
              "DynamicMetadata": 736,
              "Path": 176,
              "FieldDefToDescMap": 432,
              "ManifestModuleReferencesMap": 40,
              "MemberRefToDescMap": 72,
              "MethodDefToDescMap": 368,
              "TypeDefToMethodTableMap": 336,
              "TypeRefToMethodTableMap": 8,
              "MethodDefToILCodeVersioningStateMap": 400
            },
            "ModuleLookupMap": {
              "TableData": 8
            },
            "MethodTable": {
              "MTFlags": 0,
              "BaseSize": 4,
              "MTFlags2": 8,
              "EEClassOrCanonMT": 40,
              "Module": 24,
              "ParentMethodTable": 16,
              "NumInterfaces": 14,
              "NumVirtuals": 12,
              "PerInstInfo": 48
            },
            "EEClass": {
              "MethodTable": 16,
              "NumMethods": 68,
              "CorTypeAttr": 56,
              "InternalCorElementType": 64,
              "NumNonVirtualSlots": 78
            },
            "ArrayClass": {
              "Rank": 88
            },
            "GenericsDictInfo": {
              "NumTypeArgs": 6
            },
            "TypeDesc": {
              "TypeAndFlags": 0
            },
            "ParamTypeDesc": {
              "TypeArg": 16
            },
            "TypeVarTypeDesc": {
              "Module": 16,
              "Token": 40
            },
            "FnPtrTypeDesc": {
              "NumArgs": 24,
              "CallConv": 28,
              "RetAndArgTypes": 32,
              "LoaderModule": 16
            },
            "DynamicMetadata": {
              "Size": 0,
              "Data": 4
            },
            "MethodDesc": {
              "ChunkIndex": 2,
              "Slot": 4,
              "Flags": 6,
              "Flags3AndTokenRemainder": 0
            },
            "MethodDescChunk": {
              "!": 24,
              "MethodTable": 0,
              "Next": 8,
              "Size": 16,
              "Count": 17,
              "FlagsAndTokenRange": 18
            },
            "InstantiatedMethodDesc": {
              "PerInstInfo": 24,
              "Flags2": 32,
              "NumGenericArgs": 34
            },
            "StoredSigMethodDesc": {
              "Sig": 16,
              "cSig": 24,
              "ExtendedFlags": 28
            },
            "DynamicMethodDesc": {
              "MethodName": 32
            }
          },
          "globals": {
            "MethodDescTokenRemainderBitCount": [
              "0xc",
              "uint8"
            ],
            "FeatureEHFunclets": [
              "0x1",
              "uint8"
            ],
            "FeatureCOMInterop": [
              "0x1",
              "uint8"
            ],
            "ObjectToMethodTableUnmask": [
              "0x7",
              "uint8"
            ],
            "SOSBreakingChangeVersion": [
              "0x5",
              "uint8"
            ],
            "DirectorySeparator": [
              "0x5c",
              "uint8"
            ],
            "MethodDescAlignment": [
              "0x8",
              "uint64"
            ],
            "ObjectHeaderSize": [
              "0x8",
              "uint64"
            ],
            "SyncBlockValueToObjectOffset": [
              "0x4",
              "uint16"
            ],
            "AppDomain": [
              [
                1
              ],
              "pointer"
            ],
            "ThreadStore": [
              [
                2
              ],
              "pointer"
            ],
            "FinalizerThread": [
              [
                3
              ],
              "pointer"
            ],
            "GCThread": [
              [
                4
              ],
              "pointer"
            ],
            "ArrayBoundsZero": [
              [
                5
              ],
              "pointer"
            ],
            "ExceptionMethodTable": [
              [
                6
              ],
              "pointer"
            ],
            "FreeObjectMethodTable": [
              [
                7
              ],
              "pointer"
            ],
            "ObjectMethodTable": [
              [
                8
              ],
              "pointer"
            ],
            "ObjectArrayMethodTable": [
              [
                9
              ],
              "pointer"
            ],
            "StringMethodTable": [
              [
                10
              ],
              "pointer"
            ],
            "SyncTableEntries": [
              [
                11
              ],
              "pointer"
            ],
            "MiniMetaDataBuffAddress": [
              [
                12
              ],
              "pointer"
            ],
            "MiniMetaDataBuffMaxSize": [
              [
                13
              ],
              "pointer"
            ]
          },
          "contracts": {
            "DacStreams": 1,
            "EcmaMetadata": 1,
            "Exception": 1,
            "Loader": 1,
            "Object": 1,
            "RuntimeTypeSystem": 1,
            "Thread": 1
          }
        }
        """;
}
