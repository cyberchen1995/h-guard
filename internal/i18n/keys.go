package i18n

// 消息键。Verdict 只存键与参数（guard.Reason），文本在渲染前生成。
const (
	KeyActionBlocked           = "action.blocked"            // {rules}
	KeyActionDangerous         = "action.dangerous"          // {rules}
	KeyActionRadius            = "action.radius"             // {radius}
	KeyActionNotRequested      = "action.not_requested"      // {p}
	KeyActionGuardSelf         = "action.guard_self"         // {rules}
	KeyActionGuardSelfFile     = "action.guard_self_file"    // {paths} {rules}
	KeyActionFileRule          = "action.file_rule"          // {paths} {rules}
	KeyActionJudgeUnavailable  = "action.judge_unavailable"  // {code} {rules}
	KeyActionEvidenceTruncated = "action.evidence_truncated" //
	KeyActionRegexTimeout      = "action.regex_timeout"      //
	KeyActionBudgetExceeded    = "action.budget_exceeded"    //
	KeyActionProbe             = "action.probe"              //
	KeyActionOperation         = "action.operation"          // {command} {cwd}
	KeyActionOperationHere     = "action.operation_here"     // {command}
	KeyActionImpact            = "action.impact"             // {impact}
	KeyActionAdvice            = "action.advice"             // {advice}
	KeyOutboundCredentials     = "outbound.credentials"      // {count} {lines}
	KeyOutboundPrivateKey      = "outbound.private_key"      // {count} {lines}
	KeyOutboundPII             = "outbound.pii"              // {count} {lines}
	KeyOutboundCustom          = "outbound.custom"           // {category} {count} {lines}
	KeyOutboundJudge           = "outbound.judge"            // {category}
	KeyErrorInternal           = "error.internal"            //
	KeyErrorConfigInvalid      = "error.config_invalid"      // {detail}
	KeyErrorInputTooLarge      = "error.input_too_large"     //
	KeyErrorTargetUnparsed     = "error.target_unparsed"     // {tool}
	KeyErrorToolUnknown        = "error.tool_unknown"        // {tool} {harness}
	KeyDegradeAskUnsupported   = "degrade.ask_unsupported"   //
	KeySourceLocal             = "source.local"              //
	KeySourceJudge             = "source.judge"              //
	KeySourceBoth              = "source.both"               //
	KeyHintManual              = "hint.manual"               //
	KeyHintConsent             = "hint.consent"              // {backend}
	KeyHintJudgeUnavailable    = "hint.judge_unavailable"    //
	KeyHintSplit               = "hint.split"                //
	KeyHintNarrow              = "hint.narrow"               //
	KeyHintRequest             = "hint.request"              //
	KeyHintOutbound            = "hint.outbound"             //
	KeyHintOutboundJudge       = "hint.outbound_judge"       //
	KeyHintGrant               = "hint.grant"                // {id} {minutes}
	KeyListSeparator           = "list.separator"            // 列表项之间的分隔符
)

// AllKeys 是全部消息键；en 目录必须覆盖它们（测试检查）。
var AllKeys = []string{
	KeyActionBlocked, KeyActionDangerous, KeyActionRadius, KeyActionNotRequested, KeyActionGuardSelf, KeyActionGuardSelfFile,
	KeyActionFileRule, KeyActionJudgeUnavailable, KeyActionEvidenceTruncated, KeyActionRegexTimeout, KeyActionBudgetExceeded,
	KeyActionProbe, KeyActionOperation, KeyActionOperationHere, KeyActionImpact, KeyActionAdvice, KeyOutboundCredentials, KeyOutboundPrivateKey, KeyOutboundPII, KeyOutboundCustom, KeyOutboundJudge, KeyErrorInternal, KeyErrorConfigInvalid, KeyErrorInputTooLarge, KeyErrorTargetUnparsed, KeyErrorToolUnknown, KeyDegradeAskUnsupported,
	KeySourceLocal, KeySourceJudge, KeySourceBoth, KeyHintManual, KeyHintConsent, KeyHintJudgeUnavailable,
	KeyHintSplit, KeyHintNarrow, KeyHintRequest, KeyHintOutbound, KeyHintOutboundJudge, KeyHintGrant, KeyListSeparator,
}
