use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u8) -> Self {
        match score {
            80..=100 => Severity::Critical,
            60..=79 => Severity::High,
            40..=59 => Severity::Medium,
            20..=39 => Severity::Low,
            _ => Severity::Info,
        }
    }
    
    pub fn emoji(&self) -> &'static str {
        match self {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🔵",
            Severity::Info => "ℹ️",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    BytecodePattern,
    MLPattern,
    Simulation,
    Proxy,
    Ownership,
    Honeypot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
}

impl Finding {
    pub fn new(severity: Severity, category: Category, message: impl Into<String>) -> Self {
        Self {
            severity,
            category,
            message: message.into(),
            evidence: None,
        }
    }
    
    pub fn with_evidence(mut self, evidence: serde_json::Value) -> Self {
        self.evidence = Some(evidence);
        self
    }
}