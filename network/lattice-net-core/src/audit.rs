use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::IpProtocol;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FlowAuditRecord {
    pub timestamp: DateTime<Utc>,
    pub profile_id: Uuid,
    pub agent_id: Option<String>,
    pub service: Option<String>,
    pub destination: IpAddr,
    pub destination_port: Option<u16>,
    pub protocol: IpProtocol,
    pub bytes: u64,
    pub decision: FlowDecision,
    pub policy_version: u64,
    pub flow_fingerprint: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowDecision {
    Allow,
    Deny,
}

